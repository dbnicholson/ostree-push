from collections import namedtuple
from contextlib import contextmanager
import getpass
import gi
import logging
import os
import random
import socket
import shutil
import subprocess
import time

gi.require_version('OSTree', '1.0')
from gi.repository import GLib, Gio, OSTree  # noqa: E402

logger = logging.getLogger(__name__)
TESTSDIR = os.path.abspath(os.path.dirname(__file__))
DATADIR = os.path.join(TESTSDIR, 'data')
SRCDIR = os.path.dirname(TESTSDIR)
SCRIPTSDIR = os.path.join(SRCDIR, 'scripts')


class OTPushTestError(Exception):
    pass


@contextmanager
def oneshot_transaction(repo):
    """Start an OSTree repo transaction and abort on any failures"""
    repo.prepare_transaction()
    try:
        yield
        # Commit the transaction
        repo.commit_transaction()
    except:  # noqa: E722
        # Abort on any failures
        repo.abort_transaction()
        raise


def random_commit(repo, tmpdir, refspec, parent=None, timestamp=None,
                  extra_metadata=None):
    """Create a random commit and set refspec to it

    Returns the new commit checksum.
    """
    for path in ('a', 'sub/b'):
        full_path = tmpdir / path
        full_path.parent.mkdir(exist_ok=True)
        rand_size = random.randrange(1000, 10000)
        with open(full_path, 'wb') as f:
            f.write(os.urandom(rand_size))

    # Use current UTC time if no timestamp specified
    if timestamp is None:
        timestamp = int(time.time())
    logger.info('Using timestamp %u for random commit on %s', timestamp,
                refspec)

    # Include the collection and ref bindings in the commit
    metadata = {}
    if extra_metadata:
        metadata.update(extra_metadata)
    collection_id = repo.get_collection_id()
    if collection_id is not None:
        metadata[OSTree.COMMIT_META_KEY_COLLECTION_BINDING] = \
                GLib.Variant('s', collection_id)
    _, remote, ref = OSTree.parse_refspec(refspec)
    metadata[OSTree.COMMIT_META_KEY_REF_BINDING] = GLib.Variant('as', [ref])
    metadata_var = GLib.Variant('a{sv}', metadata)

    with oneshot_transaction(repo):
        # Populate a mutable tree from the random files
        mtree = OSTree.MutableTree.new()
        repo.write_directory_to_mtree(Gio.File.new_for_path(str(tmpdir)),
                                      mtree, None)
        _, root = repo.write_mtree(mtree)

        # Commit the mtree root
        _, checksum = repo.write_commit_with_time(parent,
                                                  'Test commit',
                                                  None,
                                                  metadata_var,
                                                  root,
                                                  timestamp)

        # Set the ref
        if remote is None:
            # Local ref, set a collection ref
            collection_ref = OSTree.CollectionRef()
            collection_ref.collection_id = collection_id
            collection_ref.ref_name = ref
            repo.transaction_set_collection_ref(collection_ref, checksum)
        else:
            # Remote ref
            repo.transaction_set_ref(remote, ref, checksum)

    logger.info('Created random commit %s on %s', checksum, refspec)
    return checksum


def wipe_repo(repo):
    """Delete all refs and objects in repo"""
    _, refs = repo.list_refs(None)
    for refspec in refs.keys():
        _, remote, ref = OSTree.parse_refspec(refspec)
        repo.set_ref_immediate(remote, ref, None)
    repo.prune(OSTree.RepoPruneFlags.REFS_ONLY, -1)


def local_refs(repo, prefix=None):
    """Get local refs in repo excluding remotes and mirrors"""
    flags = (OSTree.RepoListRefsExtFlags.EXCLUDE_REMOTES |
             OSTree.RepoListRefsExtFlags.EXCLUDE_MIRRORS)
    _, refs = repo.list_refs_ext(prefix, flags)
    return refs


def get_summary_variant(path):
    summary_file = Gio.File.new_for_path(str(path))
    summary_bytes, _ = summary_file.load_bytes()
    summary_variant = GLib.Variant.new_from_bytes(
        type=GLib.VariantType(OSTree.SUMMARY_GVARIANT_STRING),
        bytes=summary_bytes, trusted=False)
    if not summary_variant.is_normal_form():
        raise OTPushTestError(
            f'Summary file {path} is not in normal GVariant format')
    return summary_variant


def get_content_checksum(repo, rev):
    """Get a commit's content checksum"""
    _, commit, _ = repo.load_commit(rev)
    return OSTree.commit_get_content_checksum(commit)


class TmpRepo(OSTree.Repo):
    """Temporary OSTree repo"""
    COLLECTION_ID = 'com.example.Test'

    def __init__(self, path, collection_id=COLLECTION_ID, **kwargs):
        self.path = path

        self.path.mkdir()
        repo_file = Gio.File.new_for_path(str(self.path))
        super().__init__(path=repo_file, **kwargs)
        if collection_id:
            self.set_collection_id(collection_id)
        self.create(OSTree.RepoMode.ARCHIVE)


SSHServerInfo = namedtuple('SSHServerInfo', ('proc', 'address', 'port'))


def get_ssh_server_id(address):
    """Open a connection to an SSH server and get the identification string

    If a connection could not be established or no data is received, an
    empty string is returned.
    """
    for _ in range(10):
        try:
            sock = socket.create_connection(address, timeout=1)
            break
        except ConnectionRefusedError:
            logger.debug('Could not connect to port %d', address[1])
            time.sleep(0.01)
    else:
        logger.debug('Could not connect in 5 attempts')
        return ''

    try:
        return sock.recv(256).decode('utf-8')
    except socket.timeout:
        logger.debug('No data received from port %d', address[1])
        return ''
    finally:
        sock.close()


@contextmanager
def ssh_server(sshd_config, host_key, authorized_keys, env_vars=None):
    # Running sshd requires an absolute path
    path = os.getenv('PATH', os.defpath)
    sshd_path = os.pathsep.join([path, '/usr/local/sbin', '/usr/sbin',
                                 '/sbin'])
    sshd = shutil.which('sshd', path=sshd_path)
    if not sshd:
        raise OTPushTestError(f'Could not find sshd in {path}')

    # Build a SetEnv option value from the provided environment variables.
    env_vars = env_vars or {}
    setenv = ' '.join([
        f'{var}="{value}"'
        for var, value in env_vars.items()
    ])

    cmd = [
        sshd,
        # Don't fork
        '-D',
        # Write logs to stderr
        '-e',
        # Config file
        '-f', str(sshd_config),
        # Host key file
        '-h', str(host_key),
        # Authorized keys file
        '-o', f'AuthorizedKeysFile={authorized_keys}',
        # Only allow running user
        '-o', f'AllowUsers={getpass.getuser()}',
        # Set environment variables for the process
        '-o', f'SetEnv={setenv}',
    ]
    logger.debug('SSH server args: %s', ' '.join(cmd))

    # Loop a few times trying to find an open ephemeral port
    with open('/proc/sys/net/ipv4/ip_local_port_range') as f:
        start_port, stop_port = map(int, f.readline().split())
    proc = None
    try:
        for _ in range(5):
            port = random.randrange(start_port, stop_port)
            logger.debug('Starting %s with port %d', sshd, port)
            proc = subprocess.Popen(cmd + ['-p', str(port)])
            server_id = get_ssh_server_id(('127.0.0.1', port))
            if server_id.startswith('SSH-2.0-'):
                logger.info('%s started on port %d', sshd, port)
                break
        else:
            raise OTPushTestError(f'Could not start {sshd}')

        yield SSHServerInfo(proc, '127.0.0.1', port)
    finally:
        if proc is not None and proc.poll() is None:
            logger.debug('Stopping sshd process %d', proc.pid)
            proc.terminate()
