from collections import namedtuple
from contextlib import contextmanager
import getpass
import gi
import logging
import os
import pytest
import random
import shutil
import socket
import subprocess
from tempfile import TemporaryDirectory
import time

gi.require_version('OSTree', '1.0')
from gi.repository import GLib, Gio, OSTree  # noqa: E402

logger = logging.getLogger(__name__)
TESTSDIR = os.path.abspath(os.path.dirname(__file__))
DATADIR = os.path.join(TESTSDIR, 'data')
SRCDIR = os.path.dirname(TESTSDIR)
SCRIPTSDIR = os.path.join(SRCDIR, 'scripts')
PGP_KEY = os.path.join(DATADIR, 'pgp-key.asc')
PGP_PUB = os.path.join(DATADIR, 'pgp-pub.asc')
PGP_PUB_KEYRING = os.path.join(DATADIR, 'pgp-pub.gpg')
PGP_KEY_ID = '281D0DDC6EDD77CF6A8A936C247D3E51CDA08B6B'
ED25519_PUBLIC_KEY = \
    'KDurJTccLAQ4AqtSAU8g7aPV25i6oEsy1TS6gh4LdlE='
ED25519_PRIVATE_KEY = (
    '2b19zVhdsWKxoUOGP8OTBwQGAGSshWJCpage7Ov+tUcoO6slNxwsBDgCq1IBTyDto9XbmLqgS'
    'zLVNLqCHgt2UQ=='
)


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


needs_ostree = pytest.mark.skipif(
    not shutil.which('ostree'), reason='ostree required'
)


needs_flatpak = pytest.mark.skipif(
    not shutil.which('flatpak'), reason='flatpak required'
)


def random_commit(repo, tmpdir, refspec, parent=None, timestamp=None,
                  extra_metadata=None, gpg_key_id=None, gpg_homedir=None,
                  ed25519_key=None):
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

        # Sign the commit
        if gpg_key_id:
            repo.sign_commit(checksum, gpg_key_id, gpg_homedir)
        if ed25519_key:
            sign = get_ostree_ed25519_sign()
            sign.set_sk(GLib.Variant('s', ed25519_key))
            sign.commit(repo, checksum, None)

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
    flags = OSTree.RepoListRefsExtFlags.EXCLUDE_REMOTES
    try:
        # EXCLUDE_MIRRORS only available since ostree 2019.2
        flags |= OSTree.RepoListRefsExtFlags.EXCLUDE_MIRRORS
    except AttributeError:
        pass
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


def get_sshd():
    """Returns the path to sshd or None

    Looks in PATH and typical sbin directories not in PATH.
    """
    path = os.getenv('PATH', os.defpath)
    sshd_path = os.pathsep.join([path, '/usr/local/sbin', '/usr/sbin',
                                 '/sbin'])
    sshd = shutil.which('sshd', path=sshd_path)
    if sshd:
        logger.debug('Found sshd %s', sshd)
    else:
        logger.debug('sshd not found in %s', sshd_path)
    return sshd


def have_required_sshd(sshd=None):
    """Check whether sshd meets requirements

    sshd needs to be OpenSSH version 7.8 or newer to support the SetEnv
    config option.
    """
    if not sshd:
        sshd = get_sshd()
    if not sshd:
        return False

    # Run sshd -V to get the version. This is actually only an option on
    # the ssh client, but it will print the version after complaining
    # about the unknown option. Maybe someday it will exist...
    proc = subprocess.run([sshd, '-V'], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)
    lines = iter(proc.stdout.decode('utf-8').splitlines())
    try:
        version_line = next(lines)
        if version_line.startswith('unknown option'):
            version_line = next(lines)
    except StopIteration:
        logger.debug('No version information from %s -V', sshd)
        return False

    logger.debug('sshd version line: %s', version_line)
    if not version_line.startswith('OpenSSH_'):
        logger.debug('OpenSSH not in version')
        return False

    # The version line should look something like:
    #
    # OpenSSH_7.6p1 Ubuntu-4ubuntu0.3, OpenSSL 1.0.2n  7 Dec 2017
    #
    # Get the first word, strip the OpenSSH_ prefix, strip the portable
    # pX suffix, and then try to get the major and minor version
    # numbers.
    openssh_version = version_line.split()[0]
    _, _, full_version = openssh_version.partition('OpenSSH_')
    version, _, _ = full_version.partition('p')
    version_parts = version.split('.')
    try:
        major = int(version_parts[0])
    except ValueError:
        logger.debug('Could not get major version from %s', version)
        return False
    try:
        minor = int(version_parts[1])
    except IndexError:
        minor = 0
    except ValueError:
        logger.debug('Could not get minor version from %s', version)
        return False
    logger.debug('Detected OpenSSH sshd version %d.%d', major, minor)

    # OpenSSH 7.8 is needed for the SetEnv option
    if major < 7 or (major == 7 and minor < 8):
        logger.debug('OpenSSH sshd version < 7.8')
        return False

    return True


needs_sshd = pytest.mark.skipif(
    not have_required_sshd(),
    reason='OpenSSH sshd version 7.8+ required'
)


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
    sshd = get_sshd()
    if not sshd:
        raise OTPushTestError('Could not find sshd')
    if not have_required_sshd(sshd):
        raise OTPushTestError(f'{sshd} is not the required version')

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
        # Allow root login
        '-o', 'PermitRootLogin=yes',
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


def have_gpg_support():
    if shutil.which('gpg') is None:
        return False

    with TemporaryDirectory() as tempdir:
        repo = OSTree.Repo.new(Gio.File.new_for_path(tempdir))
        try:
            repo.gpg_sign_data(GLib.Bytes.new(b''), GLib.Bytes.new(b''), [],
                               None)
        except GLib.Error as ex:
            assert 'GPG feature is disabled' in ex.message
            return False

    return True


needs_gpg = pytest.mark.skipif(
    not have_gpg_support(), reason='gpg support required'
)


def get_gnupg_version():
    """Get the GnuPG version from gpg"""
    proc = subprocess.run(['gpg', '--version'], stdout=subprocess.PIPE,
                          check=True)
    lines = proc.stdout.decode('utf-8').splitlines()
    if len(lines) == 0:
        raise OTPushTestError(
            'No version information from gpg --version'
        )

    version = lines[0].split()[-1]
    logger.debug('Found GnuPG version %s', version)
    return version


def kill_gpg_agent(gpg_homedir):
    """Kill gpg-agent in GPG homedir"""
    version = get_gnupg_version()
    version_parts = version.split('.')
    if len(version_parts) < 3:
        raise OTPushTestError(
            f'GnuPG version {version} has less than 3 components'
        )
    major, minor, patch = map(int, version_parts[0:3])

    # If gpg is at least version 2.1.17, gpg-agent (properly) watches
    # the homedir with an inotify watch and exits when it's deleted.
    if (
        major > 2 or
        (major == 2 and minor > 1) or
        (major == 2 and minor == 1 and patch > 17)
    ):
        logger.debug('GnuPG >= 2.1.17, skipping gpg-agent cleanup')
        return

    # Otherwise, it needs to be told to exit. Note that this is
    # asynchronous. If the caller is deleting the homedir, there can be
    # failures as both the caller and gpg-agent try to delete the
    # sockets concurrently.
    cmd = (
        'gpg-connect-agent',
        '--homedir',
        str(gpg_homedir),
        'killagent',
        '/bye'
    )
    logger.debug('Killing GnuPG agent: %s', ' '.join(cmd))
    subprocess.run(cmd, check=True)


def get_ostree_ed25519_sign():
    """Retrieve an OSTree.Sign instance for ed25519 keys"""
    return OSTree.Sign.get_by_name('ed25519')


def have_ed25519_support():
    """Check whether ostree was compiled with ed25519 signature support"""
    try:
        get_ostree_ed25519_sign()
    except (AttributeError, GLib.GError):
        return False

    return True


needs_ed25519 = pytest.mark.skipif(
    not have_ed25519_support(), reason='ed25519 support required'
)
