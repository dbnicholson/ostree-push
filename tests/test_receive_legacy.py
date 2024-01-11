# Tests for receive_legacy/ostree-receive-0.

from contextlib import contextmanager
import gi
import logging
import os
import subprocess

from otpush.receive_legacy import (
    PushMessageReader,
    PushMessageWriter,
    ostree_object_path,
)

from .util import random_commit

gi.require_version('OSTree', '1.0')
from gi.repository import OSTree  # noqa: E402

logger = logging.getLogger(__name__)


@contextmanager
def run_receive(
    dest_repo,
    env_vars,
    check=True,
    command='ostree-receive-0',
    options=None,
):
    """Run ostree-receive-0 and return reader/writer buffers

    The receiver needs to run in a subprocess since it uses sys.stdin/stdout
    directly and that interacts poorly with pytest.
    """
    # Start the receiver with pipes for stdin and stdout to use for the
    # protocol.
    env = os.environ.copy()
    if env_vars:
        env.update(env_vars)
    options = options or []
    cmd = [command, '--debug', f'--repo={dest_repo.path}'] + options
    proc = subprocess.Popen(
        cmd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )

    # Create a reader and writer and yield them to the caller.
    reader = PushMessageReader(proc.stdout)
    writer = PushMessageWriter(proc.stdin)
    yield reader, writer

    # Make sure the process exits. This is basically how subprocess.run()
    # cleans up.
    try:
        out, _ = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        logger.warning(f'{cmd} did not exit, killing it')
        proc.kill()
        proc.wait()
        raise
    except:  # noqa: E722
        logger.warning(f'Exception stopping {cmd}, killing it')
        proc.kill()
        raise

    if check:
        ret = proc.poll()
        assert ret == 0
    assert out == b''


def test_noop(dest_repo, cli_env_vars):
    """Basic protocol smoketest"""
    with run_receive(dest_repo, cli_env_vars) as (reader, writer):
        data = reader.receive_info()
        assert data['mode'] == OSTree.RepoMode.ARCHIVE_Z2
        assert data['refs'] == {}
        writer.send_done()


def commit_objects_iter(repo, rev):
    """Get the path for all objects referenced by a commit"""
    _, reachable = repo.traverse_commit(rev, 0, None)
    for obj in reachable:
        objname = OSTree.object_to_string(obj[0], obj[1])
        if obj[1] == OSTree.ObjectType.FILE:
            # Make this a filez since we're archive-z2
            objname += 'z'
        elif obj[1] == OSTree.ObjectType.COMMIT:
            # Add in detached metadata
            metaobj = objname + 'meta'
            metapath = ostree_object_path(repo, metaobj)
            if os.path.exists(metapath):
                yield metaobj
        yield objname


def test_update(dest_repo, cli_env_vars, source_repo, tmp_files_path):
    """Test the update and putobject commands"""
    rev = random_commit(source_repo, tmp_files_path, 'test')

    # Try to update with an invalid from_rev.
    with run_receive(dest_repo, cli_env_vars, check=False) as (reader, writer):
        data = reader.receive_info()
        assert data['refs'] == {}

        # There's no remote commit, so from_rev should be all 0s.
        from_rev = '1' * 64
        update_refs = {'test': (from_rev, rev)}
        writer.send_update(update_refs)
        data = reader.receive_status()
        assert not data['result']
        assert data['message'].startswith('Invalid from commit')

        writer.send_done()

    # Send the update correctly.
    with run_receive(dest_repo, cli_env_vars) as (reader, writer):
        data = reader.receive_info()
        assert data['refs'] == {}

        from_rev = '0' * 64
        update_refs = {'test': (from_rev, rev)}
        writer.send_update(update_refs)
        data = reader.receive_status()
        assert data['result']

        for obj in set(commit_objects_iter(source_repo, rev)):
            writer.send_putobject(source_repo, obj)
            data = reader.receive_status()
            assert data['result']

        writer.send_done()

    # The destination repo should now have the commit and ref.
    _, dest_refs = dest_repo.list_refs()
    assert dest_refs == {'test': rev}
    with run_receive(dest_repo, cli_env_vars) as (reader, writer):
        data = reader.receive_info()
        assert data['refs'] == {'test': rev}
        writer.send_done()
