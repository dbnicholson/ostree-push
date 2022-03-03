import logging
import os
import subprocess

from .util import (
    TESTSDIR,
    get_content_checksum,
    needs_sshd,
    random_commit,
    wipe_repo,
)

ostree_receive_abspath = os.path.join(TESTSDIR, 'ostree-receive')
logger = logging.getLogger(__name__)

# Skip all tests here if the required sshd is not available.
pytestmark = needs_sshd


def run_push(source_repo, dest_repo, sshd, ssh_options, env_vars,
             receive_config_path, command='ostree-receive', dest=None,
             options=None, refs=None, **popen_kwargs):
    dest = dest or f'ssh://{sshd.address}:{sshd.port}/{dest_repo.path}'
    options = options or []
    refs = refs or []
    env = os.environ.copy()
    env['OSTREE_RECEIVE_CONF'] = receive_config_path
    if env_vars:
        env.update(env_vars)
    popen_kwargs['env'] = env
    if 'check' not in popen_kwargs:
        popen_kwargs['check'] = True
    cmd = [
        'ostree-push',
        f'--repo={source_repo.path}',
        f'--command={command}',
    ] + ssh_options + options + [dest] + refs
    logger.debug('push command: %s', ' '.join(cmd))
    return subprocess.run(cmd, **popen_kwargs)


def test_no_commits(source_repo, dest_repo, sshd, ssh_options,
                    cli_env_vars, receive_config_path, capfd):
    """Test push with no commits in source repo"""
    args = (
        source_repo, dest_repo, sshd, ssh_options, cli_env_vars,
        receive_config_path
    )

    run_push(*args)
    capfd.readouterr()
    _, receive_refs = dest_repo.list_refs()
    assert receive_refs == {}

    ret = run_push(*args, refs=['foo', 'bar'], check=False)
    _, err = capfd.readouterr()
    assert ret != 0
    assert 'otpush.push.OTPushError: Refs bar foo not found' in err
    _, receive_refs = dest_repo.list_refs()
    assert receive_refs == {}


def test_basic(source_repo, dest_repo, sshd, ssh_options, cli_env_vars,
               receive_config_path, tmp_files_path, capfd):
    """Test push with one commit in source repo"""
    args = (
        source_repo, dest_repo, sshd, ssh_options, cli_env_vars,
        receive_config_path
    )

    rev = random_commit(source_repo, tmp_files_path, 'test')
    source_content = get_content_checksum(source_repo, rev)

    wipe_repo(dest_repo)
    run_push(*args)
    capfd.readouterr()
    _, receive_refs = dest_repo.list_refs()
    assert receive_refs.keys() == {'test', 'ostree-metadata'}
    receive_content = get_content_checksum(dest_repo, receive_refs['test'])
    assert receive_content == source_content

    wipe_repo(dest_repo)
    run_push(*args, refs=['test'])
    capfd.readouterr()
    _, receive_refs = dest_repo.list_refs()
    assert receive_refs.keys() == {'test', 'ostree-metadata'}
    receive_content = get_content_checksum(dest_repo, receive_refs['test'])
    assert receive_content == source_content

    wipe_repo(dest_repo)
    ret = run_push(*args, refs=['test', 'foo'], check=False)
    _, err = capfd.readouterr()
    assert ret != 0
    assert 'otpush.push.OTPushError: Refs foo not found' in err
    _, receive_refs = dest_repo.list_refs()
    assert receive_refs == {}


def test_dry_run(source_repo, dest_repo, sshd, ssh_options, cli_env_vars,
                 receive_config_path, tmp_files_path):
    """Test push dry run"""
    args = (
        source_repo, dest_repo, sshd, ssh_options, cli_env_vars,
        receive_config_path
    )

    random_commit(source_repo, tmp_files_path, 'test')

    wipe_repo(dest_repo)
    run_push(*args, options=['-n'])
    _, receive_refs = dest_repo.list_refs()
    assert receive_refs == {}

    wipe_repo(dest_repo)
    run_push(*args, options=['--dry-run'])
    _, receive_refs = dest_repo.list_refs()
    assert receive_refs == {}

    wipe_repo(dest_repo)
    run_push(*args, options=['-n'], refs=['test'])
    _, receive_refs = dest_repo.list_refs()
    assert receive_refs == {}


def test_scp_dest(source_repo, dest_repo, sshd, ssh_options, cli_env_vars,
                  receive_config_path, tmp_files_path):
    """Test push with scp style destination"""
    args = (
        source_repo, dest_repo, sshd, ssh_options, cli_env_vars,
        receive_config_path
    )
    dest = f'{sshd.address}:{dest_repo.path}'
    options = ['-p', str(sshd.port)]

    random_commit(source_repo, tmp_files_path, 'test')
    run_push(*args, dest=dest, options=options)
    _, receive_refs = dest_repo.list_refs()
    assert receive_refs.keys() == {'test', 'ostree-metadata'}


def test_command_abspath(source_repo, dest_repo, sshd, ssh_options,
                         cli_env_vars, receive_config_path, tmp_files_path):
    """Test push with absolute path to ostree-receive"""
    args = (
        source_repo, dest_repo, sshd, ssh_options, cli_env_vars,
        receive_config_path
    )
    random_commit(source_repo, tmp_files_path, 'test')
    run_push(*args, command=ostree_receive_abspath)
    _, receive_refs = dest_repo.list_refs()
    assert receive_refs.keys() == {'test', 'ostree-metadata'}
