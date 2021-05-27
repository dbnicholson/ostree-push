from otpush import push, receive

import os
import pytest
import shutil

from .util import DATADIR, TESTSDIR, SRCDIR, ssh_server, TmpRepo


@pytest.fixture(scope='session')
def cli_env_vars():
    """Provide environment variables for running via CLI

    Provide adjusted PATH and PYTHONPATH environment variables for the
    processes run subprocess or sshd so that they more closely matches
    the current environment.
    """
    env_vars = {}

    path = os.getenv('PATH', os.defpath)
    cli_path_parts = path.split(os.pathsep)
    cli_path_parts.insert(0, TESTSDIR)
    toxbindir = os.getenv('TOXBINDIR')
    if toxbindir:
        cli_path_parts.insert(0, toxbindir)
    cli_path = os.pathsep.join(cli_path_parts)
    env_vars['PATH'] = cli_path

    pypath = os.getenv('PYTHONPATH')
    cli_pypath_parts = pypath.split(os.pathsep) if pypath else []
    if not toxbindir:
        cli_pypath_parts.insert(0, SRCDIR)
    cli_pypath = os.pathsep.join(cli_pypath_parts)
    env_vars['PYTHONPATH'] = cli_pypath

    return env_vars


@pytest.fixture(scope='session')
def ssh_datadir(tmp_path_factory):
    datadir = tmp_path_factory.mktemp('ssh-data')
    for src in ('host_rsa_key', 'host_rsa_key.pub', 'id_rsa',
                'id_rsa.pub', 'sshd_config'):
        shutil.copy(os.path.join(DATADIR, src), datadir)

    # ssh and sshd refuse to start when the private keys are group or
    # world accessible.
    os.chmod(datadir / 'host_rsa_key', 0o600)
    os.chmod(datadir / 'id_rsa', 0o600)

    return datadir


@pytest.fixture(scope='session')
def sshd(ssh_datadir, cli_env_vars):
    sshd_config = ssh_datadir / 'sshd_config'
    host_key = ssh_datadir / 'host_rsa_key'
    authorized_keys = ssh_datadir / 'id_rsa.pub'
    with ssh_server(sshd_config, host_key, authorized_keys, cli_env_vars) \
         as server_info:
        yield server_info


@pytest.fixture
def ssh_options(sshd, ssh_datadir):
    id_file = ssh_datadir / 'id_rsa'
    return [
        '-i', str(id_file),
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
    ]


@pytest.fixture
def ssh_socket(tmp_path):
    return str(tmp_path / 'ssh_socket')


@pytest.fixture
def tmp_files_path(tmp_path):
    return tmp_path / 'files'


@pytest.fixture
def source_repo(tmp_path, tmp_files_path):
    repo_path = tmp_path / 'source-repo'
    repo = TmpRepo(repo_path, collection_id=None)

    # Turn on auto summary generation
    config = repo.copy_config()
    config.set_boolean('core', 'auto-update-summary', True)
    repo.write_config(config)

    return repo


@pytest.fixture
def source_server(source_repo):
    with push.RepoServer(source_repo.path) as server:
        yield server


@pytest.fixture
def receive_repo(tmp_path, source_server):
    repo_path = tmp_path / 'receive-repo'
    TmpRepo(repo_path)
    with receive.OTReceiveRepo(str(repo_path), source_server.url) as repo:
        yield repo
