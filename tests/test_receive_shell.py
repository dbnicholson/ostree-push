import json
import os
import pytest
import shutil
import subprocess

from otpush import VERSION

from .util import SCRIPTSDIR, TESTSDIR

shell_abspath = os.path.join(SCRIPTSDIR, 'ostree-receive-shell')
dumpenv_abspath = os.path.join(TESTSDIR, 'dumpenv')

MAJOR = VERSION.split('.')[0]
ostree_receive_versioned = f'ostree-receive-{MAJOR}'

# Some tests can't be run if ostree-receive is in PATH
skip_ostree_receive_in_path = pytest.mark.skipif(
    shutil.which(ostree_receive_versioned) is not None,
    reason=f'cannot test correctly with {ostree_receive_versioned} in PATH',
)


@pytest.fixture
def tmp_bindir(tmp_path):
    """A temporary directory to be included in PATH"""
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    return bindir


@pytest.fixture
def tmp_receive(tmp_bindir):
    """Copy dumpenv to a temporary ostree-receive"""
    receive = tmp_bindir / ostree_receive_versioned
    shutil.copy(dumpenv_abspath, receive)
    os.chmod(receive, 0o755)
    return receive


@pytest.fixture
def tmp_shell(tmp_bindir):
    """Copy ostree-receive-shell to the temporary bindir"""
    shell = tmp_bindir / 'ostree-receive-shell'
    shutil.copy(shell_abspath, shell)
    os.chmod(shell, 0o755)
    return shell


@pytest.fixture
def shell_env_vars(tmp_bindir):
    """Environment variables for shell tests"""
    env = os.environ.copy()
    path = env.get('PATH', os.defpath).split(os.pathsep)
    path.insert(0, str(tmp_bindir))
    env['PATH'] = os.pathsep.join(path)
    return env


def test_command_args(shell_env_vars, tmp_shell, tmp_receive):
    """Test how arguments are passed to ostree-receive"""
    cmd = ('ostree-receive-shell', '-c', tmp_receive.name)
    proc = subprocess.run(cmd, check=True, env=shell_env_vars,
                          stdout=subprocess.PIPE)
    data = json.loads(proc.stdout.decode('utf-8'))
    assert data['args'] == [str(tmp_receive)]

    cmd = ('ostree-receive-shell', '-c', f'{tmp_receive.name} -n foo bar')
    proc = subprocess.run(cmd, check=True, env=shell_env_vars,
                          stdout=subprocess.PIPE)
    data = json.loads(proc.stdout.decode('utf-8'))
    assert data['args'] == [str(tmp_receive), '-n', 'foo', 'bar']


def test_auto_path(shell_env_vars, tmp_receive):
    """Test that the shell's directory is appended to PATH"""
    # Here we use the shell in the source directory to ensure that it's
    # directory isn't in PATH. Otherwise it won't get appended.
    cmd = (shell_abspath, '-c', tmp_receive.name)
    proc = subprocess.run(cmd, check=True, env=shell_env_vars,
                          stdout=subprocess.PIPE)
    data = json.loads(proc.stdout.decode('utf-8'))
    path = data['env']['PATH'].split(os.pathsep)
    assert path[-1] == SCRIPTSDIR


def test_no_interactive():
    """Test trying to run the shell interactively with no arguments"""
    cmd = (shell_abspath,)
    proc = subprocess.run(cmd, stderr=subprocess.PIPE)
    assert proc.returncode == 1
    assert proc.stderr.decode('utf-8') == (
        'ostree-receive-shell: Cannot run interactively\n'
    )


def test_wrong_args():
    """Test passing incorrect arguments"""
    commands = (
        (shell_abspath, 'foo'),
        (shell_abspath, 'foo', 'bar'),
        (shell_abspath, 'foo', 'bar', 'baz'),
        (shell_abspath, '-c'),
        (shell_abspath, '-c', 'foo', 'bar'),
    )
    for cmd in commands:
        proc = subprocess.run(cmd, stderr=subprocess.PIPE)
        assert proc.returncode == 1
        assert proc.stderr.decode('utf-8') == (
            'ostree-receive-shell: Must be run with no arguments or '
            'with -c cmd\n'
        )


def test_allowed_commands(shell_env_vars, tmp_shell, tmp_bindir):
    """Test when allowed and disallowed commands are requested"""
    # Allowed commands
    allowed = [
        f'ostree-receive-{major}' for major in range(int(MAJOR) + 1)
    ] + ['ostree-receive']
    for name in allowed:
        cmd = (shell_abspath, '-c', name)
        receive = tmp_bindir / name
        shutil.copy(dumpenv_abspath, receive)
        os.chmod(receive, 0o755)
        proc = subprocess.run(cmd, check=True, env=shell_env_vars,
                              stdout=subprocess.PIPE)
        data = json.loads(proc.stdout.decode('utf-8'))
        assert data['args'] == [str(receive)]

    # Disallowed commands
    arguments = (
        ('foo',),
        ('foo', 'bar'),
        (f'/usr/bin/{ostree_receive_versioned}'),
        ('/usr/bin/ostree-receive'),
        (f'ostree-receive-{int(MAJOR) + 1}'),
    )
    for args in arguments:
        cmd = (shell_abspath, '-c', ' '.join(args))
        proc = subprocess.run(cmd, stderr=subprocess.PIPE)
        assert proc.returncode == 1
        assert proc.stderr.decode('utf-8') == (
            f'ostree-receive-shell: Executing {args[0]} not allowed\n'
        )


# This test depends on the temporary ostree-receive being the only one
# in PATH, so it has to be skipped otherwise. It might be possible to
# mangle PATH so it's avoided, but then the required python might also
# be removed from PATH.
@skip_ostree_receive_in_path
def test_exec_errors(shell_env_vars, tmp_shell, tmp_receive, tmp_path):
    """Test how errors from execve are handled"""
    cmd = ('ostree-receive-shell', '-c', tmp_receive.name)

    # Make the temporary ostree-receive non-executable to get a
    # permission denied error.
    tmp_receive.chmod(0o644)
    proc = subprocess.run(cmd, env=shell_env_vars, stderr=subprocess.PIPE)
    assert proc.returncode == 126
    assert proc.stderr.decode('utf-8') == (
        f'ostree-receive-shell: {tmp_receive.name}: Permission denied\n'
    )

    # Make the temporary ostree-receive into a dangling symlink to get a
    # file not found error.
    tmp_receive.unlink()
    tmp_receive.symlink_to(tmp_path / 'nonexistent')
    proc = subprocess.run(cmd, env=shell_env_vars, stderr=subprocess.PIPE)
    assert proc.returncode == 127
    assert proc.stderr.decode('utf-8') == (
        f'ostree-receive-shell: {tmp_receive.name}: '
        'No such file or directory\n'
    )
