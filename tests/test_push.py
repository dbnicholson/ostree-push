from otpush import push

import argparse
from gi.repository import GLib, Gio
import logging
import json
import os
from pathlib import Path
import pytest
import re
import socket
import subprocess
from urllib.error import HTTPError
from urllib.request import urlopen

from .util import (
    TESTSDIR,
    needs_sshd,
    random_commit,
    TmpRepo,
)

logger = logging.getLogger(__name__)


class TestRepoServer:
    def populate_repo(self):
        self.repo.mkdir()
        sub = self.repo / 'sub'
        sub.mkdir()
        with open(self.repo / 'a', 'w') as f:
            f.write('foo')
        with open(sub / 'b', 'w') as f:
            f.write('bar')

    def check_server(self):
        assert self.server.path == self.repo
        assert self.server.proc.pid > 0
        assert self.server.address[0] == '127.0.0.1'
        assert self.server.address[1] > 0
        assert self.server.url.startswith('http://127.0.0.1:')
        with urlopen(f'{self.server.url}/a') as resp:
            assert resp.read().decode('utf-8') == 'foo'
        with urlopen(f'{self.server.url}/sub/b') as resp:
            assert resp.read().decode('utf-8') == 'bar'
        with pytest.raises(HTTPError) as excinfo:
            urlopen(f'{self.server.url}/missing')
        assert excinfo.value.getcode() == 404

    def test_missing(self, tmp_path):
        # Nonexistent directory should fail
        repo = tmp_path / 'repo'
        server = None
        with pytest.raises(ValueError) as excinfo:
            server = push.RepoServer(repo)
        assert str(excinfo.value) == f'{repo} is not a directory'
        assert server is None

    def test_non_context(self, tmp_path):
        # Without context manager
        self.repo = tmp_path / 'repo'
        self.populate_repo()

        self.server = push.RepoServer(self.repo)
        assert self.server.path == self.repo
        assert self.server.proc is None
        assert self.server.address is None
        assert self.server.url is None

        # This should do nothing
        self.server.stop()

        # Make sure to clean up so the tests don't hang if there are failures
        try:
            self.server.start()
            self.check_server()
            self.server.stop()
        finally:
            self.server.stop()

    def test_context(self, tmp_path):
        self.repo = tmp_path / 'repo'
        self.populate_repo()
        with push.RepoServer(self.repo) as self.server:
            self.check_server()

    def test_pull(self, tmp_path, tmp_files_path):
        local_repo = TmpRepo(tmp_path / 'local')
        remote_repo = TmpRepo(tmp_path / 'remote')
        random_commit(remote_repo, tmp_files_path, 'test')
        _, remote_refs = remote_repo.list_refs()

        with push.RepoServer(str(remote_repo.path)) as remote_server:
            repo_options = GLib.Variant('a{sv}', {
                'gpg-verify': GLib.Variant('b', False),
                'gpg-verify-summary': GLib.Variant('b', False),
            })
            local_repo.remote_add('origin', remote_server.url, repo_options)

            # Pulling a missing ref should fail
            pull_options = GLib.Variant('a{sv}', {
                'refs': GLib.Variant('as', ['missing']),
            })
            with pytest.raises(GLib.Error) as excinfo:
                local_repo.pull_with_options('origin', pull_options)
            assert excinfo.value.matches(Gio.io_error_quark(),
                                         Gio.IOErrorEnum.NOT_FOUND)
            _, local_refs = local_repo.list_refs()
            assert local_refs == {}

            # Pulling the existing ref should succeed
            pull_options = GLib.Variant('a{sv}', {
                'refs': GLib.Variant('as', ['test']),
            })
            local_repo.pull_with_options('origin', pull_options)
            _, local_refs = local_repo.list_refs()
            assert local_refs == {'origin:test': remote_refs['test']}

            # Pulling with all refs should fail because no branches were
            # setup in the configuration
            local_repo.set_ref_immediate('origin', 'test', None)
            _, local_refs = local_repo.list_refs()
            assert local_refs == {}
            pull_options = GLib.Variant('a{sv}', {})
            with pytest.raises(GLib.Error) as excinfo:
                local_repo.pull_with_options('origin', pull_options)
            assert excinfo.value.matches(Gio.io_error_quark(),
                                         Gio.IOErrorEnum.FAILED)
            assert ('No configured branches for remote origin'
                    in str(excinfo.value))
            assert local_refs == {}


@needs_sshd
class TestSSHMultiplexer:
    def test_socket_exists(self, sshd, ssh_options, ssh_socket):
        ssh = push.SSHMultiplexer(sshd.address, ssh_socket, ssh_options,
                                  port=sshd.port)
        with open(ssh_socket, 'w'):
            pass
        with pytest.raises(push.OTPushError) as excinfo:
            ssh.start()
        assert str(excinfo.value) == f'Socket {ssh_socket} already exists'

    def test_master_non_context(self, sshd, ssh_options, ssh_socket):
        ssh = push.SSHMultiplexer(sshd.address, ssh_socket, ssh_options,
                                  port=sshd.port)

        # Stopping without starting should do nothing
        assert ssh.master_proc is None
        assert not os.path.exists(ssh_socket)
        ssh.stop()

        try:
            ssh.start()
            assert ssh.master_proc.pid > 0
            assert os.path.exists(ssh_socket)

            with pytest.raises(push.OTPushError) as excinfo:
                ssh.start()
            assert str(excinfo.value).startswith(
                'SSH master process already running')
        finally:
            ssh.stop()

    def test_master_context(self, sshd, ssh_options, ssh_socket):
        with push.SSHMultiplexer(sshd.address, ssh_socket, ssh_options,
                                 port=sshd.port) as ssh:
            assert ssh.master_proc.pid > 0
            assert os.path.exists(ssh_socket)

    def test_forward_port(self, sshd, ssh_options, ssh_socket):
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        sock1.bind(('127.0.0.1', 0))
        sock1_port = sock1.getsockname()[1]
        assert sock1_port > 0

        ssh = push.SSHMultiplexer(sshd.address, ssh_socket, ssh_options,
                                  port=sshd.port)
        with pytest.raises(push.OTPushError) as excinfo:
            ssh.forward_port(sock1_port)
        assert str(excinfo.value) == 'SSH master process not running'
        assert ssh.master_proc is None

        with push.SSHMultiplexer(sshd.address, ssh_socket, ssh_options,
                                 port=sshd.port) as ssh:
            sock2_port = ssh.forward_port(sock1_port)
            assert sock2_port > 0

            sock3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            sock3.connect(('127.0.0.1', sock2_port))

    def test_run(self, tmp_path, sshd, ssh_options, ssh_socket):
        ssh = push.SSHMultiplexer(sshd.address, ssh_socket, ssh_options,
                                  port=sshd.port)
        with pytest.raises(push.OTPushError) as excinfo:
            ssh.run(['true'])
        assert str(excinfo.value) == 'SSH master process not running'
        assert ssh.master_proc is None

        with push.SSHMultiplexer(sshd.address, ssh_socket, ssh_options,
                                 port=sshd.port) as ssh:
            test_file = tmp_path / 'test_file'
            assert not os.path.exists(test_file)
            ssh.run(['touch', str(test_file)])
            assert os.path.exists(test_file)

            with pytest.raises(subprocess.CalledProcessError,
                               match='returned non-zero exit status 1'):
                ssh.run(['rmdir', str(tmp_path)])


@needs_sshd
class TestPushRefs:
    DUMPENV_PATH = os.path.join(TESTSDIR, 'dumpenv')

    def push_refs(self, source_repo, dest_repo, sshd, ssh_options, capfd,
                  refs=None, dry_run=False):
        """Run push.push_refs and check the remote command is correct"""
        dest = push.PushDest(host=sshd.address, port=sshd.port,
                             repo=str(dest_repo.path), user=None)
        push.push_refs(source_repo, dest, refs=refs, dry_run=dry_run,
                       ssh_options=ssh_options, command='dumpenv')

        out, _ = capfd.readouterr()
        data = json.loads(out)
        args = data['args']

        num_args = len(args)
        num_refs = len(refs) if refs else 0
        expected_num_args = num_refs + 3
        if dry_run:
            expected_num_args += 1
        assert num_args == expected_num_args

        args_iter = iter(args)
        assert next(args_iter) == self.DUMPENV_PATH
        if dry_run:
            assert next(args_iter) == '-n'
        assert next(args_iter) == str(dest_repo.path)
        assert next(args_iter).startswith('http://127.0.0.1:')
        remaining = list(args_iter)
        if refs:
            assert remaining == refs
        else:
            assert remaining == []

    def test_no_refs(self, source_repo, dest_repo, sshd, ssh_options,
                     tmp_files_path, capfd):
        self.push_refs(source_repo, dest_repo, sshd, ssh_options, capfd,
                       refs=None)

        self.push_refs(source_repo, dest_repo, sshd, ssh_options, capfd,
                       refs=[])

    def test_refs(self, source_repo, dest_repo, sshd, ssh_options,
                  tmp_files_path, capfd):
        random_commit(source_repo, tmp_files_path, 'test1')
        random_commit(source_repo, tmp_files_path, 'test2')
        self.push_refs(source_repo, dest_repo, sshd, ssh_options, capfd,
                       refs=['test1'])
        self.push_refs(source_repo, dest_repo, sshd, ssh_options, capfd,
                       refs=['test2'])
        self.push_refs(source_repo, dest_repo, sshd, ssh_options, capfd,
                       refs=['test1', 'test2'])

    def test_missing_ref(self, source_repo, dest_repo, sshd, ssh_options,
                         tmp_files_path, capfd):
        random_commit(source_repo, tmp_files_path, 'test')
        with pytest.raises(push.OTPushError) as excinfo:
            self.push_refs(source_repo, dest_repo, sshd, ssh_options, capfd,
                           refs=['missing'])
        assert str(excinfo.value) == \
            f'Refs missing not found in {source_repo.path}'
        with pytest.raises(push.OTPushError) as excinfo:
            self.push_refs(source_repo, dest_repo, sshd, ssh_options, capfd,
                           refs=['test', 'missing'])
        assert str(excinfo.value) == \
            f'Refs missing not found in {source_repo.path}'

    def test_summary(self, source_repo, dest_repo, sshd, ssh_options,
                     tmp_files_path, capfd):
        summary = Path(source_repo.path) / 'summary'
        random_commit(source_repo, tmp_files_path, 'test')

        # Delete the summary file and check that it gets generated.
        summary.unlink()
        self.push_refs(source_repo, dest_repo, sshd, ssh_options, capfd)
        assert summary.exists()

        # Set the summary mtime behind the repo and check that it gets
        # regenerated.
        repo_mtime = os.path.getmtime(source_repo.path)
        os.utime(summary, (repo_mtime - 1, repo_mtime - 1))
        orig_summary_mtime = summary.stat().st_mtime
        assert orig_summary_mtime < repo_mtime
        self.push_refs(source_repo, dest_repo, sshd, ssh_options, capfd)
        assert summary.exists()
        new_summary_mtime = summary.stat().st_mtime
        assert new_summary_mtime > orig_summary_mtime

    def test_dry_run(self, source_repo, dest_repo, sshd, ssh_options,
                     tmp_files_path, capfd):
        self.push_refs(source_repo, dest_repo, sshd, ssh_options, capfd,
                       dry_run=True)


class TestParseDest:
    def test_bad_scheme(self):
        for scheme in ('http', 'ftp', 'scp', 'blah'):
            with pytest.raises(
                    ValueError,
                    match=f'Destination scheme "{scheme}" not allowed'):
                push.parse_dest(f'{scheme}://host/repo')

    def test_missing_repo(self):
        for dest in ('ssh://', 'http://', 'host:', 'user@host:'):
            with pytest.raises(ValueError, match='Destination repo missing'):
                push.parse_dest('host:')

    def test_empty_dest(self):
        with pytest.raises(ValueError,
                           match='Destination not in form "host:repo"'):
            push.parse_dest('')

    def test_missing_host(self):
        for dest in (':', ':repo', ':/path/:/repo'):
            with pytest.raises(ValueError, match='Destination host missing'):
                push.parse_dest(dest)

    def test_invalid_host(self):
        for dest in ('@:repo', '@host:repo', 'user@:repo'):
            with pytest.raises(ValueError, match='Invalid destination host'):
                push.parse_dest(dest)

    def test_invalid_port(self):
        match = re.compile(
            r'(Port could not be cast to integer|invalid literal for int)'
        )
        for dest in ('ssh://host:port/repo', 'ssh://host:$/repo'):
            with pytest.raises(ValueError, match=match):
                push.parse_dest(dest)

    def test_good_dest(self):
        cases = (
            ('ssh://host/repo',
             push.PushDest(host='host', repo='/repo', user=None, port=None)),
            ('ssh://host.example.com/repo',
             push.PushDest(host='host.example.com', repo='/repo', user=None,
                           port=None)),
            ('ssh://host/path/to/repo/',
             push.PushDest(host='host', repo='/path/to/repo/', user=None,
                           port=None)),
            ('ssh://host/path/:/repo',
             push.PushDest(host='host', repo='/path/:/repo', user=None,
                           port=None)),
            ('ssh://user@host/repo',
             push.PushDest(host='host', user='user', repo='/repo', port=None)),
            ('ssh://host:22/repo',
             push.PushDest(host='host', port=22, repo='/repo', user=None)),
            ('host:repo',
             push.PushDest(host='host', repo='repo', user=None, port=None)),
            ('host:path/to/repo',
             push.PushDest(host='host', repo='path/to/repo', user=None,
                           port=None)),
            ('host:/repo',
             push.PushDest(host='host', repo='/repo', user=None, port=None)),
            ('host:/path/:/repo',
             push.PushDest(host='host', repo='/path/:/repo', user=None,
                           port=None)),
            ('user@host:repo',
             push.PushDest(host='host', user='user', repo='repo', port=None)),
            ('user@host.example.com:path/to/repo',
             push.PushDest(host='host.example.com', user='user',
                           repo='path/to/repo', port=None)),
        )

        for arg, expected in cases:
            dest = push.parse_dest(arg)
            assert dest == expected


class TestArgParser:
    def test_no_dest(self, capsys):
        ap = push.OTPushArgParser()
        with pytest.raises(SystemExit) as excinfo:
            ap.parse_args([])
        assert excinfo.value.code == 2
        out, err = capsys.readouterr()
        assert out == ''
        assert err.endswith('error: the following arguments are required: '
                            'DEST\n')

    def test_defaults(self):
        ap = push.OTPushArgParser()
        args = ap.parse_args(['host:repo'])
        assert args == argparse.Namespace(
            command='ostree-receive',
            dest=push.PushDest(host='host', repo='repo', user=None, port=None),
            dry_run=False,
            log_level=logging.INFO,
            port=None,
            refs=[],
            repo=None,
            ssh_options=[],
        )

    def test_dest(self):
        ap = push.OTPushArgParser()
        args = ap.parse_args(['host:repo'])
        assert args.dest == push.PushDest(host='host', repo='repo',
                                          user=None, port=None)
        args = ap.parse_args(['user@host:repo'])
        assert args.dest == push.PushDest(host='host', user='user',
                                          repo='repo', port=None)
        args = ap.parse_args(['ssh://user@host/repo'])
        assert args.dest == push.PushDest(host='host', user='user',
                                          repo='/repo', port=None)
        args = ap.parse_args(['ssh://user@host:1234/repo'])
        assert args.dest == push.PushDest(host='host', user='user',
                                          port=1234, repo='/repo')

    def test_refs(self):
        ap = push.OTPushArgParser()
        args = ap.parse_args(['host:repo', 'foo'])
        assert args.refs == ['foo']
        args = ap.parse_args(['host:repo', 'foo', 'bar', 'baz'])
        assert args.refs == ['foo', 'bar', 'baz']

    def test_port(self, capsys):
        ap = push.OTPushArgParser()
        args = ap.parse_args(['-p', '22', 'host:repo'])
        assert args.port == 22

        with pytest.raises(SystemExit) as excinfo:
            ap.parse_args(['-p', 'foo', 'host:repo'])
        assert excinfo.value.code == 2
        out, err = capsys.readouterr()
        assert out == ''
        assert err.endswith("invalid int value: 'foo'\n")

    def test_port_and_dest_port(self):
        ap = push.OTPushArgParser()
        args = ap.parse_args(['-p', '22', 'ssh://host:2200/repo'])
        assert args.port == 22
        assert args.dest.port == 22

    def test_dry_run(self):
        ap = push.OTPushArgParser()
        args = ap.parse_args(['-n', 'host:repo'])
        assert args.dry_run is True
        args = ap.parse_args(['--dry-run', 'host:repo'])
        assert args.dry_run is True

    def test_log_level(self):
        ap = push.OTPushArgParser()
        args = ap.parse_args(['-v', 'host:repo'])
        assert args.log_level == logging.DEBUG
        args = ap.parse_args(['--verbose', 'host:repo'])
        assert args.log_level == logging.DEBUG
        args = ap.parse_args(['-q', 'host:repo'])
        assert args.log_level == logging.WARNING
        args = ap.parse_args(['--quiet', 'host:repo'])
        assert args.log_level == logging.WARNING

    def test_repo(self):
        ap = push.OTPushArgParser()
        args = ap.parse_args(['--repo', '/repo', 'host:repo'])
        assert args.repo == '/repo'

    def test_command(self):
        ap = push.OTPushArgParser()
        args = ap.parse_args(['--command=ls', 'host:repo'])
        assert args.command == 'ls'
        args = ap.parse_args(['--command=ostree-receive', 'host:repo'])
        assert args.command == 'ostree-receive'
        args = ap.parse_args(['--command', '/path/to/ostree-receive',
                              'host:repo'])
        assert args.command == '/path/to/ostree-receive'

    def test_ssh_options(self, capsys):
        ap = push.OTPushArgParser()
        args = ap.parse_args(['-ifoo', 'host:repo'])
        assert args.ssh_options == ['-i', 'foo']
        args = ap.parse_args(['-i', 'foo', 'host:repo'])
        assert args.ssh_options == ['-i', 'foo']
        args = ap.parse_args(['-o', 'Foo=yes', 'host:repo'])
        assert args.ssh_options == ['-o', 'Foo=yes']
        args = ap.parse_args(['-o', 'Foo=yes', '-o', 'Bar=no',
                              'host:repo'])
        assert args.ssh_options == ['-o', 'Foo=yes', '-o', 'Bar=no']

        with pytest.raises(SystemExit) as excinfo:
            ap.parse_args(['-ifoo', '-ibar', 'host:repo'])
        assert excinfo.value.code == 2
        out, err = capsys.readouterr()
        assert out == ''
        assert err.endswith('Option -i can only be specified once\n')
