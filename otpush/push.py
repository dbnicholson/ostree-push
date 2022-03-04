#!/usr/bin/python3

# ostree-push - Push local ostree repo to remote server over SSH
# Copyright (C) 2017  Endless Mobile, Inc.
# Copyright (C) 2021  Endless OS Foundation LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

"""Push local ostree repo to remote server over SSH

ostree-push allows coherently publishing an ostree repo to a remote
server. It works by opening an SSH connection to the remote server and
initiating the ostree-receive service to pull from an HTTP server on the
local host. This has a distinct advantage over using rsync where files
can be pushed in the wrong order and there's no ability to push a subset
of the refs in the local repo.

ostree-push will start an HTTP server and tunnel its port to the remote
server. This allows publishing from a host that is not running an HTTP
server and avoids any firewalls between the local and remote hosts.

In either case, ostree-receive must be installed on the remote host to
pull from the tunnelled HTTP server.
"""

from . import VERSION

from argparse import Action, ArgumentError, ArgumentParser
from collections import namedtuple
import gi
from http.server import SimpleHTTPRequestHandler
import logging
import multiprocessing
import os
import queue
import shlex
import subprocess
from tempfile import TemporaryDirectory
import threading
import time
from urllib.parse import urlparse

try:
    from http.server import ThreadingHTTPServer
except ImportError:
    from http.server import HTTPServer
    from socketserver import ThreadingMixIn

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True

gi.require_version('OSTree', '1.0')
from gi.repository import Gio, OSTree  # noqa: E402

logger = logging.getLogger(__name__)

# Timeout in seconds when waiting for ports or sockets
RESOURCE_TIMEOUT = 60


class OTPushError(Exception):
    """Exceptions from ostree-push"""
    pass


class OSTreeRequestHandler(SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler with logging"""
    def log_message(self, format, *args):
        logger.debug("%s: %s - - [%s] %s",
                     threading.current_thread().name,
                     self.address_string(),
                     self.log_date_time_string(),
                     format % args)


class RepoServer:
    """HTTP server for repo

    Start an HTTP server running at the repository path. The server
    listens on an ephemeral port on the loopback address. The timeout
    parameter controls how long to wait for the server process to send
    back its URL.

    When used as a context manager, the server is stopped when the
    context closes.
    """
    def __init__(self, path, timeout=RESOURCE_TIMEOUT):
        self.path = path
        self.timeout = timeout
        self.proc = None
        self.address = None
        self.url = None

        if not os.path.isdir(path):
            raise ValueError('{} is not a directory'.format(path))

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

    def _run_server(self, path, queue):
        # FIXME: When python 3.7 is the minimum, use the
        # SimpleHTTPRequestHandler directory parameter with
        # functools.partial instead of changing directory.
        os.chdir(path)
        server = ThreadingHTTPServer(('127.0.0.1', 0), OSTreeRequestHandler)
        queue.put(server.server_address)
        server.serve_forever()

    def start(self):
        """Start an HTTP server for the repo

        The server is started in a separate process which send back the
        address it is bound to. If the address is not received by the
        instance's timeout value, an exception is raised.
        """
        addr_queue = multiprocessing.Queue()
        self.proc = multiprocessing.Process(
            target=self._run_server,
            args=(self.path, addr_queue)
        )
        self.proc.start()
        if not self.proc.is_alive():
            raise OTPushError(f'HTTP process {self.proc.pid} exited')
        try:
            self.address = addr_queue.get(True, self.timeout)
        except queue.Empty:
            raise OTPushError('HTTP process did not write port to queue') \
                from None

        self.url = f'http://{self.address[0]}:{self.address[1]}'
        logger.info('Serving %s on %s from process %d', self.path, self.url,
                    self.proc.pid)

    def stop(self):
        """Stop the HTTP server"""
        if self.proc is not None:
            if self.proc.is_alive():
                logger.debug('Stopping HTTP server process %d', self.proc.pid)
                self.proc.terminate()
            self.proc = None


class SSHMultiplexer:
    """SSH multiplexer for connecting with a remote host

    The remote host and a path to a non-existent socket.
    """
    def __init__(self, host, socket, ssh_options=None, user=None,
                 port=None):
        self.host = host
        self.user = user
        self.port = port
        self.socket = socket
        self.ssh_options = ssh_options
        self.master_proc = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

    def __del__(self):
        self.stop()

    def start(self):
        """Start an SSH master connection

        Run an SSH master connection to host in the background.
        """
        if self.master_proc is not None:
            raise OTPushError(
                f'SSH master process already running in {self.master_proc.pid}'
            )
        if os.path.exists(self.socket):
            raise OTPushError(f'Socket {self.socket} already exists')

        # Create the socket file if necessary
        # Options used:
        # -N: Don't execute a remote command
        # -M: Puts the client in master mode for connection sharing
        # -S: Specify the location of the control socket
        master_cmd = ['ssh', '-N', '-M', '-S', self.socket]
        if self.port:
            master_cmd += ['-p', str(self.port)]
        if self.ssh_options:
            master_cmd += self.ssh_options
        if self.user:
            master_cmd.append(f'{self.user}@{self.host}')
        else:
            master_cmd.append(self.host)
        logger.debug('Starting SSH master process %s',
                     ' '.join(map(shlex.quote, master_cmd)))
        self.master_proc = subprocess.Popen(master_cmd)

        # Loop until the socket shows up
        timeout = 0
        while timeout < RESOURCE_TIMEOUT:
            if self.master_proc.poll() is not None:
                raise OTPushError(
                    f'SSH master process {self.master_proc.pid} exited')
            if os.path.exists(self.socket):
                break
            timeout += 0.5
            time.sleep(0.5)

        if timeout >= RESOURCE_TIMEOUT:
            raise OTPushError(
                f'SSH control socket {self.socket} does not exist')

    def stop(self):
        if self.master_proc is not None:
            if self.master_proc.poll() is None:
                logger.debug('Stopping SSH master process %d',
                             self.master_proc.pid)
                self.master_proc.terminate()
            self.master_proc = None

    def forward_port(self, port):
        """Forward a local port over an SSH master connection

        Forward a local port to host over the SSH master connection. The
        remote port is returned.
        """
        if self.master_proc is None:
            raise OTPushError('SSH master process not running')

        # Options used:
        # -S: Specify the location of the control socket
        # -O: Makes the client print the forwarded port on stdout
        # -R: Forward the local port to the remote. Use 0 as the remote port
        #     so it binds one dynamically.
        forward_cmd = [
            'ssh', '-S', self.socket, '-O', 'forward',
            '-R', f'0:127.0.0.1:{port}'
        ]
        if self.ssh_options:
            forward_cmd += self.ssh_options
        forward_cmd.append(self.host)
        logger.debug('Forwarding HTTP port with %s',
                     ' '.join(map(shlex.quote, forward_cmd)))
        out = subprocess.check_output(forward_cmd)

        # Pass the output through int() so that any whitespace is stripped
        # and we know a port number was returned. Anything else will raise a
        # ValueError.
        return int(out)

    def run(self, cmd):
        """Run a command on the remote host using the master connection"""
        if self.master_proc is None:
            raise OTPushError('SSH master process not running')

        run_cmd = ['ssh', '-S', self.socket]
        if self.ssh_options:
            run_cmd += self.ssh_options
        run_cmd += [self.host] + cmd
        logger.debug('Executing ' + ' '.join(map(shlex.quote, cmd)))
        subprocess.check_call(run_cmd)


def push_refs(local_repo, dest, refs=None, ssh_options=None,
              command='ostree-receive', dry_run=False):
    """Run ostree-receive on remote with a tunneled HTTP server

    Start a local HTTP server and tunnel its port to the remote host.
    Use this tunneled HTTP server as the URL for ostree_receive().
    """
    local_repo_path = local_repo.get_path().get_path()

    # If refs were specified, make sure they exist before bothering with
    # the remote connection
    if refs:
        list_refs_flags = OSTree.RepoListRefsExtFlags.EXCLUDE_REMOTES
        try:
            # EXCLUDE_MIRRORS only available since ostree 2019.2
            list_refs_flags |= OSTree.RepoListRefsExtFlags.EXCLUDE_MIRRORS
        except AttributeError:
            pass
        _, local_refs = local_repo.list_refs_ext(None, list_refs_flags)
        missing_refs = sorted(set(refs) - local_refs.keys())
        if missing_refs:
            raise OTPushError(
                f'Refs {" ".join(missing_refs)} not found in {local_repo_path}'
            )

    summary = os.path.join(local_repo_path, 'summary')
    update_summary = False
    if not os.path.exists(summary):
        logger.debug('%s does not exist, regenerating', summary)
        update_summary = True
    else:
        # OSTree updates the mtime of the repo directory when refs have
        # been updated, so if that's newer than the summary, it needs to
        # be regenerated.
        repo_mtime = os.path.getmtime(local_repo_path)
        summary_mtime = os.path.getmtime(summary)
        if summary_mtime < repo_mtime:
            logger.debug('Repo %s has been modified more recently than %s, '
                         'regenerating',
                         local_repo_path, summary)
            update_summary = True
    if update_summary:
        logger.info('Regenerating summary file')
        local_repo.regenerate_summary()

    with RepoServer(local_repo_path) as http_server:
        http_port = http_server.address[1]

        with TemporaryDirectory(prefix='ostree-push-') as tempdir:
            socket_path = os.path.join(tempdir, 'socket')

            # Start an SSH master, forward the HTTP port to the remote
            # server and run ostree-receive there
            with SSHMultiplexer(dest.host, socket_path, ssh_options,
                                user=dest.user, port=dest.port) as ssh:
                remote_port = ssh.forward_port(http_port)
                logger.info('Connected local HTTP port %d to remote port %d',
                            http_port, remote_port)
                remote_url = f'http://127.0.0.1:{remote_port}'

                cmd = shlex.split(command)
                if dry_run:
                    cmd.append('-n')
                cmd += [dest.repo, remote_url]
                if refs is not None:
                    cmd += refs
                logger.debug('Remote command: %s', cmd)
                ssh.run(cmd)


PushDest = namedtuple('PushDest', ('host', 'repo', 'user', 'port'))


def parse_dest(dest):
    """Parse the push destination into host and repo

    Allowed destinations are:

    * [user@]host:path/to/repo
    * ssh://[user@]host[:port]/path/to/repo
    """
    # A bit of care is needed because urlparse parses host:repo into a
    # scheme and path but user@host:repo into just a path.
    parts = urlparse(dest)
    if parts.scheme and parts.netloc:
        # ssh:// URL
        if parts.scheme != 'ssh':
            raise ValueError(
                f'Destination scheme "{parts.scheme}" not allowed')
        if not parts.path:
            raise ValueError('Destintion repo missing')

        return PushDest(host=parts.hostname, user=parts.username,
                        port=parts.port, repo=parts.path)
    else:
        # scp form. There should be at least 1 : to separate the host
        # and repo.
        host, sep, repo = dest.partition(':')
        if not sep:
            raise ValueError('Destination not in form "host:repo"')
        if not host:
            raise ValueError('Destination host missing')
        if not repo:
            raise ValueError('Destination repo missing')

        # Try to split user@ from the host.
        user = None
        tmpuser, sep, tmphost = host.partition('@')
        if sep:
            if not tmpuser or not tmphost:
                raise ValueError(f'Invalid destination host {host}')
            host = tmphost
            user = tmpuser

        return PushDest(host=host, user=user, repo=repo, port=None)


class DestArgAction(Action):
    """Action to set push destination"""
    def __init__(self, option_strings, dest, nargs=None, default=None,
                 **kwargs):
        if nargs is not None:
            raise ValueError('nargs not allowed')
        if default is not None:
            raise ValueError('default not allowed')

        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string):
        dest = parse_dest(values)
        setattr(namespace, self.dest, dest)


class SSHOptAction(Action):
    """Action to collect ssh option verbatim"""
    # Options that can be specified multiple times
    MULTI_OPTS = {'-o'}

    def __init__(self, option_strings, dest, nargs=None, default=None,
                 **kwargs):
        if option_strings is None:
            raise ValueError('option strings are required')
        if nargs is not None:
            raise ValueError('nargs not allowed')
        if default is not None:
            raise ValueError('default not allowed')

        dest = 'ssh_options'
        default = []
        super().__init__(option_strings, dest, default=default, **kwargs)

    def __call__(self, parser, namespace, values, option_string):
        logger.debug('Parsing SSH option %r, %r, %r', namespace, option_string,
                     values)

        # A bit of care is needed in case parse_args() is called
        # multiple times. The default list needs to be copied so it's
        # not updated and the set of options seen needs to be reset.
        ssh_opts = getattr(namespace, self.dest)
        if ssh_opts is self.default:
            ssh_opts = ssh_opts.copy()
            self._single_opts_seen = set()

        if option_string not in self.MULTI_OPTS:
            if option_string in self._single_opts_seen:
                raise ArgumentError(
                    self,
                    f'Option {option_string} can only be specified once'
                )
            self._single_opts_seen.add(option_string)

        ssh_opts += [option_string, values]
        setattr(namespace, self.dest, ssh_opts)


class OTPushArgParser(ArgumentParser):
    """ArgumentParser for ostree-push"""
    def __init__(self):
        super().__init__(
            description='Push ostree refs to remote repository'
        )

        self.add_argument(
            'dest', metavar='DEST', action=DestArgAction,
            help=(
                'remote host and repo destination. DEST can take one of two '
                'forms: [user@]host:path/to/repo '
                'or ssh://[user@]host[:port]/path/to/repo.'
            )
        )
        self.add_argument('refs', metavar='REF', nargs='*', default=[],
                          help='ostree refs to push, all if none specified')
        self.add_argument('-n', '--dry-run', action='store_true',
                          help='only show what would be done')
        self.add_argument('-p', dest='port', type=int,
                          help='ssh port to connect to')
        self.set_defaults(log_level=logging.INFO)
        self.add_argument('-q', '--quiet', dest='log_level',
                          action='store_const', const=logging.WARNING,
                          help='disable most messages')
        self.add_argument('-v', '--verbose', dest='log_level',
                          action='store_const', const=logging.DEBUG,
                          help='enable verbose messages')
        self.add_argument(
            '--repo',
            help='local repository path (default: current directory)'
        )
        self.add_argument('--command', default='ostree-receive',
                          help='remote pull command (default: %(default)s)')
        self.add_argument('-i', '-o', metavar='OPTION',
                          action=SSHOptAction,
                          help='options passed through to ssh')
        self.add_argument('--version', action='version',
                          version=f'%(prog)s {VERSION}')

    def parse_args(self, *args, **kwargs):
        args = super().parse_args(*args, **kwargs)

        # If a port option has been supplied, replace the port in the
        # dest argument with it.
        if args.port:
            args.dest = args.dest._replace(port=args.port)

        return args


def main(argv=None):
    aparser = OTPushArgParser()
    args = aparser.parse_args(argv)

    logging.basicConfig(level=args.log_level)

    # Open the local repo and get the full path
    if args.repo:
        repo_file = Gio.File.new_for_path(args.repo)
        repo = OSTree.Repo.new(repo_file)
    else:
        repo = OSTree.Repo.new_default()
    repo.open()

    push_refs(repo, args.dest, refs=args.refs,
              ssh_options=args.ssh_options, command=args.command,
              dry_run=args.dry_run)


if __name__ == '__main__':
    main()
