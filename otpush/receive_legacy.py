#!/usr/bin/python3

# ostree-receive-0 - Receive OSTree commits from remote client
# Copyright (C) 2015  Dan Nicholson <nicholson@endlessm.com>
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

from argparse import ArgumentParser
from enum import Enum

import gi
import logging
import os
import sys
import tempfile
import shutil

gi.require_version('OSTree', '1.0')
from gi.repository import GLib, Gio, OSTree  # noqa: E402

PROTO_VERSION = 0
HEADER_SIZE = 5


class PushException(Exception):
    pass


class PushCommandType(Enum):
    info = 0
    update = 1
    putobject = 2
    status = 3
    done = 4


def msg_byteorder(sys_byteorder=sys.byteorder):
    if sys_byteorder == 'little':
        return 'l'
    elif sys_byteorder == 'big':
        return 'B'
    else:
        raise PushException('Unrecognized system byteorder %s'
                            % sys_byteorder)


def sys_byteorder(msg_byteorder):
    if msg_byteorder == 'l':
        return 'little'
    elif msg_byteorder == 'B':
        return 'big'
    else:
        raise PushException('Unrecognized message byteorder %s'
                            % msg_byteorder)


def ostree_object_path(repo, obj):
    repodir = repo.get_path().get_path()
    return os.path.join(repodir, 'objects', obj[0:2], obj[2:])


class PushCommand(object):
    def __init__(self, cmdtype, args):
        self.cmdtype = cmdtype
        self.args = args
        self.validate(self.cmdtype, self.args)
        self.variant = GLib.Variant('a{sv}', self.args)

    @staticmethod
    def validate(command, args):
        if not isinstance(command, PushCommandType):
            raise PushException('Message command must be PushCommandType')
        if not isinstance(args, dict):
            raise PushException('Message args must be dict')
        # Ensure all values are variants for a{sv} vardict
        for val in args.values():
            if not isinstance(val, GLib.Variant):
                raise PushException('Message args values must be '
                                    'GLib.Variant')


class PushMessageWriter(object):
    def __init__(self, file, byteorder=sys.byteorder):
        self.file = file
        self.byteorder = byteorder
        self.msg_byteorder = msg_byteorder(self.byteorder)

    def encode_header(self, cmdtype, size):
        header = self.msg_byteorder.encode() + \
                 PROTO_VERSION.to_bytes(1, self.byteorder) + \
                 cmdtype.value.to_bytes(1, self.byteorder) + \
                 size.to_bytes(2, self.byteorder)
        return header

    def encode_message(self, command):
        if not isinstance(command, PushCommand):
            raise PushException('Command must by GLib.Variant')
        data = command.variant.get_data_as_bytes()
        size = data.get_size()

        # Build the header
        header = self.encode_header(command.cmdtype, size)

        return header + data.get_data()

    def write(self, command):
        msg = self.encode_message(command)
        self.file.write(msg)
        self.file.flush()

    def send_info(self, repo):
        cmdtype = PushCommandType.info
        mode = repo.get_mode()
        _, refs = repo.list_refs(None, None)
        args = {
            'mode': GLib.Variant('i', mode),
            'refs': GLib.Variant('a{ss}', refs)
        }
        command = PushCommand(cmdtype, args)
        self.write(command)

    def send_update(self, refs):
        cmdtype = PushCommandType.update
        args = {}
        for branch, revs in refs.items():
            args[branch] = GLib.Variant('(ss)', revs)
        command = PushCommand(cmdtype, args)
        self.write(command)

    def send_putobject(self, repo, obj):
        cmdtype = PushCommandType.putobject
        objpath = ostree_object_path(repo, obj)
        size = os.stat(objpath).st_size
        args = {
            'object': GLib.Variant('s', obj),
            'size': GLib.Variant('t', size)
        }
        command = PushCommand(cmdtype, args)
        self.write(command)

        # Now write the file after the command
        logging.info('Sending object {}'.format(obj))
        logging.debug('Size {} from {}'.format(size, objpath))
        with open(objpath, 'rb') as objf:
            remaining = size
            while remaining > 0:
                chunk = min(2 ** 20, remaining)
                buf = objf.read(chunk)
                logging.debug('Sending {} bytes for {}'
                              .format(len(buf), obj))
                self.file.write(buf)
                self.file.flush()
                remaining -= chunk
                logging.debug('{} bytes remaining for {}'
                              .format(remaining, obj))

    def send_status(self, result, message=''):
        cmdtype = PushCommandType.status
        args = {
            'result': GLib.Variant('b', result),
            'message': GLib.Variant('s', message)
        }
        command = PushCommand(cmdtype, args)
        self.write(command)

    def send_done(self):
        command = PushCommand(PushCommandType.done, {})
        self.write(command)


class PushMessageReader(object):
    def __init__(self, file, byteorder=sys.byteorder, tmpdir=None):
        self.file = file
        self.byteorder = byteorder
        self.tmpdir = tmpdir

    def decode_header(self, header):
        if len(header) != HEADER_SIZE:
            raise Exception('Header is %d bytes, not %d'
                            % (len(header), HEADER_SIZE))
        order = sys_byteorder(chr(header[0]))
        version = int(header[1])
        if version != PROTO_VERSION:
            raise Exception('Unsupported protocol version %d' % version)
        cmdtype = PushCommandType(int(header[2]))
        vlen = int.from_bytes(header[3:], order)
        return order, version, cmdtype, vlen

    def decode_message(self, message, size, order):
        if len(message) != size:
            raise Exception('Expected %d bytes, but got %d'
                            % (size, len(message)))
        data = GLib.Bytes.new(message)
        variant = GLib.Variant.new_from_bytes(GLib.VariantType.new('a{sv}'),
                                              data, False)
        if order != self.byteorder:
            variant = GLib.Variant.byteswap(variant)

        return variant

    def read(self):
        header = self.file.read(HEADER_SIZE)
        if len(header) == 0:
            # Remote end quit
            return None, None
        order, version, cmdtype, size = self.decode_header(header)
        msg = self.file.read(size)
        if len(msg) != size:
            raise PushException('Did not receive full message')
        args = self.decode_message(msg, size, order)

        return cmdtype, args

    def receive(self, allowed):
        cmdtype, args = self.read()
        if cmdtype is None:
            raise PushException('Expected reply, got none')
        if cmdtype not in allowed:
            raise PushException('Unexpected reply type', cmdtype.name)
        return cmdtype, args.unpack()

    def receive_info(self):
        cmdtype, args = self.receive([PushCommandType.info])
        return args

    def receive_update(self):
        cmdtype, args = self.receive([PushCommandType.update])
        return args

    def receive_putobject_data(self, repo, args):
        # Read in the object and store it in the tmp directory
        obj = args['object']
        size = args['size']
        tmppath = os.path.join(self.tmpdir, obj)
        logging.info('Receiving object {}'.format(obj))
        logging.debug('Size {} to {}'.format(size, tmppath))
        with open(tmppath, 'wb') as tmpf:
            remaining = size
            while remaining > 0:
                chunk = min(2 ** 20, remaining)
                buf = self.file.read(chunk)
                logging.debug('Receiving {} bytes for {}'
                              .format(len(buf), obj))
                tmpf.write(buf)
                remaining -= chunk
                logging.debug('{} bytes remaining for {}'
                              .format(remaining, obj))

    def receive_putobject(self, repo):
        cmdtype, args = self.receive([PushCommandType.putobject])
        self.receive_putobject_data(repo, args)
        return args

    def receive_status(self):
        cmdtype, args = self.receive([PushCommandType.status])
        return args

    def receive_done(self):
        cmdtype, args = self.receive([PushCommandType.done])
        return args


class OSTreeReceiver(object):
    def __init__(self, repopath):
        self.repopath = repopath

        if self.repopath is None:
            self.repo = OSTree.Repo.new_default()
        else:
            self.repo = OSTree.Repo.new(Gio.File.new_for_path(self.repopath))
        self.repo.open(None)

        repo_tmp = os.path.join(self.repopath, 'tmp')
        self.tmpdir = tempfile.mkdtemp(dir=repo_tmp, prefix='ostree-push-')
        self.writer = PushMessageWriter(sys.stdout.buffer)
        self.reader = PushMessageReader(sys.stdin.buffer, tmpdir=self.tmpdir)

        # Set a sane umask before writing any objects
        os.umask(0o0022)

    def close(self):
        shutil.rmtree(self.tmpdir)
        sys.stdout.close()
        return 0

    def run(self):
        try:
            return self.do_run()
        except PushException:
            # Ensure we cleanup files if there was an error
            self.close()
            raise

    def do_run(self):
        # Send info immediately
        self.writer.send_info(self.repo)

        # Wait for update or done command
        cmdtype, args = self.reader.receive([PushCommandType.update,
                                             PushCommandType.done])
        if cmdtype == PushCommandType.done:
            return 0
        update_refs = args
        for branch, revs in update_refs.items():
            # Check that each branch can be updated appropriately
            _, current = self.repo.resolve_rev(branch, True)
            if current is None:
                # From commit should be all 0s
                if revs[0] != '0' * 64:
                    self.writer.send_status(False,
                                            'Invalid from commit %s '
                                            'for new branch %s'
                                            % (revs[0], branch))
                    self.reader.receive_done()
                    return 1
            elif revs[0] != current:
                self.writer.send_status(False,
                                        'Branch %s is at %s, not %s'
                                        % (branch, current, revs[0]))
                self.reader.receive_done()
                return 1

        # All updates valid
        self.writer.send_status(True)

        # Wait for putobject or done command
        received_objects = []
        while True:
            cmdtype, args = self.reader.receive([PushCommandType.putobject,
                                                 PushCommandType.done])
            if cmdtype == PushCommandType.done:
                logging.debug('Received done, exiting putobject loop')
                break

            self.reader.receive_putobject_data(self.repo, args)
            received_objects.append(args['object'])
            self.writer.send_status(True)

        # If we didn't get any objects, we're done
        if len(received_objects) == 0:
            return 0

        # Got all objects, move them to the object store
        for obj in received_objects:
            tmp_path = os.path.join(self.tmpdir, obj)
            obj_path = ostree_object_path(self.repo, obj)
            os.makedirs(os.path.dirname(obj_path), exist_ok=True)
            logging.debug('Renaming {} to {}'.format(tmp_path, obj_path))
            os.rename(tmp_path, obj_path)

        # Finally, update the refs
        for branch, revs in update_refs.items():
            logging.debug('Setting ref {} to {}'.format(branch, revs[1]))
            self.repo.set_ref_immediate(None, branch, revs[1], None)

        return 0


def main():
    aparser = ArgumentParser(description='Receive pushed ostree objects')
    aparser.add_argument('--repo', help='repository path')
    aparser.add_argument('-v', '--verbose', action='store_true',
                         help='enable verbose output')
    aparser.add_argument('--debug', action='store_true',
                         help='enable debugging output')
    args = aparser.parse_args()

    loglevel = logging.WARNING
    if args.verbose:
        loglevel = logging.INFO
    if args.debug:
        loglevel = logging.DEBUG
    logging.basicConfig(format='%(module)s: %(levelname)s: %(message)s',
                        level=loglevel, stream=sys.stderr)

    receiver = OSTreeReceiver(args.repo)
    return receiver.run()


if __name__ == '__main__':
    exit(main())
