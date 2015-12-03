#!/usr/bin/python3

from enum import Enum
from gi.repository import GLib
import logging
import os
import struct
import sys

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

def ostree_tmp_path(repo, obj):
    repodir = repo.get_path().get_path()
    return os.path.join(repodir, 'tmp', obj)

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
        logging.info('Beginning send of {} size {} to {}'
                     .format(obj, size, objpath))
        with open(objpath, 'rb') as objf:
            remaining = size
            while remaining > 0:
                chunk = min(2 ** 20, remaining)
                buf = objf.read(chunk)
                logging.info('Sending {} bytes for {}'
                             .format(len(buf), obj))
                logging.debug('Buffer contents: {}'.format(buf))
                self.file.write(buf)
                self.file.flush()
                remaining -= chunk
                logging.info('{} bytes remaining for {}'
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
    def __init__(self, file, byteorder=sys.byteorder):
        self.file = file
        self.byteorder = byteorder

    def decode_header(self, header):
        if len(header) != HEADER_SIZE:
            raise Exception('Header is %d bytes, not %d'
                            %(len(header), HEADER_SIZE))
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
                            %(size, len(message)))
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
        tmppath = ostree_tmp_path(repo, obj)
        logging.info('Beginning receive of {} size {} to {}'
                     .format(obj, size, tmppath))
        with open(tmppath, 'wb') as tmpf:
            remaining = size
            while remaining > 0:
                chunk = min(2 ** 20, remaining)
                buf = self.file.read(chunk)
                logging.info('Sending {} bytes for {}'
                             .format(len(buf), obj))
                logging.debug('Buffer contents: {}'.format(buf))
                tmpf.write(buf)
                remaining -= chunk
                logging.info('{} bytes remaining for {}'
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
