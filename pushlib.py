#!/usr/bin/python3

from enum import Enum
from gi.repository import GLib
import struct
import sys

class PushException(Exception):
    pass

class PushCommandType(Enum):
    getrefs = 0
    putrefs = 1
    update = 2
    getobjects = 3
    putobject = 4
    error = 5

class PushCommandStatus(Enum):
    success = 0
    failed = 1

def msg_byteorder(sys_byteorder=None):
    if sys_byteorder is None:
        sys_byteorder = sys.byteorder
    if sys_byteorder not in ['big', 'little']:
        raise PushException('Unrecognized system byteorder %s'
                            % sys_byteorder)
    if sys_byteorder == 'little':
        return b'l'
    else:
        return b'B'

def sys_byteorder(msg_byteorder):
    if msg_byteorder not in [b'B', b'l']:
        raise PushException('Unrecognized message byteorder %s'
                            % msg_byteorder)
    if msg_byteorder == b'l':
        return 'little'
    else:
        return 'big'

def struct_byteorder(sys_byteorder=None):
    if sys_byteorder is None:
        sys_byteorder = sys.byteorder
    if sys_byteorder not in ['big', 'little']:
        raise PushException('Unrecognized system byteorder %s'
                            % sys_byteorder)
    if sys_byteorder == 'little':
        return '<'
    else:
        return '>'

def decode_header(header):
    if len(header) != 4:
        raise Exception('Header is %d bytes, not 4' % len(header))
    order = chr(header[0])
    if order not in ['l', 'B']:
        raise Exception('Unrecognized byte order %s in header' % order)
    version = int(chr(header[1]))
    if version != 1:
        raise Exception('Unsupported header version %d' % version)
    if order == 'l':
        fmt = '<H'
    else:
        fmt = '>H'
    vlen = struct.unpack_from(fmt, header, 2)[0]
    return order, version, vlen

class PushCommand(object):
    def __init__(self, command, args):
        self.command = command
        self.args = args
        self.validate(self.command, self.args)
        self.variant = GLib.Variant('(ua{sv})', (self.command.value,
                                                 self.args))

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
        self.struct_byteorder = struct_byteorder(self.byteorder)
        self.proto_version = b'1'

    def encode_message(self, command):
        if not isinstance(command, PushCommand):
            raise PushException('Command must by GLib.Variant')
        data = command.variant.get_data_as_bytes()
        size = data.get_size()

        # Build the header
        header = self.msg_byteorder + self.proto_version + \
                 struct.pack(self.struct_byteorder + 'H', size)

        return header + data.get_data()

    def write(self, command):
        msg = self.encode_message(command)
        self.file.write(msg)
        self.file.flush()

class PushMessageReader(object):
    def __init__(self, file, byteorder=sys.byteorder):
        self.file = file
        self.byteorder = byteorder
        self.proto_version = 1

    def decode_header(self, header):
        if len(header) != 4:
            raise Exception('Header is %d bytes, not 4' % len(header))
        order = chr(header[0])
        if order not in ['l', 'B']:
            raise Exception('Unrecognized byte order %s in header' % order)
        version = int(chr(header[1]))
        if version != self.proto_version:
            raise Exception('Unsupported header version %d' % version)
        if order == 'l':
            fmt = '<H'
        else:
            fmt = '>H'
        vlen = struct.unpack_from(fmt, header, 2)[0]
        return order, version, vlen

    def decode_message(self, message, size, order):
        if len(message) != size:
            raise Exception('Expected %d bytes, but got %d'
                            %(size, len(message)))
        data = GLib.Bytes.new(message)
        variant = GLib.Variant.new_from_bytes(GLib.VariantType.new('(ua{sv})'),
                                              data, False)
        if (order == 'l' and self.byteorder != 'little') or \
           (order == 'B' and self.byteorder != 'big'):
            variant = GLib.Variant.byteswap(variant)

        return variant

    def read(self):
        header = self.file.read(4)
        if len(header) != 4:
            raise PushException('Expected 4 bytes, but got %d' % len(header))
        order, version, size = self.decode_header(header)
        msg = self.file.read(size)
        if len(msg) != size:
            raise PushException('Did not receive full message')
        command, args = self.decode_message(msg, size, order)

        return PushCommandType(command), args

# class PushCommandGetRefs(PushCommandBase):
#     def __init__(self, branches):
#         command = PushCommandType.getrefs
#         args = {
#             'branches': GLib.Variant('as', branches)
#         }
#         super(PushCommandGetRefs, self).__init__(command, args)

# class PushCommandPutRefs(PushCommandBase):
#     def __init__(self, refs):
#         command = PushCommandType.putrefs
#         args = {
#             'refs': GLib.Variant('a{ss}', refs)
#         }
#         super(PushCommandPutRefs, self).__init__(command, args)

# class PushCommandUpdate(PushCommandBase):
#     def __init__(self, commit, parent, branch):
#         command = PushCommandType.update
#         args = {
#             'commit': GLib.Variant('s', commit),
#             'parent': GLib.Variant('s', parent),
#             'branch': GLib.Variant('s', branch),
#         }
#         super(PushCommandUpdate, self).__init__(command, args)

# class PushCommandGetObjects(PushCommandBase):
#     def __init__(self, objects):
#         command = PushCommandType.getobject
#         args = {
#             'objects': GLib.Variant('as', objects),
#         }
#         super(PushCommandGetObject, self).__init__(command, args)

# class PushCommandPutObject(PushCommandBase):
#     def __init__(self, obj, size):
#         command = PushCommandType.putobject
#         args = {
#             'object': GLib.Variant('s', obj),
#             'size': GLib.Variant('t', size),
#         }
#         super(PushCommandPutObject, self).__init__(command, args)

# class PushCommandError(PushCommandBase):
#     def __init__(self, obj, error, message):
#         command = PushCommandType.error
#         args = {
#             'object': GLib.Variant('s', obj),
#             'error': GLib.Variant('u', error.value),
#             'message': GLib.Variant('s', message),
#         }
#         super(PushCommandError, self).__init__(command, args)
