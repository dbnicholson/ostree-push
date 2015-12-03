Overview
========

There are 2 basic parts to handle the `push` protocol between local and
remote repositories. First, the local and remote need to agree if the
refs in the remote repository can be updated to the commits in the local
repository. Then the commits and all their child objects need to be sent
to the remote repository. Once all the objects are on the remote, the
refs files can be updated.

The protocol is based on Git's upload pack. The message format is based
on D-Bus using GVariant. See [References](#References) for background.

Message Format
==============

As mentioned above, the message format is based on D-Bus, but much
simpler. This has been chosen since GVariant is already in heavy use in
OSTree and can be used for arbitrary message arguments.

Each message consists of a _header_, _body_, and optional _payload_.
Each will be described below. Both the _header_ and _body_ will be
described in the GVariant type format. See [References](#References) for
a link to documentation of this format.

Message Header
--------------

The message _header_ is 5 bytes with the following signature:

```
yyyq (BYTE, BYTE, BYTE, UINT16)
```

The values have the following meanings:

* `BYTE 1` - Endianness flag. ASCII 'l' for little endian or ASCII 'B'
  for big endian. Both header and body are in this endianness.

* `BYTE 2` - Protocol version. A single byte unsigned integer
  representing the protocol version being used by the sender.

* `BYTE 3` - Message type. A single byte unsigned integer representing
  the type of message being sent. Message types are described below.

* `UINT16 1` - Length in bytes of the message body beginning immediately
  after the header.

Message Body
------------

The message _body_ provides arguments for the message type specified in
the header. The body has the following signature:

```
a{sv} (ARRAY of STRING + VARIANT)
```

This represents a dictionary (vardict) in GVariant format. The
serialized length of the body must match that specified in `UINT16 1` of
the header. This means that the maximum body length is 65536. The
endianness of the body must match the flag in `BYTE 1` of the header.

The contents of the dictionary are particular to the message being sent
and will be described below.

Message Types
-------------

A defined set of messages can be specified in `BYTE 3` of the header.
The message types and the arguments required in the body are:

* `INFO (0)` - The repository mode and references.
  * `mode : i` - `INT32` representing the OSTree mode of the repository.
  * `refs : a{ss}` - `ARRAY of STRING + STRING` representing the current
    revision of each reference in the repository. The `STRING` value
    represents a SHA256 checksum in ASCII, and is therefore 64 bytes.

* `UPDATE (1)` - References requested to be updated with the current and
  desired revisions.
  * `<branch> : (ss)` - `(STRUCT of STRING, STRING)` with the current
    revision specified as the 1st string and the desired revision as the
    2nd string. As in the `INFO` command, the revisions represent a
    SHA256 checksum in ASCII. The `<branch>` key is the reference to be
    updated rather than a fixed string.

* `PUTOBJECT (2)` - Send a single OSTree object.
  * `object : s` - `STRING` representing the full object file basename.
  * `size : t` - `UINT64` representing the size of the object file. The
    content of the object file will be sent subsequently in the
    _payload_.

* `STATUS (3)` - Reply to previous message indicating success or failure.
  * `result : b` - `BOOL` where `TRUE` indicates success and `FALSE`
    indicates failure.
  * `message : s` - `STRING` supplying an optional message. This would
    typically be used to provide an error message.

* `DONE (4)` - Finish communication with the remote program. There are
  no arguments for this message.

Message Payload
---------------

An optional message _payload_ immediately follows the body with the
following signature:

```
ay (ARRAY of BYTE)
```

The length of the array must be communicated in the message arguments.
See `PUTOBJECT` above for an example.

Protocol
========

Using the above defined message format, a client and server can
communicate using a simple protocol.

1. When the client first connects to the server, the server immediately
   sends an `INFO` message to the client. This allows the client to
   determine if any server references can be updated.

2. If the client will not update any references, it sends a `DONE`
   message to the server and quits. If it does want to update
   references, it sends an `UPDATE` message to the server.

3. The server analyzes the `UPDATE` request and sends a `STATUS` back to
   the client approving or disapproving the request.

4. If the `STATUS` was `FALSE`, the client sends a `DONE` to the server
   and quits. Otherwise, it sends a `PUTOBJECT` to the server with the
   an OSTree object needed on the server.

5. The server sends a `STATUS` indicating whether the `PUTOBJECT` was
   received correctly or not.

6. The client and server continue to send `PUTOBJECT` and `STATUS` until
   all needed OSTree objects have been sent to the server.

7. After all objects have been sent, the client sends a `DONE` to the
   server and quits.

If step 7 has been reached, then the server has everything it needs for
the push and can update its object store and references.

References
==========

1. Git pack protocol -
   <https://github.com/git/git/blob/master/Documentation/technical/pack-protocol.txt>

2. D-Bus message format -
   <http://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol-messages>

3. GVariant type format -
   <https://developer.gnome.org/glib/stable/glib-GVariantType.html>
