# ostree-push

## Background

`ostree-push` uses `ssh` to push commits from a local OSTree repo to a
remote OSTree repo. This is to fill a gap where currently you can only
pull commits in core ostree. To publish commits to a remote repository,
you either have to `pull` from the local repo to the remote repo or use
an out of band mechanism like `rsync`.

Both approaches have significant limitations. To pull over the network,
only http is supported. So, in addition to having to login on the remote
machine and run `ostree pull`, the local repository needs to be served
over http. This means your build machine needs to be an http server with
appropriate configuration in addition to simply making commits. This
pushes the builds to be done on the public repository server, which
prevents reasonable separation of duties and makes multiarch
repositories impossible.

Using `rsync` for publishing has some major benefits since only updated
objects are published. However, it has no concept of the OSTree object
store or refs structures. There are a few problems deriving from this
issue. First, objects are published in sort order, but this means that
objects can be published before their children. In the most extreme
case, a commit object could be published before it's complete. The
remote repo would assume this commit object was valid even though some
children might be missing. Second, the refs might get updated before the
commit objects are in place. If a client pulls while `rsync` is
publishing, it may attempt to pull an incomplete or entirely missing
commit. Finally, `rsync` will push the objects directly into the store
rather than using a staging directory like `pull` or `commit` do. If
`rsync` is interrupted, it could leave partial objects in the store.

`ostree-push` tries to offer functionality like `git` where commits can
be pushed over `ssh` to avoid these issues.

## Operation

When `ostree-push` is started, it first starts a local HTTP server
providing the contents of the local ostree repo. It then connects to the
remote host with `ssh` and tunnels the HTTP server port through the SSH
connection. Finally, it runs `ostree-receive` on the remote host with
the URL of the tunneled HTTP server. `ostree-receive` then creates a
temporary remote using this URL and pulls the desired refs from it.

In essence, `ostree-push` and `ostree-receive` coordinate to pull from
the local repo to a remote repo while avoiding the limitations described
above. Namely, no HTTP server needs to be running and no port needs to
be exposed on the local host. Both resources are created temporarily and
only exposed to the remote host through the secure SSH connection.

## Installation

Use `pip` to install the `otpush` package and the `ostree-push` and
`ostree-receive` scripts. From a git checkout, run:

```
pip install .
```

If `ostree-receive` is not in a default `PATH` location, it may not be
located when run in the environment spawned by the SSH server. As a
workaround, make a symbolic link in a standard location:

```
sudo ln -s /path/to/ostree-receive /usr/bin/ostree-receive
```

In order to restrict SSH usage to only running `ostree-receive`, the
`ostree-receive-shell` script can be used as a login shell. This way
someone with SSH access to the remote machine cannot run arbitrary
commands as the user owning the repositories. To use it, set the login
shell of the repo owner to `ostree-receive-shell`:

```
sudo chsh -s /path/to/ostree-receive-shell <user>
```

`ostree-receive-shell` will also append the directory it's installed in
to `PATH` to allow `ostree-receive` to be found in non-standard
locations. In that scenario, the symbolic link to `ostree-receive`
described above is not needed.

Both `ostree-push` and `ostree-receive` require the OSTree GObject
Introspection bindings. Typically these would be installed from the host
distro. On Debian systems the package is `gir1.2-ostree-1.0` while on
RedHat systems they are in the `ostree-libs` package.

`ostree-push` relies on the connection sharing and port forwarding
features of OpenSSH and is unlikely to work with another SSH client.
Similarly, `ostree-receive` has only be tested with the OpenSSH server,
but it might work correctly with other SSH servers.

## Configuration

`ostree-receive` can be configured from YAML formatted files. It will
load `~/.config/ostree/ostree-receive.conf` and
`/etc/ostree/ostree-receive.conf` or a file specified in the
`OSTREE_RECEIVE_CONF` environment variable. See the example
[`ostree-receive.conf`](ostree-receive.conf) file for available options.

## Testing

A test suite is provided using [pytest][pytest]. Most of the time simply
running `pytest` from a git checkout will run it correctly. [tox][tox]
can also be used to automate running the test suite in a prepared Python
environment.

In addition to the `ostree-push` dependencies, many of the tests depend
on using OpenSSH `sshd` locally. On both Debian and RedHat systems this
is available in the `openssh-server` package.

[pytest]: https://docs.pytest.org/en/stable/
[tox]: https://tox.readthedocs.io/en/stable/
