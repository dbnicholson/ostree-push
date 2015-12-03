ostree-push
===========

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
be pushed over `ssh` to avoid these issues. Eventually, the protocol
could be used to offer pulls over `ssh`, which would allow working with
remotes over something other than http.

Operation
=========

When `ostree-push` is started, it opens a channel to the specified
remote host with `ssh`. On the remote host, `ostree-receive` is spawned.
`ostree-push` and `ostree-receive` then communicate via a custom
protocol to publish the commits. After determining what objects are
needed in the remote repository, `ostree-push` sends the objects one by
one to `ostree-receive`. After receiving all objects, `ostree-receive`
moves them from a temporary staging directory to the object store and
updates the refs files.

The full protocol and message format are described in `protocol.md`.
