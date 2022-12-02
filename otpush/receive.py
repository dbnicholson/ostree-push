#!/usr/bin/python3

# ostree-receive - Initiate pull from remote
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

"""Initiate pull from ostree remote repo

ostree-receive pulls updates from a remote ostree repository. The
intended use case of ostree-receive is to use it to initiate pulls from
the remote server. This would typically be used to publish commits from
a build host to a master server. ostree-receive offers a few advantages
over a standard "ostree pull".

First, the remote does not need to be pre-configured in the repository
configuration. ostree-receive will use a fake remote and override the
URL and credentials based on the specified URL and its own
configuration.

Second, ostree-receive checks that the refs to be updated are newer than
the refs it has. This prevents accidental downgrades, but it also allows
ostree-receive to be run to pull all refs from the remote and unintended
refs will be ignored.
"""

from . import VERSION

from argparse import ArgumentParser, Namespace, SUPPRESS
from collections import OrderedDict
from configparser import ConfigParser
import dataclasses
import fnmatch
import gi
import logging
import os
from pathlib import Path
import shlex
import subprocess
from tempfile import TemporaryDirectory
import yaml

gi.require_version('OSTree', '1.0')
from gi.repository import GLib, Gio, OSTree  # noqa: E402

logger = logging.getLogger(__name__)


class OTReceiveError(Exception):
    """Errors from ostree-receive"""
    pass


class OTReceiveConfigError(OTReceiveError):
    """Errors from ostree-receive configuration"""
    pass


@dataclasses.dataclass
class OTReceiveRepoConfig:
    """OTReceiveRepo configuration

    The path and url fields are required. See the OTReceiveConfig class for
    details on the remaining optional fields.
    """
    path: Path
    url: str
    gpg_sign: list = dataclasses.field(default_factory=list)
    gpg_homedir: str = None
    gpg_verify: bool = False
    gpg_trustedkeys: str = None
    sign_type: str = 'ed25519'
    sign_keyfiles: list = dataclasses.field(default_factory=list)
    sign_verify: bool = False
    sign_trustedkeyfile: str = None
    update: bool = True
    update_hook: str = None


@dataclasses.dataclass
class OTReceiveConfig:
    """OTReceive configuration

    Configuration can be provided from a file or command line arguments using
    the load method. Config files are YAML mappings with the option names
    below using hypens instead of underscores. By default, the paths
    ~/.config/ostree/ostree-receive.conf and /etc/ostree/ostree-receive.conf
    are read unless the OSTREE_RECEIVE_CONF environment variable is set. That
    can be used to point to a file to be read.

    Supported configuration options:

    root: Specify a repo root directory. When None or '', any repo path is
      allowed and paths are resolved relative to the current working
      directory. This is typically the user's home directory.
    gpg_sign: GPG key IDs for signing received commits and repo metadata.
    gpg_homedir: GnuPG home directory for loading GPG signing keys.
    gpg_verify: Whether to verify received commits with GPG.
    gpg_trustedkeys: GPG keyring for verifying received commits. If None
      or '', keyrings at ~/.config/ostree/ostree-receive-trustedkeys.gpg
      or /etc/ostree/ostree-receive-trustedkeys.gpg will be used. OSTree
      will also use the global trusted keyrings in
      /usr/share/ostree/trusted.gpg.d.
    sign_type: OSTree non-GPG signature type.
    sign_keyfiles: sign_type key files for signing received commits and repo
      metadata.
    sign_verify: Whether to verify received commits with sign_type.
    sign_trustedkeyfile: Keyfile for verifying received commits using
      sign_type. If null or '', the keyfile at
      ~/.config/ostree/ostree-receive-trustedkeyfile.SIGNTYPE or
      /etc/ostree/ostree-receive-trustedkeyfile.SIGNTYPE will be used.
    update: Update the repo metadata after receiving commits.
    update_hook: Program to run after new commits have been made. The program
      will be executed with the environment variable OSTREE_RECEIVE_REPO set
      to the absolute path of the OSTree repository and the environment
      variable OSTREE_RECEIVE_REFS set to the set of refs received separated
      by whitespace.
    repos: Optional per-repository configuration settings. All of the above
      settings except for root can be set and will override the global value.
      The value is a map of repository path to map of settings. The repository
      path can be relative or absolute. If root is specified, relative paths
      are resolved below it.
    log_level: Set the log level. See the logging module for available levels.
    force: Force receiving commits even if nothing changed or the remote
      commits are not newer than the current commits.
    dry_run: Only show what would be done without making any commits.
    """
    root: str = None
    # It would be nice to make this list[str], but that would break
    gpg_sign: list = dataclasses.field(default_factory=list)
    gpg_homedir: str = None
    gpg_verify: bool = False
    gpg_trustedkeys: str = None
    sign_type: str = 'ed25519'
    sign_keyfiles: list = dataclasses.field(default_factory=list)
    sign_verify: bool = False
    sign_trustedkeyfile: str = None
    update: bool = True
    update_hook: str = None
    repos: dict = dataclasses.field(default_factory=dict)
    log_level: str = 'INFO'
    force: bool = False
    dry_run: bool = False

    def __post_init__(self):
        # Validate the instance.
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)

            # Validate the type. None is allowed if the default is None.
            if value is None and field.default is None:
                continue
            elif not isinstance(value, field.type):
                inst_type = type(value)
                raise OTReceiveConfigError(
                    f'{field.name} must be an instance of '
                    f'{field.type}, but found {inst_type}'
                )

    @classmethod
    def load(cls, paths=None, args=None):
        """Create instance from config files and arguments

        If paths is None, default_paths() will be used.
        """
        conf = {}
        fields = {field.name for field in dataclasses.fields(cls)}
        if paths is None:
            paths = cls.default_paths()

        # Load config file options
        for p in paths:
            try:
                path = Path(p).expanduser().resolve()
            except TypeError as err:
                raise OTReceiveConfigError(err) from None
            if not path.exists():
                logger.debug('Skipping missing config file %s', path)
                continue

            logger.debug('Loading config file %s', path)
            with path.open() as f:
                data = yaml.safe_load(f)
            if data is None:
                logger.debug('Ignoring empty config file %s', path)
                continue
            elif not isinstance(data, dict):
                raise OTReceiveConfigError(
                    f'Config file {path} is not a YAML mapping'
                )

            for option, value in data.items():
                if option not in fields:
                    logger.warning(
                        'Unrecognized option %s in config file %s',
                        option, path
                    )
                    continue
                logger.debug(
                    'Setting option %s to %s from %s', option, value, path
                )
                conf[option] = value

        # Load argument options
        if args is not None:
            if not isinstance(args, Namespace):
                raise OTReceiveConfigError(
                    'args is not an argparse.Namespace instance'
                )

            logger.debug('Loading arguments %s', args)
            for arg, value in vars(args).items():
                if arg not in fields:
                    logger.debug('Ignoring argument %s', arg)
                    continue
                logger.debug('Setting option %s to %s from args', arg, value)
                conf[arg] = value

        return cls(**conf)

    @staticmethod
    def default_paths():
        """Return list of default configuration files"""
        env_config = os.getenv('OSTREE_RECEIVE_CONF')
        if env_config:
            return [Path(env_config)]

        config_home = Path(os.getenv('XDG_CONFIG_HOME', '~/.config'))
        return [
            Path('/etc/ostree/ostree-receive.conf'),
            config_home / 'ostree/ostree-receive.conf',
        ]

    def get_repo_config(self, path, url):
        """Get OTReceiveRepoConfig instance for repo path and URL"""
        repo_path = Path(path)
        repo_root = (
            Path(self.root).resolve() if self.root else None
        )

        if repo_root:
            if not repo_path.is_absolute():
                # Join the relative path to the root.
                repo_path = repo_root.joinpath(repo_path)

            # Make sure the path is below the root.
            repo_path = repo_path.resolve()
            try:
                repo_path.relative_to(repo_root)
            except ValueError:
                raise OTReceiveError(f'repo {path} not found') from None

        # Ensure the repository exists.
        if not repo_path.exists():
            raise OTReceiveError(f'repo {path} not found')

        # See if there's a matching path in repos.
        for key, values in self.repos.items():
            config_path = Path(key)
            if repo_root and not config_path.is_absolute():
                config_path = repo_root.joinpath(config_path)
            try:
                matches = repo_path.samefile(config_path)
            except FileNotFoundError:
                matches = False

            if matches:
                logger.debug(f'Applying repos {key} configuration')
                per_repo_config = values
                break
        else:
            per_repo_config = {}

        # Copy all but path and url from the per-repo or the global
        # receive config.
        repo_config_fields = {
            field.name for field in dataclasses.fields(OTReceiveRepoConfig)
        }
        receive_config_fields = {
            field.name for field in dataclasses.fields(self)
        }
        common_fields = repo_config_fields & receive_config_fields
        repo_config_args = {
            field: per_repo_config.get(field, getattr(self, field))
            for field in common_fields
        }
        repo_config_args['path'] = repo_path
        repo_config_args['url'] = url

        return OTReceiveRepoConfig(**repo_config_args)


class OTReceiveRepo(OSTree.Repo):
    """OSTree repository receiving pushed commits

    An OTReceiveRepoConfig instance is required.
    """
    # The fake remote name
    REMOTE_NAME = '_receive'

    # Generated ref patterns to be excluded when pulling everything
    EXCLUDED_REF_PATTERNS = (
        'appstream/*',
        'appstream2/*',
        OSTree.REPO_METADATA_REF,
    )

    def __init__(self, config):
        self.config = config
        self.remotes_dir = None

        if not isinstance(self.config, OTReceiveRepoConfig):
            raise OTReceiveError(
                'config is not an OTReceiveRepoConfig instance'
            )

        # Ensure the repository exists.
        if not self.path.exists():
            raise OTReceiveError(f'repo {self.path} not found')

        logger.debug('Using repo path %s', self.path)

        # Create a temporary remote config file. Just an empty URL is
        # needed and the rest of the parameters will be supplied in the
        # pull options.
        self.remotes_dir = TemporaryDirectory(prefix='ostree-receive-')
        remote_config_path = os.path.join(self.remotes_dir.name,
                                          f'{self.REMOTE_NAME}.conf')
        remote_config = ConfigParser()
        remote_section = f'remote "{self.REMOTE_NAME}"'
        remote_config.add_section(remote_section)
        remote_config[remote_section]['url'] = self.url
        if self.config.gpg_verify:
            trustedkeys = self._get_gpg_trustedkeys()
            if trustedkeys:
                remote_config[remote_section]['gpgkeypath'] = trustedkeys
            remote_config[remote_section]['gpg-verify'] = 'true'
        else:
            remote_config[remote_section]['gpg-verify'] = 'false'
        remote_config[remote_section]['gpg-verify-summary'] = 'false'
        if self.config.sign_verify:
            verification_config = f'verification-{self.config.sign_type}-file'
            trustedkeyfile = self._get_sign_trustedkeyfile()
            if trustedkeyfile:
                remote_config[remote_section][verification_config] = \
                    trustedkeyfile
            remote_config[remote_section]['sign-verify'] = 'true'
            remote_config[remote_section]['sign-verify-summary'] = 'false'
        with open(remote_config_path, 'w') as f:
            remote_config.write(f, space_around_delimiters=False)

        repo_file = Gio.File.new_for_path(os.fspath(self.path))
        super().__init__(path=repo_file,
                         remotes_config_dir=self.remotes_dir.name)
        self.open()

    @property
    def path(self):
        return self.config.path

    @property
    def url(self):
        return self.config.url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.cleanup()

    def cleanup(self):
        """Cleanup instance temporary directory

        This will be called automatically when the instance is deleted
        or the context exits.
        """
        if self.remotes_dir:
            self.remotes_dir.cleanup()
            self.remotes_dir = None

    def _get_gpg_trustedkeys(self):
        """Get the GPG trusted keyring for verification"""
        if self.config.gpg_trustedkeys:
            if not os.path.exists(self.config.gpg_trustedkeys):
                raise OTReceiveConfigError(
                    f'gpg_trustedkeys keyring "{self.config.gpg_trustedkeys}" '
                    'does not exist',
                )
            path = os.path.realpath(self.config.gpg_trustedkeys)
            logger.debug('Using GPG trusted keyring %s', path)
            return path
        else:
            config_home = Path(os.getenv('XDG_CONFIG_HOME', '~/.config'))
            default_paths = [
                Path('/etc/ostree/ostree-receive-trustedkeys.gpg'),
                config_home / 'ostree/ostree-receive-trustedkeys.gpg'
            ]

            for path in default_paths:
                path = path.expanduser().resolve()
                if path.exists():
                    logger.debug('Using default GPG trusted keyring %s', path)
                    return os.fspath(path)

            return None

    def _get_sign_trustedkeyfile(self):
        """Get the GPG trusted keyring for verification"""
        if self.config.sign_trustedkeyfile:
            if not os.path.exists(self.config.sign_trustedkeyfile):
                self._report_missing_keyfile(self.config.sign_trustedkeyfile,
                                             from_config='sign_trustedkeyfile')
            path = os.path.realpath(self.config.sign_trustedkeyfile)
            logger.debug('Using trusted keyfile %s', path)
            return path
        else:
            config_home = Path(os.getenv('XDG_CONFIG_HOME', '~/.config'))
            basename = f'ostree-receive-trustedkeyfile.{self.config.sign_type}'
            default_paths = [
                Path(f'/etc/ostree/{basename}'),
                config_home / f'ostree/{basename}'
            ]

            for path in default_paths:
                path = path.expanduser().resolve()
                if path.exists():
                    logger.debug('Using default trusted keyfile %s', path)
                    return os.fspath(path)

            return None

    def _read_keyfile_keys(self, keyfile, *, from_config):
        try:
            with open(keyfile) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    yield line
        except FileNotFoundError:
            self._report_missing_keyfile(keyfile, from_config=from_config)

    def _report_missing_keyfile(self, keyfile, *, from_config):
        raise OTReceiveConfigError(
            f'{from_config} keyfile "{keyfile}" does not exist'
        )

    def _get_commit_timestamp(self, rev):
        """Get the timestamp of a commit"""
        _, commit, _ = self.load_commit(rev)
        return OSTree.commit_get_timestamp(commit)

    def _pull_commits(self, commits):
        """Pull commits from repo

        The caller is responsible for managing the repository transaction.
        """
        opts = GLib.Variant('a{sv}', {
            'refs': GLib.Variant('as', commits),
            'depth': GLib.Variant('i', 0),
            'inherit-transaction': GLib.Variant('b', True),
            # Pull objects directly instead of processing deltas since
            # it's an error to pull deltas into an archive repo.
            'disable-static-deltas': GLib.Variant('b', True),
        })
        progress = OSTree.AsyncProgress.new()
        progress.connect('changed',
                         OSTree.Repo.pull_default_console_progress_changed,
                         None)
        try:
            self.pull_with_options(self.REMOTE_NAME, opts, progress)
        finally:
            progress.finish()

    def copy_commit(self, rev, ref):
        _, src_variant, src_state = self.load_commit(rev)
        if src_state != OSTree.RepoCommitState.NORMAL:
            raise OTReceiveError(f'Cannot copy irregular commit {rev}')

        _, src_root, _ = self.read_commit(rev)

        # Make a copy of the commit metadata to update. Like flatpak
        # build-commit-from, the detached metadata is not copied since
        # the only known usage is for GPG signatures, which would become
        # invalid.
        commit_metadata = GLib.VariantDict.new(src_variant.get_child_value(0))
        commit_metadata.insert_value(OSTree.COMMIT_META_KEY_REF_BINDING,
                                     GLib.Variant('as', [ref]))
        collection_id = self.get_collection_id()
        if collection_id is not None:
            commit_metadata.insert_value(
                OSTree.COMMIT_META_KEY_COLLECTION_BINDING,
                GLib.Variant('s', collection_id))
        else:
            commit_metadata.remove(OSTree.COMMIT_META_KEY_COLLECTION_BINDING)

        # Add flatpak specific metadata
        if self._is_flatpak_ref(ref):
            # Deprecated in favor of ostree.ref-binding, but add it for
            # older flatpak clients
            commit_metadata.insert_value('xa.ref', GLib.Variant('s', ref))

            # Nothing really uses this, but flatpak build-commit-from
            # adds it
            commit_metadata.insert_value('xa.from_commit',
                                         GLib.Variant('s', rev))

        # Convert from GVariantDict to GVariant vardict
        commit_metadata = commit_metadata.end()

        # Copy other commit data from source commit
        commit_subject = src_variant.get_child_value(3).get_string()
        commit_body = src_variant.get_child_value(4).get_string()

        # If the dest ref exists, use the current commit as the parent.
        # Prior to ostree 2019.2, the GIR for
        # OSTree.RepoResolveRevExtFlags was represented as an
        # enumeration and the longer name is required.
        try:
            resolve_flags = OSTree.RepoResolveRevExtFlags.NONE
        except AttributeError:
            resolve_flags = \
                OSTree.RepoResolveRevExtFlags.REPO_RESOLVE_REV_EXT_NONE
        _, parent = self.resolve_rev_ext(ref, allow_noent=True,
                                         flags=resolve_flags)

        # Keep the source commit's timestamp
        commit_time = OSTree.commit_get_timestamp(src_variant)

        # Make the new commit
        mtree = OSTree.MutableTree.new()
        self.write_directory_to_mtree(src_root, mtree, None)
        _, commit_root = self.write_mtree(mtree)
        _, commit_checksum = self.write_commit_with_time(parent,
                                                         commit_subject,
                                                         commit_body,
                                                         commit_metadata,
                                                         commit_root,
                                                         commit_time)

        for key in self.config.gpg_sign:
            logger.debug('Signing commit %s with GPG key %s',
                         commit_checksum, key)
            self.sign_commit(commit_checksum, key,
                             self.config.gpg_homedir)

        if self.config.sign_keyfiles:
            sign = OSTree.Sign.get_by_name(self.config.sign_type)
            for keyfile in self.config.sign_keyfiles:
                logging.debug('Signing commit %s with %s keys from %s',
                              commit_checksum, sign.get_name(), keyfile)

                for key in self._read_keyfile_keys(
                        keyfile,
                        from_config='sign_keyfiles'):
                    sign.set_sk(GLib.Variant('s', key))
                    sign.commit(self, commit_checksum, None)

        # Update the ref
        self.transaction_set_refspec(ref, commit_checksum)

        return commit_checksum

    def _get_local_refs(self):
        flags = OSTree.RepoListRefsExtFlags.EXCLUDE_REMOTES
        try:
            # EXCLUDE_MIRRORS only available since ostree 2019.2
            flags |= OSTree.RepoListRefsExtFlags.EXCLUDE_MIRRORS
        except AttributeError:
            pass
        _, refs = self.list_refs_ext(None, flags)
        return refs

    @staticmethod
    def _is_flatpak_ref(ref):
        return ref.startswith('app/') or ref.startswith('runtime/')

    def _is_flatpak_repo(self):
        refs = self._get_local_refs()
        return any(filter(self._is_flatpak_ref, refs))

    def update_repo_metadata(self):
        sign_opts = []
        if self.config.gpg_sign:
            sign_opts += [f'--gpg-sign={key}' for key in self.config.gpg_sign]
            if self.config.gpg_homedir:
                sign_opts.append(f'--gpg-homedir={self.config.gpg_homedir}')

        # Since --sign= keys are passed directly on the CLI, make a separate
        # copy of the options list with the key "censored", so that the command
        # line can be safely printed.
        safe_sign_opts = sign_opts[:]
        if self.config.sign_keyfiles:
            for opts in sign_opts, safe_sign_opts:
                opts.append(f'--sign-type={self.config.sign_type}')
            for keyfile in self.config.sign_keyfiles:
                for i, key in enumerate(self._read_keyfile_keys(
                                            keyfile,
                                            from_config='sign_keyfiles'),
                                        start=1):
                    sign_opts.append(f'--sign={key}')
                    safe_sign_opts.append(f'--sign=<key #{i} from {keyfile}>')

        if self._is_flatpak_repo():
            cmd_prefix = [
                'flatpak',
                'build-update-repo',
                str(self.path),
            ]
        else:
            cmd_prefix = [
                'ostree',
                f'--repo={self.path}',
                'summary',
                '--update',
            ]
        logger.info('Updating repo metadata with %s',
                    ' '.join(cmd_prefix + safe_sign_opts))
        subprocess.check_call(cmd_prefix + sign_opts)

    def update_repo_hook(self, refs):
        """Run the configured update_hook

        The program will be executed with the environment variable
        OSTREE_RECEIVE_REPO set to the absolute path of the OSTree repository
        and the environment variable OSTREE_RECEIVE_REFS set to the set of
        refs received separated by whitespace.
        """
        if not self.config.update_hook:
            raise OTReceiveConfigError('update_hook not set in configuration')

        cmd = shlex.split(self.config.update_hook)
        env = os.environ.copy()
        env['OSTREE_RECEIVE_REPO'] = os.fspath(self.path.absolute())
        env['OSTREE_RECEIVE_REFS'] = ' '.join(refs)

        logger.info('Updating repo with %s', self.config.update_hook)
        logger.debug('OSTREE_RECEIVE_REPO=%s', env['OSTREE_RECEIVE_REPO'])
        logger.debug('OSTREE_RECEIVE_REFS=%s', env['OSTREE_RECEIVE_REFS'])
        subprocess.check_call(cmd, env=env)

    def receive(self, refs, force=False, dry_run=False):
        # See what revisions we're pulling.
        _, remote_refs = self.remote_list_refs(self.REMOTE_NAME)
        if len(refs) == 0:
            # Pull all the remote refs
            refs = remote_refs.keys()

        # Strip duplicate and generated refs
        refs = set(refs)
        for pattern in self.EXCLUDED_REF_PATTERNS:
            refs -= set(fnmatch.filter(refs, pattern))
        wanted_refs = sorted(refs)

        logger.info('Remote commits:')
        for ref in wanted_refs:
            logger.info(' %s %s', ref, remote_refs.get(ref))

        # See what commits we have on these refs.
        current_refs = self._get_local_refs()
        logger.info('Current commits:')
        for ref in wanted_refs:
            logger.info(' %s %s', ref, current_refs.get(ref))

        # See what refs need to be pulled, erroring if the ref doesn't
        # exist on the remote
        refs_to_pull = OrderedDict()
        for ref in wanted_refs:
            current_rev = current_refs.get(ref)
            remote_rev = remote_refs.get(ref)

            if remote_rev is None:
                raise OTReceiveError(
                    f'Could not find ref {ref} in summary file')

            if force or remote_rev != current_rev:
                logger.debug('Pulling %s', ref)
                refs_to_pull[ref] = remote_rev

        if len(refs_to_pull) == 0:
            logger.info('No refs need updating')
            return set()

        # Start a transaction for the entire operation
        self.prepare_transaction()
        try:
            # Pull the refs by commit
            commits_to_pull = list(set(refs_to_pull.values()))
            self._pull_commits(commits_to_pull)

            # See what refs should be merged, skipping older commits and
            # commits on the same root
            #
            # FIXME: Newer ostree puts the commit timestamps in the
            # summary file in the ostree.commit.timestamp key. When
            # that's deployed and used everywhere we care about, switch
            # to doing this in the pre-pull checks.
            refs_to_merge = OrderedDict()
            for ref, remote_rev in refs_to_pull.items():
                if ref not in current_refs:
                    refs_to_merge[ref] = remote_rev
                else:
                    current_rev = current_refs[ref]
                    current_timestamp = self._get_commit_timestamp(current_rev)
                    remote_timestamp = self._get_commit_timestamp(remote_rev)
                    _, current_root, _ = self.read_commit(current_rev)
                    _, remote_root, _ = self.read_commit(remote_rev)

                    if remote_timestamp > current_timestamp and \
                       not current_root.equal(remote_root):
                        refs_to_merge[ref] = remote_rev
                    else:
                        if remote_timestamp <= current_timestamp:
                            logger.warning(
                                'received %s commit %s is not newer than '
                                'current %s commit %s',
                                ref, remote_rev, ref, current_rev
                            )
                        if current_root.equal(remote_root):
                            logger.warning(
                                'received %s commit %s has the same content '
                                'as current %s commit %s',
                                ref, remote_rev, ref, current_rev
                            )
                        if force:
                            logger.info('Forcing merge of ref %s', ref)
                            refs_to_merge[ref] = remote_rev

            if len(refs_to_merge) == 0:
                logger.info('No refs need updating')
                self.abort_transaction()
                return set()

            # For a dry run, exit now before creating the refs
            if dry_run:
                self.abort_transaction()
                return refs_to_merge.keys()

            # Copy the pulled commits to the local ref so they get the
            # correct collection and ref bindings
            for ref, rev in refs_to_merge.items():
                new_rev = self.copy_commit(rev, ref)
                logger.debug('Set %s ref to %s', ref, new_rev)

            # All done, commit the changes
            self.commit_transaction()
        except:  # noqa: E722
            self.abort_transaction()
            raise

        # Finally, regenerate the summary and metadata
        if self.config.update:
            if self.config.update_hook:
                self.update_repo_hook(refs_to_merge.keys())
            else:
                self.update_repo_metadata()

        return refs_to_merge.keys()


class OTReceiver:
    """Pushed commit receiver

    An OTReceiveConfig instance can be provided to configure the receiver.
    """
    def __init__(self, config=None):
        self.config = config or OTReceiveConfig()

        if not isinstance(self.config, OTReceiveConfig):
            raise OTReceiveError(
                'config is not an OTReceiveConfig instance'
            )

    def receive(self, path, url, refs):
        """Receive pushed commits

        Creates an OTReceiveRepo at path and receives commits on refs
        from url.
        """
        repo_config = self.config.get_repo_config(path, url)
        with OTReceiveRepo(repo_config) as repo:
            return repo.receive(refs, self.config.force, self.config.dry_run)


class OTReceiveArgParser(ArgumentParser):
    """ArgumentParse for ostree-receive"""
    def __init__(self):
        config_paths = ' or '.join(map(str, OTReceiveConfig.default_paths()))
        super().__init__(
            description='Pull from a remote repo to a dev repo',
            epilog=(
                'Many options can also be set in a config file '
                f'({config_paths}). The config file uses YAML syntax and '
                'must represent a YAML mapping.'
            ),

            # The global default is set to SUPPRESS so that options
            # don't override config defaults.
            argument_default=SUPPRESS,
        )
        self.add_argument('repo', metavar='REPO',
                          help='repository name to use')
        self.add_argument('url', metavar='URL', help='remote repository URL')
        self.add_argument('refs', metavar='REF', nargs='*', default=None,
                          help='ostree refs to pull, all if none specified')
        self.add_argument('--no-update', dest='update', action='store_false',
                          help="""don't update repo metadata""")
        self.add_argument('-n', '--dry-run', action='store_true',
                          help='only show what would be done')
        self.add_argument('-f', '--force', action='store_true',
                          help=('force pull even if nothing changed or '
                                'remote commits are not newer'))
        self.add_argument('-q', '--quiet', dest='log_level',
                          action='store_const', const='WARNING',
                          help='disable most messages')
        self.add_argument('-v', '--verbose', dest='log_level',
                          action='store_const', const='DEBUG',
                          help='enable verbose messages')
        self.add_argument('--version', action='version',
                          version=f'%(prog)s {VERSION}')


def main():
    aparser = OTReceiveArgParser()
    args = aparser.parse_args()
    config = OTReceiveConfig.load(args=args)

    logging.basicConfig(level=config.log_level)

    receiver = OTReceiver(config)
    receiver.receive(args.repo, args.url, args.refs)


if __name__ == '__main__':
    main()
