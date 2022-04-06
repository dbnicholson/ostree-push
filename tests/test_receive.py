from otpush import receive

import argparse
import dataclasses
import gi
from gi.repository import GLib, Gio
import json
import logging
import os
from pathlib import Path
import pytest
import time
import yaml

from .util import (
    PGP_PUB_KEYRING,
    PGP_KEY_ID,
    TESTSDIR,
    get_summary_variant,
    local_refs,
    needs_flatpak,
    needs_gpg,
    needs_ostree,
    oneshot_transaction,
    random_commit,
    wipe_repo,
    TmpRepo,
)

gi.require_version('OSTree', '1.0')
from gi.repository import OSTree  # noqa: E402

logger = logging.getLogger(__name__)


class TestReceiveRepo:
    def test_cleanup(self, dest_repo):
        url = 'http://example.com'
        repo = receive.OTReceiveRepo(dest_repo.path, url)
        remotes_dir = Path(repo.remotes_dir.name)
        assert remotes_dir.exists()
        del repo
        assert not remotes_dir.exists()

        with receive.OTReceiveRepo(dest_repo.path, url) as repo:
            remotes_dir = Path(repo.remotes_dir.name)
            assert remotes_dir.exists()
        assert not remotes_dir.exists()

    def test_get_commit_timestamp(self, tmp_files_path, receive_repo):
        with pytest.raises(GLib.Error) as excinfo:
            receive_repo._get_commit_timestamp('missing')
        assert excinfo.value.matches(Gio.io_error_quark(),
                                     Gio.IOErrorEnum.NOT_FOUND)

        commit = random_commit(receive_repo, tmp_files_path, 'someref',
                               timestamp=0)
        timestamp = receive_repo._get_commit_timestamp(commit)
        assert timestamp == 0

        now = int(time.time())
        commit = random_commit(receive_repo, tmp_files_path, 'someref',
                               timestamp=now)
        timestamp = receive_repo._get_commit_timestamp(commit)
        assert timestamp == now

        now = int(time.time())
        commit = random_commit(receive_repo, tmp_files_path, 'someref')
        timestamp = receive_repo._get_commit_timestamp(commit)
        assert timestamp >= now

    def test_is_flatpak_repo(self, tmp_files_path, receive_repo):
        assert not receive_repo._is_flatpak_repo()

        random_commit(receive_repo, tmp_files_path, 'someref')
        assert not receive_repo._is_flatpak_repo()

        random_commit(receive_repo, tmp_files_path,
                      'app/com.example.App/x86_64/stable')
        assert receive_repo._is_flatpak_repo()

    def test_pull_commits(self, tmp_files_path, receive_repo, source_repo,
                          source_server):
        rev1 = random_commit(source_repo, tmp_files_path, 'ref1')
        rev2 = random_commit(source_repo, tmp_files_path, 'ref2')

        _, remote_refs = receive_repo.remote_list_refs(
            receive_repo.REMOTE_NAME)
        assert remote_refs == {'ref1': rev1, 'ref2': rev2}

        # Pull by single ref
        with oneshot_transaction(receive_repo):
            receive_repo._pull_commits(['ref1'])
        _, refs = receive_repo.list_refs(None)
        assert refs == {'_receive:ref1': rev1}
        _, _, state = receive_repo.load_commit(rev1)
        assert state == OSTree.RepoCommitState.NORMAL
        wipe_repo(receive_repo)

        # Pull by multiple refs
        with oneshot_transaction(receive_repo):
            receive_repo._pull_commits(['ref1', 'ref2'])
        _, refs = receive_repo.list_refs(None)
        assert refs == {'_receive:ref1': rev1, '_receive:ref2': rev2}
        _, _, state = receive_repo.load_commit(rev1)
        assert state == OSTree.RepoCommitState.NORMAL
        _, _, state = receive_repo.load_commit(rev2)
        assert state == OSTree.RepoCommitState.NORMAL
        wipe_repo(receive_repo)

        # Pull by single rev
        with oneshot_transaction(receive_repo):
            receive_repo._pull_commits([rev1])
        _, refs = receive_repo.list_refs(None)
        assert refs == {}
        _, _, state = receive_repo.load_commit(rev1)
        assert state == OSTree.RepoCommitState.NORMAL
        wipe_repo(receive_repo)

        # Pull by multiple revs
        with oneshot_transaction(receive_repo):
            receive_repo._pull_commits([rev1, rev2])
        _, refs = receive_repo.list_refs(None)
        assert refs == {}
        _, _, state = receive_repo.load_commit(rev1)
        assert state == OSTree.RepoCommitState.NORMAL
        _, _, state = receive_repo.load_commit(rev2)
        assert state == OSTree.RepoCommitState.NORMAL
        wipe_repo(receive_repo)

        # Pull by missing ref
        with pytest.raises(GLib.Error) as excinfo:
            with oneshot_transaction(receive_repo):
                receive_repo._pull_commits(['missing'])
        assert excinfo.value.matches(Gio.io_error_quark(),
                                     Gio.IOErrorEnum.FAILED)
        wipe_repo(receive_repo)

    def test_copy_commit(self, tmp_files_path, receive_repo):
        # Non-flatpak ref
        src = random_commit(receive_repo, tmp_files_path, 'src')
        with oneshot_transaction(receive_repo):
            dst = receive_repo.copy_commit(src, 'dst')
        assert src != dst
        _, src_commit, _ = receive_repo.load_commit(src)
        _, dst_commit, dst_state = receive_repo.load_commit(dst)
        assert dst_state == OSTree.RepoCommitState.NORMAL
        assert OSTree.commit_get_parent(dst_commit) is None
        assert OSTree.commit_get_content_checksum(src_commit) == \
            OSTree.commit_get_content_checksum(dst_commit)
        assert OSTree.commit_get_timestamp(src_commit) == \
            OSTree.commit_get_timestamp(dst_commit)
        expected_metadata = {
            OSTree.COMMIT_META_KEY_REF_BINDING: ['dst'],
            OSTree.COMMIT_META_KEY_COLLECTION_BINDING: 'com.example.Test',
        }
        dst_metadata = dst_commit.get_child_value(0).unpack()
        assert dst_metadata == expected_metadata

        # Make another commit and check that the previous commit is used
        # as the parent
        expected_parent = dst
        src = random_commit(receive_repo, tmp_files_path, 'src')
        with oneshot_transaction(receive_repo):
            dst = receive_repo.copy_commit(src, 'dst')
        assert src != dst
        _, src_commit, _ = receive_repo.load_commit(src)
        _, dst_commit, dst_state = receive_repo.load_commit(dst)
        assert dst_state == OSTree.RepoCommitState.NORMAL
        assert OSTree.commit_get_parent(dst_commit) == expected_parent
        assert OSTree.commit_get_content_checksum(src_commit) == \
            OSTree.commit_get_content_checksum(dst_commit)
        assert OSTree.commit_get_timestamp(src_commit) == \
            OSTree.commit_get_timestamp(dst_commit)
        dst_metadata = dst_commit.get_child_value(0).unpack()
        assert dst_metadata == expected_metadata

        # Check that additional metadata is copied
        extra_metadata = {'foo': GLib.Variant('s', 'bar')}
        expected_metadata['foo'] = 'bar'
        src = random_commit(receive_repo, tmp_files_path, 'src',
                            extra_metadata=extra_metadata)
        with oneshot_transaction(receive_repo):
            dst = receive_repo.copy_commit(src, 'dst')
        assert src != dst
        _, dst_commit, _ = receive_repo.load_commit(dst)
        dst_metadata = dst_commit.get_child_value(0).unpack()
        assert dst_metadata == expected_metadata

        # Flatpak metadata
        ref = 'app/com.example.Foo/x86_64/stable'
        src = random_commit(receive_repo, tmp_files_path, 'src')
        with oneshot_transaction(receive_repo):
            dst = receive_repo.copy_commit(src, ref)
        assert src != dst
        _, dst_commit, _ = receive_repo.load_commit(dst)
        expected_metadata = {
            OSTree.COMMIT_META_KEY_REF_BINDING: [ref],
            OSTree.COMMIT_META_KEY_COLLECTION_BINDING: 'com.example.Test',
            'xa.ref': ref,
            'xa.from_commit': src,
        }
        dst_metadata = dst_commit.get_child_value(0).unpack()
        assert dst_metadata == expected_metadata

        # Copying partial commit should fail
        receive_repo.mark_commit_partial(src, True)
        with pytest.raises(receive.OTReceiveError) as excinfo:
            with oneshot_transaction(receive_repo):
                receive_repo.copy_commit(src, ref)
        assert str(excinfo.value) == f'Cannot copy irregular commit {src}'

    def test_receive(self, tmp_files_path, receive_repo, source_repo,
                     source_server):
        random_commit(source_repo, tmp_files_path, 'ref1')
        random_commit(source_repo, tmp_files_path, 'ref2')

        with pytest.raises(receive.OTReceiveError) as excinfo:
            receive_repo.receive(['missing'])
        assert str(excinfo.value) == \
            'Could not find ref missing in summary file'

        merged = receive_repo.receive(['ref1'])
        assert merged == {'ref1'}
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1'}

    @needs_ostree
    def test_receive_update(self, tmp_files_path, receive_repo, source_repo,
                            source_server):
        receive_repo.config.update = True

        random_commit(source_repo, tmp_files_path, 'ref1')

        merged = receive_repo.receive(['ref1'])
        assert merged == {'ref1'}
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ostree-metadata', 'ref1'}
        summary = Path(receive_repo.path) / 'summary'
        assert summary.exists()

    def test_receive_update_hook(self, tmp_files_path, receive_repo,
                                 source_repo, source_server):
        dumpenv = os.path.join(TESTSDIR, 'dumpenv')
        receive_repo.config.update = True
        receive_repo.config.update_hook = dumpenv

        random_commit(source_repo, tmp_files_path, 'ref1')

        merged = receive_repo.receive(['ref1'])
        assert merged == {'ref1'}
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1'}
        summary = Path(receive_repo.path) / 'summary'
        assert not summary.exists()

    @needs_gpg
    def test_receive_gpg_sign(self, tmp_files_path, receive_repo, source_repo,
                              source_server, gpg_homedir, monkeypatch):
        random_commit(source_repo, tmp_files_path, 'ref1')

        # Specifying a bogus GPG key should fail
        receive_repo.config.gpg_sign = ['DEADBEEF']
        receive_repo.config.gpg_homedir = str(gpg_homedir)
        with pytest.raises(GLib.Error) as excinfo:
            receive_repo.receive(['ref1'])
        assert excinfo.value.matches(Gio.io_error_quark(),
                                     Gio.IOErrorEnum.FAILED)

        # Specifying both key and homedir
        receive_repo.config.gpg_sign = [PGP_KEY_ID]
        receive_repo.config.gpg_homedir = str(gpg_homedir)
        merged = receive_repo.receive(['ref1'])
        assert merged == {'ref1'}
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1'}

        # Validate the signature and make sure it was signed by the correct
        # key
        commit = refs['ref1']
        keyring_file = Gio.File.new_for_path(str(PGP_PUB_KEYRING))
        result = receive_repo.verify_commit_ext(commit, None, keyring_file)
        OSTree.GpgVerifyResult.require_valid_signature(result)
        assert OSTree.GpgVerifyResult.count_all(result) == 1
        sig = OSTree.GpgVerifyResult.get_all(result, 0).unpack()
        key_id = sig[OSTree.GpgSignatureAttr.FINGERPRINT]
        assert key_id == PGP_KEY_ID

        # Using the default homedir via GNUPGHOME
        monkeypatch.setenv('GNUPGHOME', str(gpg_homedir))
        receive_repo.config.gpg_sign = [PGP_KEY_ID]
        receive_repo.config.gpg_homedir = None
        wipe_repo(receive_repo)
        merged = receive_repo.receive(['ref1'])
        assert merged == {'ref1'}
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1'}

    @needs_ostree
    def test_update_repo_metadata(self, tmp_files_path, receive_repo):
        summary = Path(receive_repo.path) / 'summary'

        receive_repo.update_repo_metadata()
        assert summary.exists()
        summary_refs, summary_metadata = get_summary_variant(summary)
        ref_names = {ref[0] for ref in summary_refs}
        assert ref_names == {'ostree-metadata'}
        assert 'xa.cache' not in summary_metadata

        random_commit(receive_repo, tmp_files_path, 'someref')
        receive_repo.update_repo_metadata()
        assert summary.exists()
        summary_refs, summary_metadata = get_summary_variant(summary)
        ref_names = {ref[0] for ref in summary_refs}
        assert ref_names == {'ostree-metadata', 'someref'}
        assert 'xa.cache' not in summary_metadata

    @needs_flatpak
    def test_update_repo_metadata_flatpak(self, tmp_files_path, receive_repo):
        summary = Path(receive_repo.path) / 'summary'

        random_commit(receive_repo, tmp_files_path,
                      'app/com.example.App/x86_64/stable')
        receive_repo.update_repo_metadata()
        assert summary.exists()
        summary_refs, summary_metadata = get_summary_variant(summary)
        ref_names = {ref[0] for ref in summary_refs}

        # Flatpak < 1.10 creates the ostree-metadata commit when the
        # repo has a collecton ID, but newer versions don't. Add it to
        # the generated set if it's not there already so the expected
        # set is consistent.
        ref_names.add('ostree-metadata')
        assert ref_names == {
            'ostree-metadata',
            'app/com.example.App/x86_64/stable',
            'appstream/x86_64',
            'appstream2/x86_64',
        }
        assert 'xa.cache' in summary_metadata

    @needs_gpg
    @needs_ostree
    def test_update_repo_metadata_gpg_sign(self, receive_repo, gpg_homedir):
        receive_repo.config.gpg_sign = [PGP_KEY_ID]
        receive_repo.config.gpg_homedir = str(gpg_homedir)
        receive_repo.update_repo_metadata()

        summary = Path(receive_repo.path) / 'summary'
        summary_sig = summary.with_suffix('.sig')
        assert summary.exists()
        assert summary_sig.exists()

    def test_update_repo_hook(self, receive_repo, tmp_path, monkeypatch):
        dumpenv = os.path.join(TESTSDIR, 'dumpenv')
        dumpenv_dest = tmp_path / 'dumpenv.json'
        monkeypatch.setenv('DUMPENV_DEST', str(dumpenv_dest))

        # Exported environment variables
        receive_repo.config.update_hook = dumpenv
        receive_repo.update_repo_hook(['foo', 'bar'])
        with dumpenv_dest.open() as f:
            data = json.load(f)
        assert data['env']['OSTREE_RECEIVE_REPO'] == str(
            receive_repo.path.absolute()
        )
        assert data['env']['OSTREE_RECEIVE_REFS'] == 'foo bar'

        # Wrong refs passed
        with pytest.raises(TypeError):
            receive_repo.update_repo_hook(None)

        # No hook configured
        receive_repo.config.update_hook = None
        with pytest.raises(receive.OTReceiveConfigError) as excinfo:
            receive_repo.update_repo_hook([])
        assert str(excinfo.value) == 'update_hook not set in configuration'

        # Missing or non-executable hook
        hook = tmp_path / 'hook'
        receive_repo.config.update_hook = str(hook)
        with pytest.raises(FileNotFoundError):
            receive_repo.update_repo_hook([])
        hook.touch()
        with pytest.raises(PermissionError):
            receive_repo.update_repo_hook([])

        # Hook argument parsing
        receive_repo.config.update_hook = f'{dumpenv} foo bar'
        receive_repo.update_repo_hook([])
        with dumpenv_dest.open() as f:
            data = json.load(f)
        assert data['args'] == [dumpenv, 'foo', 'bar']

        receive_repo.config.update_hook = f'{dumpenv} "foo bar"'
        receive_repo.update_repo_hook([])
        with dumpenv_dest.open() as f:
            data = json.load(f)
        assert data['args'] == [dumpenv, 'foo bar']

        receive_repo.config.update_hook = fr'{dumpenv} foo\ bar'
        receive_repo.update_repo_hook([])
        with dumpenv_dest.open() as f:
            data = json.load(f)
        assert data['args'] == [dumpenv, 'foo bar']

    def test_receive_missing(self, tmp_files_path, receive_repo, source_repo,
                             source_server):
        random_commit(source_repo, tmp_files_path, 'ref1')

        with pytest.raises(receive.OTReceiveError) as excinfo:
            receive_repo.receive(['missing'])
        assert str(excinfo.value) == \
            'Could not find ref missing in summary file'

        with pytest.raises(receive.OTReceiveError) as excinfo:
            receive_repo.receive(['missing', 'ref1'])
        assert str(excinfo.value) == \
            'Could not find ref missing in summary file'

    def test_receive_specific(self, tmp_files_path, receive_repo, source_repo,
                              source_server):
        random_commit(source_repo, tmp_files_path, 'ref1')
        random_commit(source_repo, tmp_files_path, 'ref2')

        merged = receive_repo.receive(['ref1'])
        assert merged == {'ref1'}
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1'}

        merged = receive_repo.receive(['ref1', 'ref2'])
        assert merged == {'ref2'}
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1', 'ref2'}

        merged = receive_repo.receive(['ref1', 'ref2'])
        assert merged == set()
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1', 'ref2'}

    def test_receive_all(self, tmp_files_path, receive_repo, source_repo,
                         source_server):
        random_commit(source_repo, tmp_files_path, 'ref1')
        random_commit(source_repo, tmp_files_path, 'ref2')
        random_commit(source_repo, tmp_files_path, 'appstream/x86_64')
        random_commit(source_repo, tmp_files_path, 'appstream2/x86_64')
        random_commit(source_repo, tmp_files_path, 'ostree-metadata')
        source_refs = local_refs(source_repo)
        assert source_refs.keys() == {
            'ref1',
            'ref2',
            'appstream/x86_64',
            'appstream2/x86_64',
            'ostree-metadata',
        }

        merged = receive_repo.receive([])
        assert merged == {'ref1', 'ref2'}
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1', 'ref2'}

        merged = receive_repo.receive([])
        assert merged == set()
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1', 'ref2'}

    def test_root(self, tmp_path, tmp_files_path, source_server):
        url = source_server.url
        root = tmp_path / 'pub/repos'
        root.mkdir(parents=True)
        config = receive.OTReceiveConfig(root=str(root), update=False)
        root_tmp_repo = TmpRepo(root / 'root-dest')
        non_root_tmp_repo = TmpRepo(tmp_path / 'non-root-dest')

        # Requesting a repo outside the root should fail
        repo_path = non_root_tmp_repo.path
        logger.debug('Repo path %s', repo_path)
        with pytest.raises(receive.OTReceiveError) as excinfo:
            receive.OTReceiveRepo(str(repo_path), url, config)
        assert str(excinfo.value) == (
            f'repo {non_root_tmp_repo.path} not found'
        )

        # Absolute path under the root should work
        repo_path = root_tmp_repo.path.resolve()
        assert repo_path.is_absolute()
        logger.debug('Repo path %s', repo_path)
        with receive.OTReceiveRepo(str(repo_path), url, config):
            pass

        # Relative path under the root should work
        repo_path = root_tmp_repo.path.relative_to(root)
        assert not repo_path.is_absolute()
        logger.debug('Repo path %s', repo_path)
        with receive.OTReceiveRepo(str(repo_path), url, config):
            pass


class TestConfig:
    """Tests for OTReceiveConfig"""
    def test_defaults(self):
        config = receive.OTReceiveConfig()
        assert dataclasses.asdict(config) == {
            'root': None,
            'gpg_sign': [],
            'gpg_homedir': None,
            'update': True,
            'update_hook': None,
            'log_level': 'INFO',
            'force': False,
            'dry_run': False,
        }

    def test_invalid(self):
        with pytest.raises(receive.OTReceiveConfigError) as excinfo:
            receive.OTReceiveConfig(update=None)
        assert str(excinfo.value) == (
            "update must be an instance of <class 'bool'>, "
            "but found <class 'NoneType'>"
        )

        with pytest.raises(receive.OTReceiveConfigError) as excinfo:
            receive.OTReceiveConfig(update='true')
        assert str(excinfo.value) == (
            "update must be an instance of <class 'bool'>, "
            "but found <class 'str'>"
        )

    def test_default_paths(self, tmp_path, monkeypatch):
        assert receive.OTReceiveConfig.default_paths() == [
            Path('/etc/ostree/ostree-receive.conf'),
            Path('~/.config/ostree/ostree-receive.conf'),
        ]

        monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path))
        assert receive.OTReceiveConfig.default_paths() == [
            Path('/etc/ostree/ostree-receive.conf'),
            tmp_path / 'ostree/ostree-receive.conf',
        ]

        monkeypatch.setenv('OSTREE_RECEIVE_CONF', str(tmp_path))
        assert receive.OTReceiveConfig.default_paths() == [tmp_path]

    def test_load_valid(self, tmp_path):
        path = tmp_path / 'ostree-receive.conf'
        data = {
            'root': str(tmp_path / 'pub/repos'),
            'gpg_sign': ['01234567', '89ABCDEF'],
            'gpg_homedir': str(tmp_path / 'gnupg'),
            'update': False,
            'update_hook': '/foo/bar baz',
            'log_level': 'DEBUG',
            'force': True,
            'dry_run': True,
        }
        with path.open('w') as f:
            yaml.dump(data, f)

        config = receive.OTReceiveConfig.load([path])
        assert dataclasses.asdict(config) == data

    def test_load_none(self):
        config = receive.OTReceiveConfig.load([])
        assert config == receive.OTReceiveConfig()

    def test_load_empty(self, tmp_path, caplog):
        caplog.set_level(logging.DEBUG, receive.logger.name)
        path = tmp_path / 'ostree-receive.conf'
        path.touch()
        config = receive.OTReceiveConfig.load([path])
        assert config == receive.OTReceiveConfig()

        expected_log_record = (
            receive.logger.name,
            logging.DEBUG,
            f'Ignoring empty config file {path}'
        )
        assert expected_log_record in caplog.record_tuples

    def test_load_missing(self, tmp_path, caplog):
        caplog.set_level(logging.DEBUG, receive.logger.name)
        path = tmp_path / 'ostree-receive.conf'
        config = receive.OTReceiveConfig.load([path])
        assert config == receive.OTReceiveConfig()

        expected_log_record = (
            receive.logger.name,
            logging.DEBUG,
            f'Skipping missing config file {path}'
        )
        assert expected_log_record in caplog.record_tuples

    def test_load_multiple(self, tmp_path):
        path1 = tmp_path / 'receive1.conf'
        data = {
            'log_level': 'DEBUG',
        }
        with path1.open('w') as f:
            yaml.dump(data, f)

        path2 = tmp_path / 'receive2.conf'
        data = {
            'log_level': 'WARNING',
        }
        with path2.open('w') as f:
            yaml.dump(data, f)

        config = receive.OTReceiveConfig.load([path1, path2])
        assert config.log_level == 'WARNING'

    def test_load_unknown(self, tmp_path, caplog):
        caplog.set_level(logging.WARNING, receive.logger.name)
        path = tmp_path / 'ostree-receive.conf'
        data = {
            'fake_option': False,
        }
        with path.open('w') as f:
            yaml.dump(data, f)

        config = receive.OTReceiveConfig.load([path])
        assert config == receive.OTReceiveConfig()

        expected_log_record = (
            receive.logger.name,
            logging.WARNING,
            f'Unrecognized option fake_option in config file {path}',
        )
        assert expected_log_record in caplog.record_tuples

    def test_load_invalid(self, tmp_path):
        with pytest.raises(receive.OTReceiveConfigError) as excinfo:
            receive.OTReceiveConfig.load([True])
        assert str(excinfo.value) == (
            'expected str, bytes or os.PathLike object, not bool'
        )

        path = tmp_path / 'ostree-receive.conf'
        data = {
            'update': None,
        }
        with path.open('w') as f:
            yaml.dump(data, f)

        with pytest.raises(receive.OTReceiveConfigError) as excinfo:
            receive.OTReceiveConfig.load([path])
        assert str(excinfo.value) == (
            "update must be an instance of <class 'bool'>, "
            "but found <class 'NoneType'>"
        )

        data = ['not', 'a', 'mapping']
        with path.open('w') as f:
            yaml.dump(data, f)

        with pytest.raises(receive.OTReceiveConfigError) as excinfo:
            receive.OTReceiveConfig.load([path])
        assert str(excinfo.value) == (
            f'Config file {path} is not a YAML mapping'
        )

    def test_load_env(self, tmp_path, monkeypatch):
        path = tmp_path / 'ostree-receive.conf'
        data = {
            'log_level': 'DEBUG',
        }
        with path.open('w') as f:
            yaml.dump(data, f)

        monkeypatch.setenv('OSTREE_RECEIVE_CONF', str(path))
        config = receive.OTReceiveConfig.load()
        assert config.log_level == 'DEBUG'

    def test_load_args(self, caplog):
        caplog.set_level(logging.DEBUG, receive.logger.name)
        ap = argparse.ArgumentParser()
        ap.add_argument('--log-level', default='WARNING')
        ap.add_argument('--someopt', default='someval')
        ap.add_argument('pos')
        args = ap.parse_args(['foo'])

        config = receive.OTReceiveConfig.load(paths=[], args=args)
        assert dataclasses.asdict(config) == {
            'root': None,
            'gpg_sign': [],
            'gpg_homedir': None,
            'update': True,
            'update_hook': None,
            'log_level': 'WARNING',
            'force': False,
            'dry_run': False,
        }

        expected_log_record = (
            receive.logger.name,
            logging.DEBUG,
            'Ignoring argument someopt'
        )
        assert expected_log_record in caplog.record_tuples

        expected_log_record = (
            receive.logger.name,
            logging.DEBUG,
            'Ignoring argument pos'
        )
        assert expected_log_record in caplog.record_tuples

    def test_load_args_invalid(self):
        with pytest.raises(receive.OTReceiveConfigError) as excinfo:
            receive.OTReceiveConfig.load(paths=[], args='foo')
        assert str(excinfo.value) == (
            'args is not an argparse.Namespace instance'
        )

    def test_load_conf_and_args(self, tmp_path):
        path = tmp_path / 'ostree-receive.conf'
        data = {
            'log-level': 'DEBUG',
        }
        with path.open('w') as f:
            yaml.dump(data, f)

        ap = argparse.ArgumentParser()
        ap.add_argument('--log-level', default='WARNING')
        args = ap.parse_args([])

        config = receive.OTReceiveConfig.load(paths=[path], args=args)
        assert config.log_level == 'WARNING'


class TestArgParser:
    def test_no_repo(self, capsys):
        ap = receive.OTReceiveArgParser()
        with pytest.raises(SystemExit) as excinfo:
            ap.parse_args([])
        assert excinfo.value.code == 2
        out, err = capsys.readouterr()
        assert out == ''
        assert err.endswith(
            'error: the following arguments are required: REPO, URL\n'
        )

    def test_no_url(self, capsys):
        ap = receive.OTReceiveArgParser()
        with pytest.raises(SystemExit) as excinfo:
            ap.parse_args(['repo'])
        assert excinfo.value.code == 2
        out, err = capsys.readouterr()
        assert out == ''
        assert err.endswith(
            'error: the following arguments are required: URL\n'
        )

    def test_defaults(self):
        ap = receive.OTReceiveArgParser()
        args = ap.parse_args(['repo', 'url'])
        assert args == argparse.Namespace(
            repo='repo',
            url='url',
            refs=[],
        )

    def test_refs(self):
        ap = receive.OTReceiveArgParser()
        args = ap.parse_args(['repo', 'url', 'foo'])
        assert args.refs == ['foo']
        args = ap.parse_args(['repo', 'url', 'foo', 'bar', 'baz'])
        assert args.refs == ['foo', 'bar', 'baz']

    def test_update(self):
        ap = receive.OTReceiveArgParser()
        args = ap.parse_args(['--no-update', 'repo', 'url'])
        assert args.update is False

    def test_dry_run(self):
        ap = receive.OTReceiveArgParser()
        args = ap.parse_args(['-n', 'repo', 'url'])
        assert args.dry_run is True
        args = ap.parse_args(['--dry-run', 'repo', 'url'])
        assert args.dry_run is True

    def test_force(self):
        ap = receive.OTReceiveArgParser()
        args = ap.parse_args(['-f', 'repo', 'url'])
        assert args.force is True
        args = ap.parse_args(['--force', 'repo', 'url'])
        assert args.force is True

    def test_log_level(self):
        ap = receive.OTReceiveArgParser()
        args = ap.parse_args(['-v', 'repo', 'url'])
        assert args.log_level == 'DEBUG'
        args = ap.parse_args(['--verbose', 'repo', 'url'])
        assert args.log_level == 'DEBUG'
        args = ap.parse_args(['-q', 'repo', 'url'])
        assert args.log_level == 'WARNING'
        args = ap.parse_args(['--quiet', 'repo', 'url'])
        assert args.log_level == 'WARNING'
