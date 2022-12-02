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
    ED25519_PRIVATE_KEY,
    ED25519_PUBLIC_KEY,
    PGP_PUB,
    PGP_PUB_KEYRING,
    PGP_KEY_ID,
    TESTSDIR,
    get_ostree_ed25519_sign,
    get_summary_variant,
    local_refs,
    needs_ed25519,
    needs_flatpak,
    needs_gpg,
    needs_ostree,
    oneshot_transaction,
    random_commit,
    wipe_repo,
)

gi.require_version('OSTree', '1.0')
from gi.repository import OSTree  # noqa: E402

logger = logging.getLogger(__name__)


class TestReceiveRepo:
    def test_cleanup(self, dest_repo):
        url = 'http://example.com'
        config = receive.OTReceiveRepoConfig(dest_repo.path, url)
        repo = receive.OTReceiveRepo(config)
        remotes_dir = Path(repo.remotes_dir.name)
        assert remotes_dir.exists()
        del repo
        assert not remotes_dir.exists()

        with receive.OTReceiveRepo(config) as repo:
            remotes_dir = Path(repo.remotes_dir.name)
            assert remotes_dir.exists()
        assert not remotes_dir.exists()

    def test_missing_repo(self, tmp_path):
        repo_path = tmp_path / 'repo'
        url = 'http://example.com'
        config = receive.OTReceiveRepoConfig(repo_path, url)
        with pytest.raises(receive.OTReceiveError) as excinfo:
            receive.OTReceiveRepo(config)
        assert str(excinfo.value) == f'repo {repo_path} not found'

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

    @needs_gpg
    def test_receive_gpg_verify(self, tmp_path, tmp_files_path, dest_repo,
                                source_repo, source_server, gpg_homedir,
                                monkeypatch):
        # Specifying a missing GPG keyring should fail
        keyring_path = str(tmp_path / 'missing.gpg')
        config = receive.OTReceiveRepoConfig(
            dest_repo.path,
            source_server.url,
            gpg_verify=True,
            gpg_trustedkeys=keyring_path,
            update=False,
        )
        with pytest.raises(receive.OTReceiveConfigError) as excinfo:
            receive.OTReceiveRepo(config)
        assert str(excinfo.value) == (
            f'gpg_trustedkeys keyring "{keyring_path}" does not exist'
        )

        # Receiving an unsigned commit should fail.
        random_commit(source_repo, tmp_files_path, 'ref1')
        config = receive.OTReceiveRepoConfig(
            dest_repo.path,
            source_server.url,
            gpg_verify=True,
            gpg_trustedkeys=str(PGP_PUB_KEYRING),
            update=False,
        )
        repo = receive.OTReceiveRepo(config)
        with pytest.raises(GLib.Error) as excinfo:
            repo.receive(['ref1'])
        assert excinfo.value.matches(OSTree.gpg_error_quark(),
                                     OSTree.GpgError.NO_SIGNATURE)

        # Receiving a signed commit should succeed.
        random_commit(source_repo, tmp_files_path, 'ref1',
                      gpg_key_id=PGP_KEY_ID, gpg_homedir=str(gpg_homedir))
        config = receive.OTReceiveRepoConfig(
            dest_repo.path,
            source_server.url,
            gpg_verify=True,
            gpg_trustedkeys=str(PGP_PUB_KEYRING),
            update=False,
        )
        repo = receive.OTReceiveRepo(config)
        wipe_repo(repo)
        merged = repo.receive(['ref1'])
        assert merged == {'ref1'}
        refs = local_refs(repo)
        assert refs.keys() == {'ref1'}

        # Using an ASCII armored key instead of a PGP keyring should
        # also work.
        random_commit(source_repo, tmp_files_path, 'ref1',
                      gpg_key_id=PGP_KEY_ID, gpg_homedir=str(gpg_homedir))
        config = receive.OTReceiveRepoConfig(
            dest_repo.path,
            source_server.url,
            gpg_verify=True,
            gpg_trustedkeys=str(PGP_PUB),
            update=False,
        )
        repo = receive.OTReceiveRepo(config)
        wipe_repo(repo)
        merged = repo.receive(['ref1'])
        assert merged == {'ref1'}
        refs = local_refs(repo)
        assert refs.keys() == {'ref1'}

        # Using the user's default keyring.
        random_commit(source_repo, tmp_files_path, 'ref1',
                      gpg_key_id=PGP_KEY_ID, gpg_homedir=str(gpg_homedir))
        monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path))
        keyring = tmp_path / 'ostree/ostree-receive-trustedkeys.gpg'
        keyring.parent.mkdir(exist_ok=True)
        keyring.symlink_to(PGP_PUB_KEYRING)
        config = receive.OTReceiveRepoConfig(
            dest_repo.path,
            source_server.url,
            gpg_verify=True,
            update=False,
        )
        repo = receive.OTReceiveRepo(config)
        wipe_repo(repo)
        merged = repo.receive(['ref1'])
        assert merged == {'ref1'}
        refs = local_refs(repo)
        assert refs.keys() == {'ref1'}

    @needs_ed25519
    def test_receive_ed25519_sign(self, tmp_files_path, tmp_path, receive_repo,
                                  source_repo, ed25519_private_keyfile):
        random_commit(source_repo, tmp_files_path, 'ref1')

        # Specifying a missing keyfile should fail.
        keyfile_path = str(tmp_path / 'missing')
        receive_repo.config.sign_keyfiles = [keyfile_path]
        with pytest.raises(receive.OTReceiveConfigError,
                           match=f'sign_keyfiles keyfile "{keyfile_path}"'
                                 + ' does not exist'):
            receive_repo.receive(['ref1'])

        # Specifying the key.
        receive_repo.config.sign_keyfiles = [ed25519_private_keyfile]
        merged = receive_repo.receive(['ref1'])
        assert merged == {'ref1'}
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1'}

        # Validate the signature and make sure it was signed by the correct
        # key.
        sign = get_ostree_ed25519_sign()
        sign.set_pk(GLib.Variant('s', ED25519_PUBLIC_KEY))
        commit = refs['ref1']
        assert sign.commit_verify(receive_repo, commit)

    @needs_ed25519
    def test_receive_ed25519_verify(self, tmp_path, tmp_files_path, dest_repo,
                                    source_repo, source_server,
                                    ed25519_public_keyfile, monkeypatch):
        # Specifying a missing keyfile should fail.
        keyfile_path = str(tmp_path / 'missing')
        config = receive.OTReceiveRepoConfig(
            dest_repo.path,
            source_server.url,
            sign_verify=True,
            sign_trustedkeyfile=keyfile_path,
            update=False,
        )
        with pytest.raises(receive.OTReceiveConfigError,
                           match='sign_trustedkeyfile keyfile'
                                 + f' "{keyfile_path}" does not'
                                 + ' exist') as excinfo:
            receive.OTReceiveRepo(config)

        # Receiving an unsigned commit should fail.
        random_commit(source_repo, tmp_files_path, 'ref1')
        config = receive.OTReceiveRepoConfig(
            dest_repo.path,
            source_server.url,
            sign_verify=True,
            sign_trustedkeyfile=ed25519_public_keyfile,
            update=False,
        )
        repo = receive.OTReceiveRepo(config)
        with pytest.raises(GLib.Error, match="Can't verify commit") as excinfo:
            repo.receive(['ref1'])
        assert excinfo.value.matches(Gio.io_error_quark(),
                                     Gio.IOErrorEnum.FAILED)

        # Receiving a signed commit should succeed.
        random_commit(source_repo, tmp_files_path, 'ref1',
                      ed25519_key=ED25519_PRIVATE_KEY)
        config = receive.OTReceiveRepoConfig(
            dest_repo.path,
            source_server.url,
            sign_verify=True,
            sign_trustedkeyfile=ed25519_public_keyfile,
            update=False,
        )
        repo = receive.OTReceiveRepo(config)
        wipe_repo(repo)
        merged = repo.receive(['ref1'])
        assert merged == {'ref1'}
        refs = local_refs(repo)
        assert refs.keys() == {'ref1'}

        # Using the user's default keyfile.
        random_commit(source_repo, tmp_files_path, 'ref1',
                      ed25519_key=ED25519_PRIVATE_KEY)
        monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path))
        keyring = tmp_path / 'ostree/ostree-receive-trustedkeyfile.ed25519'
        keyring.parent.mkdir(exist_ok=True)
        keyring.symlink_to(ed25519_public_keyfile)
        config = receive.OTReceiveRepoConfig(
            dest_repo.path,
            source_server.url,
            sign_verify=True,
            update=False,
        )
        repo = receive.OTReceiveRepo(config)
        wipe_repo(repo)
        merged = repo.receive(['ref1'])
        assert merged == {'ref1'}
        refs = local_refs(repo)
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

    @needs_ed25519
    @needs_ostree
    def test_update_repo_metadata_ed25519_sign(self, receive_repo,
                                               ed25519_private_keyfile):
        receive_repo.config.sign_keyfiles = [ed25519_private_keyfile]
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

    def test_receive_dry_run(self, tmp_files_path, receive_repo, source_repo,
                             source_server):
        random_commit(source_repo, tmp_files_path, 'ref1')
        merged = receive_repo.receive(['ref1'], dry_run=True)
        assert merged == {'ref1'}
        refs = local_refs(receive_repo)
        assert refs.keys() == set()

    def test_receive_force(self, tmp_files_path, receive_repo, source_repo,
                           source_server, caplog):
        caplog.set_level(logging.WARNING, receive.logger.name)

        # First make a commit and pull it directly so the destination
        # has the exact same commit.
        checksum = random_commit(
            source_repo,
            tmp_files_path,
            'ref1',
            timestamp=0,
        )
        opts = GLib.Variant('a{sv}', {
            'refs': GLib.Variant('as', ['ref1']),
        })
        receive_repo.pull_with_options(source_repo.path.as_uri(), opts)
        refs = local_refs(receive_repo)
        assert refs == {'ref1': checksum}

        # Non-forced receive will get nothing. There should be no
        # warnings since the commits are exactly the same.
        caplog.clear()
        merged = receive_repo.receive(['ref1'])
        assert merged == set()
        refs = local_refs(receive_repo)
        assert refs == {'ref1': checksum}
        assert caplog.record_tuples == []

        # Forced merge will make a new commit. This will have warnings
        # about both timestamp and content.
        caplog.clear()
        merged = receive_repo.receive(['ref1'], force=True)
        assert merged == {'ref1'}
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1'}
        assert refs['ref1'] != checksum
        assert caplog.record_tuples == [
            (
                receive.logger.name, logging.WARNING,
                f'received ref1 commit {checksum} is not newer than '
                f'current ref1 commit {checksum}'
            ),
            (
                receive.logger.name, logging.WARNING,
                f'received ref1 commit {checksum} has the same content as '
                f'current ref1 commit {checksum}'
            ),
        ]

        # Make a new commit with the same content and set the
        # destination repo back to the original commit.
        with oneshot_transaction(source_repo):
            mtree = OSTree.MutableTree.new()
            _, root, _ = source_repo.read_commit(checksum)
            _, commit, _ = source_repo.load_commit(checksum)
            source_repo.write_directory_to_mtree(root, mtree, None)
            _, new_root = source_repo.write_mtree(mtree)
            metadata = commit.get_child_value(0)
            _, new_checksum = source_repo.write_commit_with_time(
                checksum,
                'Test commit',
                None,
                metadata,
                new_root,
                1,
            )
            source_repo.transaction_set_ref(None, 'ref1', new_checksum)
        receive_repo.set_ref_immediate(None, 'ref1', checksum)

        # Non-forced receive will get nothing but there will be a
        # warning about the content.
        caplog.clear()
        merged = receive_repo.receive(['ref1'])
        assert merged == set()
        refs = local_refs(receive_repo)
        assert refs == {'ref1': checksum}
        assert caplog.record_tuples == [
            (
                receive.logger.name, logging.WARNING,
                f'received ref1 commit {new_checksum} has the same content '
                f'as current ref1 commit {checksum}'
            ),
        ]

        # Forced merge will make a new commit.
        caplog.clear()
        merged = receive_repo.receive(['ref1'], force=True)
        assert merged == {'ref1'}
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1'}
        assert refs['ref1'] != checksum

        # Make a random commit in the destination so it's newer and has
        # different content.
        dest_checksum = random_commit(
            receive_repo,
            tmp_files_path,
            'ref1',
            timestamp=2,
        )

        # Non-forced receive will get nothing but there will be a
        # warning about the timestamp.
        caplog.clear()
        merged = receive_repo.receive(['ref1'])
        assert merged == set()
        refs = local_refs(receive_repo)
        assert refs == {'ref1': dest_checksum}
        assert caplog.record_tuples == [
            (
                receive.logger.name, logging.WARNING,
                f'received ref1 commit {new_checksum} is not newer than '
                f'current ref1 commit {dest_checksum}'
            ),
        ]

        # Forced merge will make a new commit.
        caplog.clear()
        merged = receive_repo.receive(['ref1'], force=True)
        assert merged == {'ref1'}
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1'}
        assert refs['ref1'] != dest_checksum


class TestReceiver:
    """Tests for OTReceiver class"""
    def test_default_config(self):
        receiver = receive.OTReceiver()
        assert receiver.config == receive.OTReceiveConfig()

    def test_receive(self, receiver, tmp_files_path, source_repo, dest_repo,
                     source_server):
        random_commit(source_repo, tmp_files_path, 'ref1')
        source_refs = local_refs(source_repo)
        assert source_refs.keys() == {'ref1'}

        merged = receiver.receive(dest_repo.path, source_server.url, ['ref1'])
        assert merged == {'ref1'}
        dest_refs = local_refs(dest_repo)
        assert dest_refs.keys() == {'ref1'}

        merged = receiver.receive(dest_repo.path, source_server.url, ['ref1'])
        assert merged == set()
        dest_refs = local_refs(dest_repo)
        assert dest_refs.keys() == {'ref1'}

        # Test that repos override is applied.
        summary_path = dest_repo.path / 'summary'
        assert not summary_path.exists()
        assert not receiver.config.update
        receiver.config.repos = {str(dest_repo.path): {'update': True}}
        random_commit(source_repo, tmp_files_path, 'ref2')
        merged = receiver.receive(dest_repo.path, source_server.url, ['ref2'])
        assert merged == {'ref2'}
        assert summary_path.exists()


class TestRepoConfig:
    """Tests for OTReceiveRepoConfig"""
    def test_defaults(self):
        config = receive.OTReceiveRepoConfig(Path('foo'), 'http://bar')
        assert dataclasses.asdict(config) == {
            'path': Path('foo'),
            'url': 'http://bar',
            'gpg_sign': [],
            'gpg_homedir': None,
            'gpg_verify': False,
            'gpg_trustedkeys': None,
            'sign_type': 'ed25519',
            'sign_keyfiles': [],
            'sign_verify': False,
            'sign_trustedkeyfile': None,
            'update': True,
            'update_hook': None,
        }

    def test_required(self):
        with pytest.raises(TypeError):
            receive.OTReceiveRepoConfig()
        with pytest.raises(TypeError):
            receive.OTReceiveRepoConfig(path=Path('foo'))
        with pytest.raises(TypeError):
            receive.OTReceiveRepoConfig(url='http://bar')


class TestConfig:
    """Tests for OTReceiveConfig"""
    def test_defaults(self):
        config = receive.OTReceiveConfig()
        assert dataclasses.asdict(config) == {
            'root': None,
            'gpg_sign': [],
            'gpg_homedir': None,
            'gpg_verify': False,
            'gpg_trustedkeys': None,
            'sign_type': 'ed25519',
            'sign_keyfiles': [],
            'sign_verify': False,
            'sign_trustedkeyfile': None,
            'update': True,
            'update_hook': None,
            'repos': {},
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
            'gpg_verify': True,
            'gpg_trustedkeys': str(tmp_path / 'trustedkeys.gpg'),
            'sign_type': 'ed25519',
            'sign_keyfiles': [
                str(tmp_path / 'signkey1'),
                str(tmp_path / 'signkey2'),
            ],
            'sign_verify': True,
            'sign_trustedkeyfile': str(tmp_path / 'trustedkey'),
            'update': False,
            'update_hook': '/foo/bar baz',
            'repos': {
                'foo': {
                    'gpg_sign': ['76543210'],
                },
                'bar': {
                    'gpg_verify': False,
                },
            },
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
            'gpg_verify': False,
            'gpg_trustedkeys': None,
            'sign_type': 'ed25519',
            'sign_keyfiles': [],
            'sign_verify': False,
            'sign_trustedkeyfile': None,
            'update': True,
            'update_hook': None,
            'repos': {},
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

    def test_repo_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config = receive.OTReceiveConfig()
        url = 'http://example.com'
        rel_root = Path('root')
        root = rel_root.resolve()
        root.mkdir()
        root_repo = root / 'repo'
        rel_root_repo = root_repo.relative_to(root)
        root_repo.mkdir()
        rel_nonroot_repo = Path('repo')
        nonroot_repo = rel_nonroot_repo.resolve()
        nonroot_repo.mkdir()

        # Non-existent repo should raise an exception.
        repo_path = tmp_path / 'nonexistent'
        with pytest.raises(receive.OTReceiveError) as excinfo:
            config.get_repo_config(repo_path, url)
        assert str(excinfo.value) == f'repo {repo_path} not found'

        # Without root setup, the path should be passed back as is.
        repo_config = config.get_repo_config(str(rel_nonroot_repo), url)
        assert repo_config.path == rel_nonroot_repo
        repo_config = config.get_repo_config(rel_nonroot_repo, url)
        assert repo_config.path == rel_nonroot_repo
        repo_config = config.get_repo_config(str(nonroot_repo), url)
        assert repo_config.path == nonroot_repo
        repo_config = config.get_repo_config(nonroot_repo, url)
        assert repo_config.path == nonroot_repo

        # Requesting a repo outside the root should fail.
        config.root = str(root)
        with pytest.raises(receive.OTReceiveError) as excinfo:
            config.get_repo_config(nonroot_repo, url)
        assert str(excinfo.value) == f'repo {nonroot_repo} not found'

        # All combinations of root, repo path, and config override path.
        base_expected_config = {
            'path': nonroot_repo,
            'url': url,
            'gpg_sign': config.gpg_sign,
            'gpg_homedir': config.gpg_homedir,
            'gpg_verify': config.gpg_verify,
            'gpg_trustedkeys': config.gpg_trustedkeys,
            'sign_type': config.sign_type,
            'sign_keyfiles': config.sign_keyfiles,
            'sign_verify': config.sign_verify,
            'sign_trustedkeyfile': config.sign_trustedkeyfile,
            'update': config.update,
            'update_hook': config.update_hook,
        }
        for root_path, repo_path, override_path, expected_repo_path in (
            # Absolute repo path with no root and no override.
            (None, nonroot_repo, None, nonroot_repo),
            # Relative repo path with no root and no override.
            (None, rel_nonroot_repo, None, rel_nonroot_repo),
            # Absolute repo path with absolute root and no override.
            (root, root_repo, None, root_repo),
            # Relative repo path with absolute root and no override.
            (root, rel_root_repo, None, root_repo),
            # Absolute repo path with relative root and no override.
            (rel_root, root_repo, None, root_repo),
            # Relative repo path with relative root and no override.
            (rel_root, rel_root_repo, None, root_repo),

            # Absolute repo path with no root and absolute override.
            (None, nonroot_repo, nonroot_repo, nonroot_repo),
            # Relative repo path with no root and absolute override.
            (None, rel_nonroot_repo, nonroot_repo, rel_nonroot_repo),
            # Absolute repo path with absolute root and absolute override.
            (root, root_repo, root_repo, root_repo),
            # Relative repo path with absolute root and absolute override.
            (root, rel_root_repo, root_repo, root_repo),
            # Absolute repo path with relative root and absolute override.
            (rel_root, root_repo, root_repo, root_repo),
            # Relative repo path with relative root and absolute override.
            (rel_root, rel_root_repo, root_repo, root_repo),

            # Absolute repo path with no root and relative override.
            (None, nonroot_repo, rel_nonroot_repo, nonroot_repo),
            # Relative repo path with no root and relative override.
            (None, rel_nonroot_repo, rel_nonroot_repo, rel_nonroot_repo),
            # Absolute repo path with absolute root and relative override.
            (root, root_repo, rel_root_repo, root_repo),
            # Relative repo path with absolute root and relative override.
            (root, rel_root_repo, rel_root_repo, root_repo),
            # Absolute repo path with relative root and relative override.
            (rel_root, root_repo, rel_root_repo, root_repo),
            # Relative repo path with relative root and relative override.
            (rel_root, rel_root_repo, rel_root_repo, root_repo),
        ):
            logger.debug(
                f'Testing {root_path=}, {repo_path=}, {override_path=}, '
                f'{expected_repo_path=}',
            )

            expected_config = base_expected_config.copy()
            expected_config['path'] = expected_repo_path
            config.root = str(root_path) if root_path else None
            if override_path:
                config.repos = {str(override_path): {'update': False}}
                expected_config['update'] = False
            else:
                config.repos = {}
                expected_config['update'] = True

            repo_config = config.get_repo_config(repo_path, url)
            assert dataclasses.asdict(repo_config) == expected_config
            if override_path:
                assert repo_config.update != config.update


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
