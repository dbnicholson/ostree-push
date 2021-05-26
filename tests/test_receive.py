from otpush import receive

import argparse
import gi
from gi.repository import GLib, Gio
import logging
from pathlib import Path
import pytest
import time

from .util import (
    get_summary_variant,
    local_refs,
    oneshot_transaction,
    random_commit,
    wipe_repo,
)

gi.require_version('OSTree', '1.0')
from gi.repository import OSTree  # noqa: E402


class TestReceiveRepo:
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

        merged = receive_repo.receive(['ref1'], update_metadata=False)
        assert merged == {'ref1'}
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1'}

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

        random_commit(receive_repo, tmp_files_path,
                      'app/com.example.App/x86_64/stable')
        receive_repo.update_repo_metadata()
        assert summary.exists()
        summary_refs, summary_metadata = get_summary_variant(summary)
        ref_names = {ref[0] for ref in summary_refs}
        assert ref_names == {
            'ostree-metadata',
            'someref',
            'app/com.example.App/x86_64/stable',
            'appstream/x86_64',
            'appstream2/x86_64',
        }
        assert 'xa.cache' in summary_metadata

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

        merged = receive_repo.receive(['ref1'], update_metadata=False)
        assert merged == {'ref1'}
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1'}

        merged = receive_repo.receive(['ref1', 'ref2'], update_metadata=False)
        assert merged == {'ref2'}
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1', 'ref2'}

        merged = receive_repo.receive(['ref1', 'ref2'], update_metadata=False)
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

        merged = receive_repo.receive([], update_metadata=False)
        assert merged == {'ref1', 'ref2'}
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1', 'ref2'}

        merged = receive_repo.receive([], update_metadata=False)
        assert merged == set()
        refs = local_refs(receive_repo)
        assert refs.keys() == {'ref1', 'ref2'}


class TestArgParser:
    def test_no_repo(self, capsys):
        ap = receive.OTReceiveArgParser()
        with pytest.raises(SystemExit) as excinfo:
            ap.parse_args([])
        assert excinfo.value.code == 2
        out, err = capsys.readouterr()
        assert out == ''
        assert err.endswith('error: the following arguments are required: '
                            'REPO, URL, REF\n')

    def test_no_url(self, capsys):
        ap = receive.OTReceiveArgParser()
        with pytest.raises(SystemExit) as excinfo:
            ap.parse_args(['repo'])
        assert excinfo.value.code == 2
        out, err = capsys.readouterr()
        assert out == ''
        assert err.endswith('error: the following arguments are required: '
                            'URL, REF\n')

    def test_defaults(self):
        ap = receive.OTReceiveArgParser()
        args = ap.parse_args(['repo', 'url'])
        assert args == argparse.Namespace(
            repo='repo',
            url='url',
            refs=[],
            update=True,
            dry_run=False,
            force=False,
            log_level=logging.INFO,
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
        assert args.log_level == logging.DEBUG
        args = ap.parse_args(['--verbose', 'repo', 'url'])
        assert args.log_level == logging.DEBUG
        args = ap.parse_args(['-q', 'repo', 'url'])
        assert args.log_level == logging.WARNING
        args = ap.parse_args(['--quiet', 'repo', 'url'])
        assert args.log_level == logging.WARNING
