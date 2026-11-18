"""Real Linux descriptor IO for the Bundle2 terminal writer's private store."""

from contextlib import contextmanager
import errno
import os
from pathlib import Path
import sys

import pytest

from phase_tool import evidence, installation
from phase_tool.canonical import canonical_bytes, digest_bytes
from phase_tool.errors import PhaseError


pytestmark = pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux dir_fd and /proc required')
CHECKPOINT = {'scope': 'synthetic descriptor fixture'}
LEAF = 'commit-intent.json'


def fixture_fds(tmp_path):
    result = {}
    prefix = str(tmp_path.resolve()) + '/'
    for leaf in Path('/proc/self/fd').iterdir():
        try:
            name = os.readlink(leaf)
        except FileNotFoundError:
            continue  # The iterator's own fd can already be closed.
        if name.startswith(prefix):
            result[int(leaf.name)] = name
    return result


@contextmanager
def opened(binding, run, **kwargs):
    store = evidence._open_native_recovery_store(binding, run.name, **kwargs)
    try:
        yield store
    finally:
        evidence._close_native_recovery_store(store)


@pytest.fixture
def existing_checkpoint(tmp_path, monkeypatch):
    root = tmp_path.resolve() / 'evidence'
    run = root / '.phase/runs/selected-bundle2'
    for directory in (root, root/'.phase', run.parent, run, run/'attachments'):
        directory.mkdir(mode=0o700)
    inspect_filesystem = installation._linux_filesystem_type
    if inspect_filesystem(root) != 'ext4':
        # Only model the required ext4 classification for this one fixture.
        # All lstat, device/inode, ownership, no-mount and descriptor checks run.
        def fixture_filesystem(path):
            actual = inspect_filesystem(path)
            return 'ext4' if path == root else actual

        monkeypatch.setattr(installation, '_linux_filesystem_type', fixture_filesystem)
    physical = root.stat()
    raw = canonical_bytes({'native_read_installation_version': '1.9', 'evidence_root': str(root),
        'evidence_identity': {'stable_id': 'synthetic.recovery', 'device': physical.st_dev, 'inode': physical.st_ino}})
    binding = installation._NativeFileCreateReadBinding(raw, digest_bytes(raw), registry=None)
    assert not fixture_fds(tmp_path)
    with opened(binding, run) as store:
        assert len(store._native_recovery_fds) == 5
        path, digest = evidence._write_native_recovery_canonical(store, LEAF, CHECKPOINT)
        assert path == run/'recovery'/LEAF and digest == digest_bytes(canonical_bytes(CHECKPOINT))
        expected = evidence._native_recovery_checkpoint_identity(store)
        descriptors = store._native_recovery_fds
        assert len(descriptors) == 6
        assert descriptors[5][1:3] == [descriptors[3][0], 'recovery']
        assert set(fixture_fds(tmp_path)) == {row[0] for row in descriptors}
    assert not fixture_fds(tmp_path)
    return binding, run, expected


def test_real_reopen_pins_same_recovery_directory_and_checkpoint(tmp_path, existing_checkpoint):
    binding, run, expected = existing_checkpoint
    with opened(binding, run, _expected_commit_checkpoint=expected) as store:
        descriptors = store._native_recovery_fds
        assert len(descriptors) == 6 and descriptors[5][1:3] == [descriptors[3][0], 'recovery']
        assert set(fixture_fds(tmp_path)) == {row[0] for row in descriptors}
        assert tuple((info.st_dev, info.st_ino) for info in (os.fstat(row[0]) for row in descriptors)) == expected[0]
        assert evidence._native_recovery_checkpoint_identity(store) == expected
        for leaf in ('native-commit-proof.json', 'commit-receipt.json'):
            evidence._write_native_recovery_canonical(store, leaf, {'synthetic': leaf})
        assert evidence._native_recovery_checkpoint_identity(store) == expected
    assert not fixture_fds(tmp_path)
    assert {leaf.name: leaf.read_bytes() for leaf in (run/'recovery').iterdir()} == {
        LEAF: canonical_bytes(CHECKPOINT),
        'native-commit-proof.json': canonical_bytes({'synthetic': 'native-commit-proof.json'}),
        'commit-receipt.json': canonical_bytes({'synthetic': 'commit-receipt.json'}),
    }


@pytest.mark.parametrize(('entry', 'change'), [
    ('directory', 'missing'), ('directory', 'symlink'), ('directory', 'replacement'),
    ('checkpoint', 'missing'), ('checkpoint', 'symlink'), ('checkpoint', 'replacement'),
])
def test_real_reopen_refuses_namespace_drift_and_closes_all_fds(tmp_path, existing_checkpoint, entry, change):
    binding, run, expected = existing_checkpoint
    directory = run/'recovery'
    selected = directory if entry == 'directory' else directory/LEAF
    saved = tmp_path/'saved'
    selected.rename(saved)  # Keep old inode alive even when testing equal-byte replacement.
    if change == 'symlink':
        selected.symlink_to(saved, target_is_directory=entry == 'directory')
    elif change == 'replacement':
        if entry == 'directory':
            selected.mkdir(mode=0o700)
        checkpoint = selected/LEAF if entry == 'directory' else selected
        checkpoint.write_bytes(canonical_bytes(CHECKPOINT))
        checkpoint.chmod(0o600)
    with pytest.raises((OSError, PhaseError)) as failure:
        evidence._open_native_recovery_store(binding, run.name, _expected_commit_checkpoint=expected)
    error = failure.value
    if change == 'missing':
        assert type(error) is FileNotFoundError and not os.path.lexists(selected)
    elif change == 'symlink' and entry == 'directory':
        assert isinstance(error, OSError) and error.errno in (errno.ENOTDIR, errno.ELOOP)
    else:
        assert type(error) is PhaseError and error.code == 'recovery.commit_checkpoint_identity_changed'
    assert not fixture_fds(tmp_path)
    assert not (directory/'native-commit-proof.json').exists() and not (directory/'commit-receipt.json').exists()
    if change == 'symlink':
        assert selected.is_symlink() and selected.readlink() == saved
    elif change == 'replacement':
        replacement = selected/LEAF if entry == 'directory' else selected
        assert replacement.read_bytes() == canonical_bytes(CHECKPOINT)
    preserved = saved/LEAF if entry == 'directory' else saved
    assert preserved.read_bytes() == canonical_bytes(CHECKPOINT)
