import os
import stat
import subprocess
import sys

import pytest

from secure_osint.utils import secure_fs
from secure_osint.utils.secure_fs import InsecurePermissionsError
from tests.owner_only import assert_owner_only, make_permissive

windows_only = pytest.mark.skipif(os.name != 'nt', reason='Windows DACL behaviour')
posix_only = pytest.mark.skipif(os.name == 'nt', reason='POSIX mode-bit behaviour')


def _break_enforcement(monkeypatch):
    """Simulate a filesystem where owner-only cannot be applied (FAT32, SMB share, foreign owner...)."""
    monkeypatch.setattr(secure_fs, '_apply_owner_only', lambda path, is_dir: None)
    monkeypatch.setattr(secure_fs, 'is_owner_only', lambda path: False)


# --- secure_dir ---


def test_secure_dir_creates_nested_owner_only_directories(tmp_path):
    target = tmp_path / 'a' / 'b' / 'c'
    assert secure_fs.secure_dir(target) == target
    assert target.is_dir()
    for created in (tmp_path / 'a', tmp_path / 'a' / 'b', target):
        assert_owner_only(created)


def test_secure_dir_resecures_an_existing_permissive_directory(tmp_path):
    target = tmp_path / 'existing'
    target.mkdir()
    make_permissive(target)
    secure_fs.secure_dir(target)
    assert_owner_only(target)


def test_secure_dir_fails_closed(tmp_path, monkeypatch):
    _break_enforcement(monkeypatch)
    target = tmp_path / 'existing'
    target.mkdir()
    make_permissive(target)
    with pytest.raises(InsecurePermissionsError):
        secure_fs.secure_dir(target)


def test_secure_dir_rejects_a_file(tmp_path):
    target = tmp_path / 'file'
    target.write_text('x', encoding='utf-8')
    with pytest.raises(InsecurePermissionsError):
        secure_fs.secure_dir(target)


@windows_only
def test_files_created_inside_a_secured_directory_inherit_owner_only(tmp_path):
    # Closes the create-then-restrict race: even a plain open() is born with the owner-only ACE.
    directory = secure_fs.secure_dir(tmp_path / 'private')
    inner = directory / 'plain.txt'
    inner.write_text('x', encoding='utf-8')
    acl = secure_fs.read_acl(inner)
    assert [ace.sid for ace in acl.aces] == [secure_fs.current_user_sid()]


# --- write_private ---


def test_write_private_text_is_utf8_and_owner_only(tmp_path):
    out = tmp_path / 'r.md'
    assert secure_fs.write_private(out, 'città — ✓') == out
    assert out.read_bytes() == 'città — ✓'.encode('utf-8')
    assert_owner_only(out)


def test_write_private_bytes(tmp_path):
    out = tmp_path / 'blob.bin'
    secure_fs.write_private(out, b'\x00\x81\xff')
    assert out.read_bytes() == b'\x00\x81\xff'
    assert_owner_only(out)


def test_write_private_replaces_a_permissive_file_and_leaves_no_temp_files(tmp_path):
    out = tmp_path / 'r.json'
    out.write_text('old', encoding='utf-8')
    make_permissive(out)
    secure_fs.write_private(out, 'new')
    assert out.read_text(encoding='utf-8') == 'new'
    assert_owner_only(out)
    assert sorted(p.name for p in tmp_path.iterdir()) == ['r.json']


def test_write_private_secures_directories_it_creates(tmp_path):
    out = tmp_path / 'reports' / 'gui' / 'run' / 'latest.json'
    secure_fs.write_private(out, '{}')
    for created in (tmp_path / 'reports', tmp_path / 'reports' / 'gui', out.parent):
        assert_owner_only(created)


@posix_only
def test_write_private_does_not_change_a_pre_existing_user_directory(tmp_path):
    # The output directory may be the user's cwd: the file is born owner-only, the directory is left alone.
    os.chmod(tmp_path, 0o755)
    secure_fs.write_private(tmp_path / 'r.json', '{}')
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o755


def test_write_private_removes_the_temp_file_when_replace_fails(tmp_path, monkeypatch):
    def boom(src, dst):
        raise OSError('disk full')

    monkeypatch.setattr(secure_fs.os, 'replace', boom)
    with pytest.raises(OSError):
        secure_fs.write_private(tmp_path / 'r.json', '{}')
    assert list(tmp_path.iterdir()) == []


@posix_only
def test_write_private_replaces_a_symlink_instead_of_following_it(tmp_path):
    victim = tmp_path / 'victim'
    victim.write_text('untouched', encoding='utf-8')
    link = tmp_path / 'r.json'
    link.symlink_to(victim)
    secure_fs.write_private(link, 'report')
    assert victim.read_text(encoding='utf-8') == 'untouched'
    assert not link.is_symlink() and link.read_text(encoding='utf-8') == 'report'


@posix_only
def test_write_private_is_umask_independent(tmp_path):
    old = os.umask(0o277)
    try:
        secure_fs.write_private(tmp_path / 'r.json', '{}')
    finally:
        os.umask(old)
    assert_owner_only(tmp_path / 'r.json')


def test_write_private_strict_fails_closed(tmp_path, monkeypatch):
    _break_enforcement(monkeypatch)
    with pytest.raises(InsecurePermissionsError):
        secure_fs.write_private(tmp_path / 'r.json', '{}')


def test_write_private_non_strict_warns_but_writes(tmp_path, monkeypatch, caplog):
    _break_enforcement(monkeypatch)
    out = tmp_path / 'r.json'
    secure_fs.write_private(out, '{}', strict=False)
    assert out.read_text(encoding='utf-8') == '{}'
    assert 'owner-only' in caplog.text


# --- create_private_exclusive ---


def test_create_private_exclusive_creates_owner_only(tmp_path):
    path = tmp_path / 'cache.key'
    with secure_fs.create_private_exclusive(path) as f:
        f.write(b'secret')
    assert path.read_bytes() == b'secret'
    assert_owner_only(path)


def test_create_private_exclusive_refuses_existing_file(tmp_path):
    path = tmp_path / 'cache.key'
    path.write_bytes(b'existing')
    with pytest.raises(FileExistsError):
        secure_fs.create_private_exclusive(path)
    assert path.read_bytes() == b'existing'


@posix_only
def test_create_private_exclusive_refuses_dangling_symlink(tmp_path):
    path = tmp_path / 'cache.key'
    path.symlink_to(tmp_path / 'elsewhere')
    with pytest.raises(FileExistsError):
        secure_fs.create_private_exclusive(path)
    assert not (tmp_path / 'elsewhere').exists()


def test_create_private_exclusive_fails_closed_and_removes_the_file(tmp_path, monkeypatch):
    _break_enforcement(monkeypatch)
    path = tmp_path / 'cache.key'
    with pytest.raises(InsecurePermissionsError):
        secure_fs.create_private_exclusive(path)
    assert not path.exists()


# --- secure_file / is_owner_only ---


def test_secure_file_restricts_an_existing_file(tmp_path):
    path = tmp_path / '.env'
    path.write_text('A=1', encoding='utf-8')
    make_permissive(path)
    secure_fs.secure_file(path)
    assert_owner_only(path)
    assert path.read_text(encoding='utf-8') == 'A=1'


def test_is_owner_only_is_false_for_missing_path(tmp_path):
    assert secure_fs.is_owner_only(tmp_path / 'missing') is False


@windows_only
def test_is_owner_only_rejects_an_extra_ace(tmp_path):
    path = tmp_path / 'f'
    path.write_text('x', encoding='utf-8')
    secure_fs.secure_file(path)
    # Add Everyone:R next to the owner ACE: still protected, but no longer owner-only.
    secure_fs._apply_sddl(path, f'D:P(A;;FA;;;{secure_fs.current_user_sid()})(A;;FR;;;WD)')
    assert secure_fs.is_owner_only(path) is False


@windows_only
def test_current_user_sid_comes_from_the_process_token(monkeypatch):
    expected = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'], capture_output=True, text=True, check=True)
    sid = expected.stdout.strip().split(',')[-1].strip('"')
    for var in ('USERNAME', 'USERDOMAIN', 'USERPROFILE'):
        monkeypatch.setenv(var, 'attacker')
    secure_fs.current_user_sid.cache_clear()
    assert secure_fs.current_user_sid() == sid
    assert sid.startswith('S-1-5-')


@windows_only
def test_current_user_sid_is_not_derived_from_environment(monkeypatch):
    secure_fs.current_user_sid.cache_clear()
    monkeypatch.setenv('USERNAME', 'Administrator')
    monkeypatch.setenv('USERDOMAIN', 'EVIL')
    sid = secure_fs.current_user_sid()
    secure_fs.current_user_sid.cache_clear()
    monkeypatch.delenv('USERNAME')
    monkeypatch.delenv('USERDOMAIN')
    assert secure_fs.current_user_sid() == sid


# --- grants_only_current_user / secure_tree ---


def test_grants_only_current_user_accepts_owner_only_paths(tmp_path):
    out = secure_fs.write_private(tmp_path / 'f', 'x')
    assert secure_fs.grants_only_current_user(out) is True
    assert secure_fs.grants_only_current_user(secure_fs.secure_dir(tmp_path / 'd')) is True


def test_grants_only_current_user_rejects_permissive_and_missing_paths(tmp_path):
    path = tmp_path / 'f'
    path.write_text('x', encoding='utf-8')
    make_permissive(path)
    assert secure_fs.grants_only_current_user(path) is False
    assert secure_fs.grants_only_current_user(tmp_path / 'missing') is False


@windows_only
def test_grants_only_current_user_accepts_an_ace_inherited_from_a_secured_directory(tmp_path):
    directory = secure_fs.secure_dir(tmp_path / 'private')
    inner = directory / 'plain.txt'
    inner.write_text('x', encoding='utf-8')
    assert secure_fs.is_owner_only(inner) is False  # not protected: strictly speaking not ours alone
    assert secure_fs.grants_only_current_user(inner) is True  # but nobody else is granted access


@windows_only
def test_grants_only_current_user_rejects_an_extra_ace(tmp_path):
    path = tmp_path / 'f'
    path.write_text('x', encoding='utf-8')
    secure_fs._apply_sddl(path, f'D:P(A;;FA;;;{secure_fs.current_user_sid()})(A;;FR;;;WD)')
    assert secure_fs.grants_only_current_user(path) is False


def test_secure_tree_secures_root_and_repairs_children(tmp_path):
    root = tmp_path / 'cache'
    (root / 'sub').mkdir(parents=True)
    leaked = root / 'sub' / 'entry.val'
    leaked.write_text('x', encoding='utf-8')
    make_permissive(root)
    if os.name == 'nt':
        # An explicit, protected Everyone ACE does not go away when the root is re-secured.
        secure_fs._apply_sddl(leaked, f'D:P(A;;FA;;;{secure_fs.current_user_sid()})(A;;FR;;;WD)')
    assert secure_fs.secure_tree(root) == root
    assert_owner_only(root)
    assert secure_fs.grants_only_current_user(leaked)
    assert secure_fs.grants_only_current_user(root / 'sub')


def test_secure_tree_fails_closed(tmp_path, monkeypatch):
    _break_enforcement(monkeypatch)
    with pytest.raises(InsecurePermissionsError):
        secure_fs.secure_tree(tmp_path / 'cache')


def test_platform_backend_is_the_expected_one():
    assert secure_fs.BACKEND == ('windows-dacl' if sys.platform == 'win32' else 'posix-mode')
