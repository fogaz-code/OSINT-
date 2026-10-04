"""Cross-platform assertion that a path is readable by its owner only.

POSIX: the exact mode bits (0700 for directories, 0600 for files) and the owner uid.
Windows: os.chmod is a no-op there, so the DACL is read back instead: it must be protected (no
inheritance from the parent) and hold exactly one allow ACE, for the SID of the current process token.
"""

import os
import stat
import sys
from pathlib import Path
from typing import Union

from secure_osint.utils import secure_fs


def assert_owner_only(path: Union[str, Path]) -> None:
    """Fail unless ``path`` is accessible by the current user only."""
    path = Path(path)
    if sys.platform == 'win32':  # sys.platform (not os.name) so mypy narrows per platform
        acl = secure_fs.read_acl(path)
        assert acl.protected, f'{path}: DACL still inherits from the parent directory'
        assert len(acl.aces) == 1, f'{path}: expected exactly one ACE, got {acl.aces}'
        ace = acl.aces[0]
        assert ace.allowed, f'{path}: the only ACE is not an allow ACE: {ace}'
        assert ace.sid == secure_fs.current_user_sid(), f'{path}: ACE is for {ace.sid}, not the current user'
        return
    st = os.stat(path)
    assert st.st_uid == os.geteuid(), f'{path}: owned by uid {st.st_uid}'
    expected = 0o700 if stat.S_ISDIR(st.st_mode) else 0o600
    assert stat.S_IMODE(st.st_mode) == expected, f'{path}: mode {stat.S_IMODE(st.st_mode):o} != {expected:o}'


def make_permissive(path: Union[str, Path]) -> None:
    """Make an existing file/directory readable by others (the state secure_fs must repair)."""
    path = Path(path)
    if sys.platform == 'win32':
        # Inherit the parent's ACL again AND grant Everyone read explicitly: readable by others even when
        # the parent is itself owner-only.
        secure_fs._reset_to_inherited(path)
        secure_fs._apply_sddl(path, 'D:(A;;FR;;;WD)', unprotect=True)
    else:
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
    assert not secure_fs.is_owner_only(path)
    assert not secure_fs.grants_only_current_user(path)
