"""Owner-only files and directories that actually work on Windows as well as POSIX.

``os.chmod(path, 0o600)`` is a silent no-op on Windows: a file keeps the ACL it inherited from its
directory (typically SYSTEM, Administrators and the user, or wider on shared folders and backup
volumes). This module enforces "readable by the current user only" on both platforms:

- POSIX: 0700 directories and 0600 files, set explicitly so the result does not depend on the umask;
  new files are created with ``O_EXCL`` (and ``O_NOFOLLOW`` where available) so a planted symlink is
  never followed.
- Windows: a *protected* DACL (inheritance from the parent disabled) holding a single ACE that grants
  full control to the SID of the current process token (never derived from environment variables).
  New files and directories are created with that security descriptor already attached (no
  create-then-restrict window); directories carry an inheritable ACE so anything created inside them
  is born owner-only as well. The DACL is always read back to verify it.

Every operation verifies its result. ``InsecurePermissionsError`` is raised when owner-only access
cannot be guaranteed (FAT/exFAT volumes, some network shares, a directory owned by someone else...).
"""

import contextlib
import functools
import logging
import os
import secrets
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterator, List, Optional, Union

logger = logging.getLogger(__name__)

PathLike = Union[str, Path]
BACKEND = 'windows-dacl' if sys.platform == 'win32' else 'posix-mode'

_DIR_MODE = 0o700
_FILE_MODE = 0o600


class InsecurePermissionsError(OSError):
    """Owner-only access could not be applied or verified on a path."""


@dataclass(frozen=True)
class Ace:
    """One access-control entry of a Windows DACL."""

    allowed: bool
    sid: str
    mask: int
    flags: int


@dataclass(frozen=True)
class AclInfo:
    """The parts of a Windows security descriptor that decide who can read a path."""

    owner: Optional[str]
    protected: bool
    aces: List[Ace] = field(default_factory=list)
    null_dacl: bool = False


# --- Windows backend -------------------------------------------------------------------------------

if sys.platform == 'win32':
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    _kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    _TOKEN_QUERY = 0x0008
    _TOKEN_USER = 1
    _TOKEN_OWNER = 4
    _SE_FILE_OBJECT = 1
    _OWNER_SECURITY_INFORMATION = 0x00000001
    _DACL_SECURITY_INFORMATION = 0x00000004
    _PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
    _UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
    _SE_DACL_PRESENT = 0x0004
    _SE_DACL_PROTECTED = 0x1000
    _ACL_SIZE_INFORMATION = 2
    _ACCESS_ALLOWED_ACE_TYPE = 0
    _ACCESS_DENIED_ACE_TYPE = 1
    _SDDL_REVISION_1 = 1
    _GENERIC_WRITE = 0x40000000
    _CREATE_NEW = 1
    _FILE_ATTRIBUTE_NORMAL = 0x80
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _ERROR_FILE_EXISTS = 80
    _ERROR_ALREADY_EXISTS = 183
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ('nLength', wintypes.DWORD),
            ('lpSecurityDescriptor', ctypes.c_void_p),
            ('bInheritHandle', wintypes.BOOL),
        ]

    class _AclSizeInformation(ctypes.Structure):
        _fields_ = [('AceCount', wintypes.DWORD), ('AclBytesInUse', wintypes.DWORD), ('AclBytesFree', wintypes.DWORD)]

    class _AceHeader(ctypes.Structure):
        _fields_ = [('AceType', ctypes.c_ubyte), ('AceFlags', ctypes.c_ubyte), ('AceSize', wintypes.WORD)]

    class _AccessAce(ctypes.Structure):
        # ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE: the SID starts at SidStart and runs to the end of the ACE.
        _fields_ = [('Header', _AceHeader), ('Mask', wintypes.DWORD), ('SidStart', wintypes.DWORD)]

    def _proto(func, restype, *argtypes):
        func.restype = restype
        func.argtypes = list(argtypes)
        return func

    _GetCurrentProcess = _proto(_kernel32.GetCurrentProcess, wintypes.HANDLE)
    _CloseHandle = _proto(_kernel32.CloseHandle, wintypes.BOOL, wintypes.HANDLE)
    _LocalFree = _proto(_kernel32.LocalFree, ctypes.c_void_p, ctypes.c_void_p)
    _CreateFileW = _proto(
        _kernel32.CreateFileW,
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SecurityAttributes),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    _CreateDirectoryW = _proto(
        _kernel32.CreateDirectoryW, wintypes.BOOL, wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)
    )
    _OpenProcessToken = _proto(
        _advapi32.OpenProcessToken, wintypes.BOOL, wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
    )
    _GetTokenInformation = _proto(
        _advapi32.GetTokenInformation,
        wintypes.BOOL,
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    _ConvertSidToStringSidW = _proto(
        _advapi32.ConvertSidToStringSidW, wintypes.BOOL, ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)
    )
    _ConvertStringSDToSD = _proto(
        _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW,
        wintypes.BOOL,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    )
    _GetSecurityDescriptorDacl = _proto(
        _advapi32.GetSecurityDescriptorDacl,
        wintypes.BOOL,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    )
    _GetSecurityDescriptorControl = _proto(
        _advapi32.GetSecurityDescriptorControl,
        wintypes.BOOL,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    )
    _SetNamedSecurityInfoW = _proto(
        _advapi32.SetNamedSecurityInfoW,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    _GetNamedSecurityInfoW = _proto(
        _advapi32.GetNamedSecurityInfoW,
        wintypes.DWORD,
        wintypes.LPCWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    )
    _GetAclInformation = _proto(
        _advapi32.GetAclInformation, wintypes.BOOL, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int
    )
    _GetAce = _proto(_advapi32.GetAce, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p))

    def _check(ok: object, what: str) -> None:
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error(), f'{what} failed')

    def _sid_to_string(psid: object) -> str:
        out = wintypes.LPWSTR()
        _check(_ConvertSidToStringSidW(psid, ctypes.byref(out)), 'ConvertSidToStringSidW')
        try:
            return str(out.value)
        finally:
            _LocalFree(ctypes.cast(out, ctypes.c_void_p))

    def _token_sid(info_class: int) -> str:
        # TOKEN_USER and TOKEN_OWNER both start with a pointer to the SID, inside the same buffer.
        token = wintypes.HANDLE()
        _check(_OpenProcessToken(_GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)), 'OpenProcessToken')
        try:
            needed = wintypes.DWORD()
            _GetTokenInformation(token, info_class, None, 0, ctypes.byref(needed))
            buf = ctypes.create_string_buffer(needed.value)
            _check(_GetTokenInformation(token, info_class, buf, needed, ctypes.byref(needed)), 'GetTokenInformation')
            psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
            return _sid_to_string(psid)
        finally:
            _CloseHandle(token)

    @contextlib.contextmanager
    def _security_descriptor(sddl: str) -> Iterator[ctypes.c_void_p]:
        psd = ctypes.c_void_p()
        _check(
            _ConvertStringSDToSD(sddl, _SDDL_REVISION_1, ctypes.byref(psd), None),
            'ConvertStringSecurityDescriptorToSecurityDescriptorW',
        )
        try:
            yield psd
        finally:
            _LocalFree(psd)

    def _owner_only_sddl(is_dir: bool) -> str:
        # P = protected (no inheritance from the parent); FA = full access; OICI = inherited by children.
        inherit = 'OICI' if is_dir else ''
        return f'D:P(A;{inherit};FA;;;{current_user_sid()})'

    def _apply_sddl(path: PathLike, sddl: str, unprotect: bool = False) -> None:
        with _security_descriptor(sddl) as psd:
            present = wintypes.BOOL()
            defaulted = wintypes.BOOL()
            pdacl = ctypes.c_void_p()
            _check(
                _GetSecurityDescriptorDacl(psd, ctypes.byref(present), ctypes.byref(pdacl), ctypes.byref(defaulted)),
                'GetSecurityDescriptorDacl',
            )
            flags = _DACL_SECURITY_INFORMATION
            flags |= _UNPROTECTED_DACL_SECURITY_INFORMATION if unprotect else _PROTECTED_DACL_SECURITY_INFORMATION
            err = _SetNamedSecurityInfoW(str(path), _SE_FILE_OBJECT, flags, None, None, pdacl, None)
            if err:
                raise ctypes.WinError(err, f'SetNamedSecurityInfoW failed on {path}')

    def _reset_to_inherited(path: PathLike) -> None:
        """Test helper: drop explicit ACEs and the protection so the path inherits its parent's ACL."""
        _apply_sddl(path, 'D:', unprotect=True)

    def _win_read_acl(path: PathLike) -> AclInfo:
        powner = ctypes.c_void_p()
        pdacl = ctypes.c_void_p()
        psd = ctypes.c_void_p()
        err = _GetNamedSecurityInfoW(
            str(path),
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(powner),
            None,
            ctypes.byref(pdacl),
            None,
            ctypes.byref(psd),
        )
        if err:
            raise ctypes.WinError(err, f'GetNamedSecurityInfoW failed on {path}')
        try:
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            _check(
                _GetSecurityDescriptorControl(psd, ctypes.byref(control), ctypes.byref(revision)),
                'GetSecurityDescriptorControl',
            )
            owner = _sid_to_string(powner) if powner.value else None
            protected = bool(control.value & _SE_DACL_PROTECTED)
            if not (control.value & _SE_DACL_PRESENT) or not pdacl.value:
                # No DACL at all = everyone has full access.
                return AclInfo(owner=owner, protected=protected, aces=[], null_dacl=True)
            size = _AclSizeInformation()
            _check(
                _GetAclInformation(pdacl, ctypes.byref(size), ctypes.sizeof(size), _ACL_SIZE_INFORMATION),
                'GetAclInformation',
            )
            aces = []
            for index in range(size.AceCount):
                pace = ctypes.c_void_p()
                _check(_GetAce(pdacl, index, ctypes.byref(pace)), 'GetAce')
                header = ctypes.cast(pace, ctypes.POINTER(_AceHeader)).contents
                if header.AceType not in (_ACCESS_ALLOWED_ACE_TYPE, _ACCESS_DENIED_ACE_TYPE):
                    # Object/callback ACEs: record them so they count against "exactly one ACE".
                    aces.append(Ace(allowed=False, sid=_UNKNOWN_SID, mask=0, flags=header.AceFlags))
                    continue
                ace = ctypes.cast(pace, ctypes.POINTER(_AccessAce)).contents
                psid = ctypes.c_void_p(pace.value + _AccessAce.SidStart.offset)  # type: ignore[operator]
                aces.append(
                    Ace(
                        allowed=header.AceType == _ACCESS_ALLOWED_ACE_TYPE,
                        sid=_sid_to_string(psid),
                        mask=int(ace.Mask),
                        flags=int(header.AceFlags),
                    )
                )
            return AclInfo(owner=owner, protected=protected, aces=aces)
        finally:
            _LocalFree(psd)

    def _win_create_dir(path: Path) -> None:
        with _security_descriptor(_owner_only_sddl(is_dir=True)) as psd:
            sa = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), psd, False)
            if not _CreateDirectoryW(str(path), ctypes.byref(sa)):
                err = ctypes.get_last_error()
                if err == _ERROR_ALREADY_EXISTS:
                    raise FileExistsError(err, 'already exists', str(path))
                raise ctypes.WinError(err, f'CreateDirectoryW failed on {path}')

    def _win_create_file(path: Path) -> int:
        with _security_descriptor(_owner_only_sddl(is_dir=False)) as psd:
            sa = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), psd, False)
            handle = _CreateFileW(
                str(path),
                _GENERIC_WRITE,
                0,  # no sharing while we write
                ctypes.byref(sa),
                _CREATE_NEW,  # fails if the name exists, symlink or not
                _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
            if handle is None or handle == _INVALID_HANDLE_VALUE:
                err = ctypes.get_last_error()
                if err in (_ERROR_FILE_EXISTS, _ERROR_ALREADY_EXISTS):
                    raise FileExistsError(err, 'already exists', str(path))
                raise ctypes.WinError(err, f'CreateFileW failed on {path}')
        try:
            return msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
        except BaseException:
            _CloseHandle(handle)
            raise


# --- public API ------------------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def current_user_sid() -> str:
    """Return the SID of the user the current process runs as (Windows only, read from the process token)."""
    if sys.platform == 'win32':
        return _token_sid(_TOKEN_USER)
    raise NotImplementedError('SIDs only exist on Windows')


@functools.lru_cache(maxsize=1)
def _token_owner_sid() -> str:
    # Default owner of new objects: the user, or BUILTIN\Administrators for elevated admin tokens.
    if sys.platform == 'win32':
        return _token_sid(_TOKEN_OWNER)
    raise NotImplementedError('SIDs only exist on Windows')


def read_acl(path: PathLike) -> AclInfo:
    """Return the owner, protection flag and ACEs of ``path`` (Windows only)."""
    if sys.platform == 'win32':
        return _win_read_acl(path)
    raise NotImplementedError('DACLs only exist on Windows')


def is_owner_only(path: PathLike) -> bool:
    """True if ``path`` exists and only the current user can access it."""
    try:
        if sys.platform == 'win32':
            acl = _win_read_acl(path)
            if acl.null_dacl or not acl.protected or len(acl.aces) != 1:
                return False
            ace = acl.aces[0]
            # Whoever owns the object can always rewrite its DACL: it must be us.
            owner_ok = acl.owner in (current_user_sid(), _token_owner_sid())
            return ace.allowed and ace.sid == current_user_sid() and owner_ok
        st = os.stat(path)
        expected = _DIR_MODE if stat.S_ISDIR(st.st_mode) else _FILE_MODE
        return st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == expected
    except OSError:
        return False


_UNKNOWN_SID = '?'
_INHERIT_ONLY_ACE = 0x08


def grants_only_current_user(path: PathLike) -> bool:
    """True if ``path`` exists and no account other than the current user is granted access to it.

    Weaker than ``is_owner_only``: on Windows it also accepts an allow ACE for the current user that
    was *inherited* from a secured parent (the normal state of files created inside a ``secure_dir``),
    rather than requiring a protected DACL of its own.
    """
    try:
        if sys.platform == 'win32':
            acl = _win_read_acl(path)
            if acl.null_dacl or acl.owner not in (current_user_sid(), _token_owner_sid()):
                return False
            effective = [ace for ace in acl.aces if not ace.flags & _INHERIT_ONLY_ACE]
            if any(ace.sid == _UNKNOWN_SID for ace in effective):
                return False  # object/callback ACE we cannot interpret: assume it grants access
            allowed = [ace for ace in effective if ace.allowed]
            return bool(allowed) and all(ace.sid == current_user_sid() for ace in allowed)
        st = os.stat(path)
        return st.st_uid == os.geteuid() and not stat.S_IMODE(st.st_mode) & 0o077
    except OSError:
        return False


def _apply_owner_only(path: PathLike, is_dir: bool) -> None:
    """Restrict an existing path to the current user (no verification: see _enforce)."""
    if sys.platform == 'win32':
        _apply_sddl(path, _owner_only_sddl(is_dir))
    else:
        os.chmod(path, _DIR_MODE if is_dir else _FILE_MODE)


def _enforce(path: Path, is_dir: bool) -> None:
    if is_owner_only(path):
        return
    try:
        _apply_owner_only(path, is_dir)
    except OSError as e:
        raise InsecurePermissionsError(f'cannot restrict {path} to the current user: {e}') from e
    if not is_owner_only(path):
        raise InsecurePermissionsError(
            f'cannot guarantee owner-only access to {path} '
            '(filesystem without ACL support, network share, or path owned by another account?)'
        )


def _mkdir_private(path: Path) -> None:
    if sys.platform == 'win32':
        _win_create_dir(path)
    else:
        os.mkdir(path, _DIR_MODE)


def _make_missing_dirs(path: Path) -> List[Path]:
    """Create the missing components of ``path`` owner-only from birth; return the ones created."""
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    created = []
    for directory in reversed(missing):
        try:
            _mkdir_private(directory)
        except FileExistsError:
            continue  # created concurrently: it is not ours, leave it as found
        created.append(directory)
    return created


def secure_dir(path: PathLike) -> Path:
    """Create ``path`` (and missing parents) owner-only, re-securing the leaf if it already exists.

    Raises:
        InsecurePermissionsError: If owner-only access cannot be applied and verified.
    """
    path = Path(path).expanduser()
    for created in _make_missing_dirs(path):
        _enforce(created, is_dir=True)
    if not path.is_dir():
        raise InsecurePermissionsError(f'{path} is not a directory')
    _enforce(path, is_dir=True)
    return path


def _is_link(path: str) -> bool:
    is_junction = getattr(os.path, 'isjunction', None)  # Python 3.12+
    return os.path.islink(path) or bool(is_junction and is_junction(path))


def secure_tree(path: PathLike) -> Path:
    """``secure_dir`` plus a repair pass over what already exists inside ``path``.

    On POSIX a 0700 root already stops other accounts from traversing it, but on Windows it does not:
    "bypass traverse checking" lets any account open a file by its full path regardless of the
    directory's ACL. So every descendant that grants access to another account is re-secured on both
    platforms (defence in depth on POSIX). Symlinks and junctions are skipped, never followed.

    Raises:
        InsecurePermissionsError: If the root or a descendant cannot be made owner-only.
    """
    root = secure_dir(path)
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if not _is_link(os.path.join(current, d))]
        for name, is_dir in [(d, True) for d in dirs] + [(f, False) for f in files]:
            child = os.path.join(current, name)
            if is_dir or not _is_link(child):
                if not grants_only_current_user(child):
                    _enforce(Path(child), is_dir=is_dir)
    return root


def secure_file(path: PathLike) -> Path:
    """Restrict an existing regular file to the current user and verify it.

    Raises:
        InsecurePermissionsError: If owner-only access cannot be applied and verified.
    """
    path = Path(path)
    if not path.is_file():
        raise InsecurePermissionsError(f'{path} is not a regular file')
    _enforce(path, is_dir=False)
    return path


def _create_exclusive_fd(path: Path) -> int:
    if sys.platform == 'win32':
        return _win_create_file(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(path, flags, _FILE_MODE)
    try:
        os.fchmod(fd, _FILE_MODE)  # the umask may have removed bits from the mode passed to open()
    except BaseException:
        os.close(fd)
        raise
    return fd


def create_private_exclusive(path: PathLike) -> BinaryIO:
    """Create a new owner-only file and return it open for binary writing.

    The file is born owner-only (no window in which another account can open it). The parent
    directory is not modified: secure it first with ``secure_dir`` when it is the tool's own.

    Raises:
        FileExistsError: If anything (including a dangling symlink) already exists at ``path``.
        InsecurePermissionsError: If owner-only access cannot be verified; the file is removed.
    """
    path = Path(path)
    fd = _create_exclusive_fd(path)
    handle = os.fdopen(fd, 'wb')
    try:
        _enforce(path, is_dir=False)
    except BaseException:
        handle.close()
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise
    return handle


def write_private(path: PathLike, data: Union[str, bytes], *, strict: bool = True) -> Path:
    """Atomically write ``data`` (str is encoded as UTF-8) to an owner-only file.

    The content goes to a temporary file created owner-only in the same directory, is flushed to
    disk and then moved over ``path`` with os.replace: readers never see a partial file, and an
    existing symlink at ``path`` is replaced rather than followed. Directories that have to be
    created are owner-only; pre-existing ones (possibly the user's working directory) are left
    untouched, since the file itself never relies on inheritance.

    Args:
        path: Destination file.
        data: Text or bytes to write.
        strict: If False, a destination where owner-only cannot be verified (e.g. a FAT32 USB stick)
            is written anyway with a warning instead of raising.

    Raises:
        InsecurePermissionsError: In strict mode, if owner-only access cannot be guaranteed.
    """
    path = Path(path)
    payload = data.encode('utf-8') if isinstance(data, str) else data
    for created in _make_missing_dirs(path.parent):
        _enforce(created, is_dir=True)
    tmp = path.parent / f'.{path.name}.{secrets.token_hex(8)}.tmp'
    try:
        try:
            with create_private_exclusive(tmp) as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
        except InsecurePermissionsError:
            if strict:
                raise
            _write_plain(tmp, payload)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    try:
        _enforce(path, is_dir=False)  # rename keeps the DACL; re-apply and verify on the final name anyway
    except InsecurePermissionsError:
        if strict:
            with contextlib.suppress(OSError):
                os.unlink(path)  # fail closed: do not leave target data behind with unknown permissions
            raise
        logger.warning('Could not make %s owner-only: it may be readable by other accounts', path)
    return path


def _write_plain(path: Path, payload: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(fd, 'wb') as f:
        f.write(payload)
