import hashlib
import ipaddress
import os
import re
import stat
from typing import Optional

from secure_osint.security.input_sanitizer import normalize_domain
from secure_osint.utils.keccak import keccak256

# Formats exifread can read metadata from (TIFF-based RAW formats included). GIF/BMP carry no EXIF.
IMAGE_EXTENSIONS = frozenset(
    {
        '.jpg',
        '.jpeg',
        '.jpe',
        '.jfif',
        '.tif',
        '.tiff',
        '.png',
        '.webp',
        '.heic',
        '.heif',
        '.jxl',
        '.dng',
        '.cr2',
        '.nef',
        '.nrw',
        '.arw',
        '.orf',
        '.rw2',
        '.pef',
        '.srw',
    }
)

_B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}
_B58_ADDRESS = re.compile(r'[1-9A-HJ-NP-Za-km-z]{25,35}')
_BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3
_ETH_ADDRESS = re.compile(r'0x[0-9a-fA-F]{40}')

_BTC_VERSIONS = (0x00, 0x05)  # mainnet P2PKH, P2SH
_TRON_VERSION = 0x41


def _b58check_decode(value: str) -> Optional[bytes]:
    """Decode a Base58Check string and return its payload (version byte included), or None."""
    if not _B58_ADDRESS.fullmatch(value):
        return None
    number = 0
    for char in value:
        number = number * 58 + _B58_INDEX[char]
    pad = len(value) - len(value.lstrip('1'))
    raw = b'\x00' * pad + (number.to_bytes((number.bit_length() + 7) // 8, 'big') if number else b'')
    if len(raw) < 5:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        return None
    return payload


def _bech32_polymod(values: list) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if (top >> i) & 1 else 0
    return chk


def _convert_bits(data: list, from_bits: int, to_bits: int) -> Optional[list]:
    """Regroup 5-bit words into bytes without padding (BIP-173 decoding rules)."""
    acc = 0
    bits = 0
    out = []
    maxv = (1 << to_bits) - 1
    for value in data:
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            out.append((acc >> bits) & maxv)
    if bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        return None
    return out


def _is_segwit_address(value: str, hrp: str = 'bc') -> bool:
    """BIP-173 (bech32, witness v0) / BIP-350 (bech32m, witness v1+) mainnet address check."""
    if len(value) > 90 or (value.lower() != value and value.upper() != value):
        return False
    value = value.lower()
    sep = value.rfind('1')
    if value[:sep] != hrp or len(value) - sep - 1 < 7:
        return False
    try:
        data = [_BECH32_CHARSET.index(c) for c in value[sep + 1 :]]
    except ValueError:
        return False
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    const = _bech32_polymod(expanded + data)
    if const not in (_BECH32_CONST, _BECH32M_CONST):
        return False
    version = data[0]
    program = _convert_bits(data[1:-6], 5, 8)
    if version > 16 or program is None or not 2 <= len(program) <= 40:
        return False
    if version == 0:
        return const == _BECH32_CONST and len(program) in (20, 32)
    return const == _BECH32M_CONST


def is_btc_address(value: str) -> bool:
    """True for a checksum-valid Bitcoin mainnet address (P2PKH, P2SH, bech32 or bech32m)."""
    if value[:3].lower() == 'bc1':
        return _is_segwit_address(value)
    if value[:1] not in ('1', '3'):
        return False
    payload = _b58check_decode(value)
    return payload is not None and len(payload) == 21 and payload[0] in _BTC_VERSIONS


def is_tron_address(value: str) -> bool:
    """True for a checksum-valid TRON address (``T`` + Base58Check, version byte 0x41)."""
    if len(value) != 34 or not value.startswith('T'):
        return False
    payload = _b58check_decode(value)
    return payload is not None and len(payload) == 21 and payload[0] == _TRON_VERSION


def is_eth_address(value: str) -> bool:
    """True for ``0x`` + 40 hex digits; a mixed-case address must also pass its EIP-55 checksum."""
    if not _ETH_ADDRESS.fullmatch(value):
        return False
    body = value[2:]
    if body.lower() == body or body.upper() == body:
        return True  # no checksum encoded
    digest = keccak256(body.lower().encode('ascii')).hex()
    return all(c.isdigit() or (c.isupper() == (int(digest[i], 16) >= 8)) for i, c in enumerate(body))


def wallet_chain(value: str) -> Optional[str]:
    """Return ``'btc'``, ``'eth'`` or ``'tron'`` for a valid wallet address, else ``None``."""
    value = (value or '').strip()
    if len(value) > 90:
        return None
    if is_eth_address(value):
        return 'eth'
    if is_tron_address(value):
        return 'tron'
    if is_btc_address(value):
        return 'btc'
    return None


def is_unc_path(value: str) -> bool:
    """True for UNC / device paths (``\\\\host\\share``, ``//host/share``, ``\\\\?\\``, ``\\\\.\\pipe``).

    A stat() or open() on such a path makes Windows open an SMB session to an arbitrary host and send
    the user's NTLM credentials (or talk to a named pipe): never touch the filesystem for these inputs.
    Windows accepts either separator in any mix (``\\/host/share``, ``/\\host\\share``) and the NT
    object-manager prefix ``\\??\\UNC\\host``, so separators are normalised before checking.
    """
    s = value.lstrip().replace('/', '\\')
    return s.startswith(('\\\\', '\\??\\'))


def is_local_image_file(value: str) -> bool:
    """True if ``value`` names an existing local regular file with an image extension.

    Cheap and side-effect free: only an extension match triggers a single ``stat``; network paths are
    rejected without any filesystem access.
    """
    if is_unc_path(value) or os.path.splitext(value)[1].lower() not in IMAGE_EXTENSIONS:
        return False
    try:
        return stat.S_ISREG(os.stat(value).st_mode)
    except (OSError, ValueError):
        return False


def detect_input_type(input_str: str, allow_files: bool = True) -> str:
    """Classify a raw input string.

    Args:
        input_str: The user-supplied target.
        allow_files: When False, never touch the filesystem, so a path is never ``image_file``. Use it to
            re-classify a target after the run, or for input from someone other than the local user.

    Returns:
        One of: url, image_file, phone, email, ipv4, ipv6, github_repo, domain, wallet, username, generic.

    Raises:
        ValueError: If the input is empty.
    """
    s = (input_str or '').strip()
    if not s:
        raise ValueError('Input cannot be empty.')
    if re.fullmatch(r'https?://\S+', s, re.IGNORECASE):
        return 'url'
    # Before github_repo/domain: 'pics/a.png' and 'photo.jpg' match those patterns too.
    if allow_files and is_local_image_file(s):
        return 'image_file'
    # Telefono in forma E.164: '+' seguito da 8-15 cifre (separatori spazio/-/./() ammessi).
    if s.startswith('+'):
        digits = re.sub(r'[\s().-]', '', s)
        if re.fullmatch(r'\+\d{8,15}', digits):
            return 'phone'
    if re.fullmatch(r'[A-Za-z0-9._%+-]+@[^@\s]+\.[^@\s]{2,}', s):
        return 'email'
    try:
        return 'ipv4' if ipaddress.ip_address(s).version == 4 else 'ipv6'
    except ValueError:
        pass
    if re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', s):
        return 'github_repo'
    if '.' in s:
        try:
            normalize_domain(s)
            return 'domain'
        except ValueError:
            pass
    # Before username: a 26-30 char Base58 address also matches the username pattern. The checksum
    # makes a false positive on a real username practically impossible (1 in 2^32).
    if wallet_chain(s):
        return 'wallet'
    # Nota: 'john.doe' è anche un dominio sintatticamente valido e viene classificato come tale;
    # per forzare lo username usare --workflow username.
    if re.fullmatch(r'[A-Za-z0-9_]{3,30}', s):
        return 'username'
    return 'generic'
