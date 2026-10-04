"""Pure-Python Keccak-256 (the pre-NIST padding Ethereum uses).

``hashlib.sha3_256`` is NOT a substitute: FIPS-202 SHA-3 pads with ``0x06`` while Ethereum's Keccak
pads with ``0x01``, so the digests differ. Only used to verify EIP-55 address checksums (a few dozen
bytes per call), so a dependency-free implementation is fast enough and keeps the core install small.
"""

from typing import List

_MASK = (1 << 64) - 1
_RATE = 136  # bytes: 1600-bit state minus 2 * 256-bit capacity

_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)

# Rotation offsets r[x][y] of the rho step.
_ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rotl(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _keccak_f(state: List[int]) -> None:
    """Apply the Keccak-f[1600] permutation in place. ``state[x + 5 * y]`` is lane (x, y)."""
    for rc in _ROUND_CONSTANTS:
        # theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for i in range(25):
            state[i] ^= d[i % 5]
        # rho + pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(state[x + 5 * y], _ROTATIONS[x][y])
        # chi
        for y in range(0, 25, 5):
            row = b[y : y + 5]
            for x in range(5):
                state[y + x] = row[x] ^ (~row[(x + 1) % 5] & row[(x + 2) % 5])
        # iota
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Return the 32-byte Keccak-256 digest of ``data`` (Ethereum flavour)."""
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b'\x00' * (-len(padded) % _RATE))
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), _RATE):
        block = padded[offset : offset + _RATE]
        for i in range(_RATE // 8):
            state[i] ^= int.from_bytes(block[8 * i : 8 * i + 8], 'little')
        _keccak_f(state)
    return b''.join(lane.to_bytes(8, 'little') for lane in state[:4])
