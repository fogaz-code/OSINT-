"""Offline EXIF/XMP metadata extraction from a local image file (source ``image_exif``, contract C5).

Strictly offline: no network access, nothing is uploaded anywhere (pixel-based geolocation services are
deliberately out of scope). The file is treated as hostile input:

* the path must name an existing local regular file (no UNC/network paths, devices, FIFOs or dirs);
* the file is read once, capped at ``MAX_FILE_BYTES``; hash and parsers see exactly the same bytes;
* exifread parses it (pure Python, no pixel decoding, ``details=False``) through a reader with an
  operation budget, so crafted IFD fan-out cannot turn into minutes of CPU, and the step deadline is
  honoured from inside the parser;
* the XMP packet is size-capped and parsed only with defusedxml with DTDs forbidden (no XXE, no
  entity expansion); a hostile or broken packet becomes a warning, the EXIF evidence is still returned;
* every parser failure surfaces as ``SourceUnavailable``, never as a raw exception;
* metadata strings are stripped of control characters (terminal escape injection via EXIF fields).
"""

import hashlib
import io
import logging
import math
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from secure_osint.core.validator import is_unc_path
from secure_osint.sources.base import BaseSource, SourceError, SourceUnavailable
from secure_osint.sources.registry import register_source
from secure_osint.utils.deadline import clamp_timeout

MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_XMP_BYTES = 1024 * 1024
# read()/seek() calls allowed to exifread for one file. A normal photo needs ~150; the cap only stops
# hostile structures (e.g. an IFD repeating a GPS pointer thousands of times, each re-walking the GPS IFD).
READ_BUDGET = 100_000
_DEADLINE_CHECK_EVERY = 256

MAX_TEXT = 1024
MAX_XMP_PROPERTIES = 200
MAX_XMP_LIST = 100
MAX_XMP_DEPTH = 8

INSTALL_HINT = 'install secure-osint[image]'
NO_EXIF_WARNING = 'no EXIF metadata (commonly stripped by social platforms)'

# exifread logs one warning per corrupt field it meets; a hostile file could flood the logs with them.
logging.getLogger('exifread').setLevel(logging.ERROR)

_CONTROL_CHARS = re.compile(r'[\x00-\x1f\x7f-\x9f]')
_EXIF_DATETIME = re.compile(r'(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})')
_EXIF_DATE = re.compile(r'(\d{4}):(\d{2}):(\d{2})')
_UTC_OFFSET = re.compile(r'[+-](?:[01]\d|2[0-3]):[0-5]\d|Z')
_XMP_COORD = re.compile(r'(\d{1,3}),(\d{1,2}(?:\.\d+)?)(?:,(\d{1,2}(?:\.\d+)?))?([NSEWnsew])')
_XMLNS = re.compile(r'xmlns:([A-Za-z_][\w.-]*)\s*=\s*["\']([^"\']{1,512})["\']')

_RDF = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#'
_XML = 'http://www.w3.org/XML/1998/namespace'
_RDF_CONTAINERS = {f'{{{_RDF}}}Seq', f'{{{_RDF}}}Bag', f'{{{_RDF}}}Alt'}
# XMP properties that name or measure a place (Lightroom/IPTC reverse geocoding, photoshop:City,
# DJI drone altitude). Matched on the local name; reported under 'xmp_location' (a C3 location key).
_XMP_PLACE_NAMES = frozenset(
    {
        'location',
        'sublocation',
        'city',
        'state',
        'provincestate',
        'country',
        'countryname',
        'countrycode',
        'locationcreated',
        'locationshown',
        'worldregion',
    }
)


def _is_xmp_place_key(key: str) -> bool:
    local = key.rsplit(':', 1)[-1].lower()
    return local in _XMP_PLACE_NAMES or local.endswith('altitude')


_KNOWN_PREFIXES = {
    'http://purl.org/dc/elements/1.1/': 'dc',
    'http://ns.adobe.com/xap/1.0/': 'xmp',
    'http://ns.adobe.com/xap/1.0/mm/': 'xmpMM',
    'http://ns.adobe.com/xap/1.0/rights/': 'xmpRights',
    'http://ns.adobe.com/xap/1.0/sType/ResourceEvent#': 'stEvt',
    'http://ns.adobe.com/xap/1.0/sType/ResourceRef#': 'stRef',
    'http://ns.adobe.com/exif/1.0/': 'exif',
    'http://cipa.jp/exif/1.0/': 'exifEX',
    'http://ns.adobe.com/exif/1.0/aux/': 'aux',
    'http://ns.adobe.com/tiff/1.0/': 'tiff',
    'http://ns.adobe.com/photoshop/1.0/': 'photoshop',
    'http://ns.adobe.com/camera-raw-settings/1.0/': 'crs',
    'http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/': 'Iptc4xmpCore',
    'http://iptc.org/std/Iptc4xmpExt/2008-02-29/': 'Iptc4xmpExt',
    'http://ns.google.com/photos/1.0/camera/': 'GCamera',
    'http://ns.google.com/photos/1.0/image/': 'GImage',
}

# exifread key names. 0xC62F (DNG CameraSerialNumber) has no name in exifread's tables.
_SERIAL_TAGS = (
    ('EXIF BodySerialNumber', 'body serial number'),
    ('Image BodySerialNumber', 'body serial number'),
    ('Image Tag 0xC62F', 'camera serial number'),
    ('EXIF Tag 0xC62F', 'camera serial number'),
    ('EXIF SerialNumber', 'camera serial number'),
    ('Image SerialNumber', 'camera serial number'),
    ('EXIF LensSerialNumber', 'lens serial number'),
    ('Image LensSerialNumber', 'lens serial number'),
)
_XMP_SERIALS = (
    ('exifEX:BodySerialNumber', 'body serial number'),
    ('aux:SerialNumber', 'camera serial number'),
    ('exifEX:LensSerialNumber', 'lens serial number'),
    ('aux:LensSerialNumber', 'lens serial number'),
)


class _ParseBudgetExceeded(Exception):
    """Internal: the parser used up its read budget on this file."""


class _BudgetedReader(io.BytesIO):
    """In-memory file that counts read/seek calls, fails once over budget and checks the step deadline.

    The failure is sticky: if the parser swallowed the first exception, every later call raises again,
    so the parse still ends promptly.
    """

    def __init__(self, data: bytes, budget: int):
        """Wrap ``data``; allow at most ``budget`` read/seek calls."""
        super().__init__(data)
        self._budget = budget
        self._ops = 0

    def _tick(self) -> None:
        self._ops += 1
        if self._ops > self._budget:
            raise _ParseBudgetExceeded()
        if self._ops % _DEADLINE_CHECK_EVERY == 0:
            clamp_timeout(1.0)  # raises DeadlineExceeded once the step budget is spent

    def read(self, size: Optional[int] = -1, /) -> bytes:
        """Count the call, then read like ``BytesIO``."""
        self._tick()
        return super().read(size)

    def seek(self, pos: int, whence: int = 0, /) -> int:
        """Count the call, then seek like ``BytesIO``."""
        self._tick()
        return super().seek(pos, whence)


# --- File access --------------------------------------------------------------------------------------


def _display_name(raw: str) -> str:
    """File name only: a full path would leak the analyst's home directory into reports and logs."""
    return clean_text(Path(raw).name, 255) or '<unnamed>'


def _read_image(raw: str) -> Tuple[str, bytes]:
    """Return ``(file name, content)`` of a local regular file, enforcing every file-level check."""
    if is_unc_path(raw):
        # Opening \\host\share on Windows authenticates to that host with the user's NTLM credentials.
        raise SourceUnavailable('network paths are not allowed: image_exif only reads local files')
    name = _display_name(raw)
    try:
        path = Path(raw).expanduser().resolve(strict=True)
        if is_unc_path(str(path)):  # a symlink or junction that points at a network share
            raise SourceUnavailable('network paths are not allowed: image_exif only reads local files')
        st = os.stat(path)
    except FileNotFoundError as e:
        raise SourceUnavailable(f'image file not found: {name}') from e
    except (OSError, RuntimeError, ValueError) as e:
        raise SourceUnavailable(f'cannot access image file {name}: {type(e).__name__}') from e
    # Checked BEFORE opening: open() on a FIFO blocks and a device (e.g. /dev/zero) never ends.
    if not stat.S_ISREG(st.st_mode):
        raise SourceUnavailable(f'not a regular file: {name}')
    if st.st_size > MAX_FILE_BYTES:
        raise SourceUnavailable(f'image file too large: {st.st_size} bytes (limit {MAX_FILE_BYTES})')
    # O_NONBLOCK: if the path is swapped for a FIFO after the check, open() must not hang.
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOCTTY', 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, 'rb') as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                raise SourceUnavailable(f'not a regular file: {name}')
            # Capped read: the file may have grown since stat() (TOCTOU), never trust the earlier size.
            data = fh.read(MAX_FILE_BYTES + 1)
    except OSError as e:
        raise SourceUnavailable(f'cannot read image file {name}: {type(e).__name__}') from e
    if len(data) > MAX_FILE_BYTES:
        raise SourceUnavailable(f'image file too large: more than {MAX_FILE_BYTES} bytes')
    if not data:
        raise SourceUnavailable(f'empty file: {name}')
    return path.name, data


def sniff_mime(head: bytes) -> Optional[str]:
    """MIME type from magic bytes for the formats exifread can read, ``None`` for anything else."""
    if head.startswith(b'\xff\xd8\xff'):
        return 'image/jpeg'
    if head.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'image/png'
    if head[:4] in (b'II*\x00', b'MM\x00*'):
        return 'image/tiff'  # TIFF and TIFF-based RAW: DNG, CR2, NEF, ARW, PEF, SRW...
    if head[:4] in (b'IIRO', b'IIRS', b'MMOR', b'IIU\x00'):
        return 'image/x-raw'  # Olympus ORF, Panasonic RW2
    if head[:4] == b'RIFF' and head[8:12] == b'WEBP':
        return 'image/webp'
    if head[4:8] == b'ftyp':
        brand = head[8:12]
        if brand in (b'heic', b'heix', b'hevc', b'heim', b'heis', b'hevm', b'hevs'):
            return 'image/heic'
        if brand in (b'avif', b'avis'):
            return 'image/avif'
        if brand in (b'mif1', b'msf1'):
            return 'image/heif'
    if head.startswith(b'\xff\x0a') or head.startswith(b'\x00\x00\x00\x0cJXL \r\n\x87\n'):
        return 'image/jxl'
    return None


# --- EXIF ---------------------------------------------------------------------------------------------


def _import_exifread() -> Any:
    try:
        import exifread
    except ImportError as e:
        raise SourceUnavailable(f'EXIF support is not installed: {INSTALL_HINT}') from e
    return exifread


def _parse_exif(data: bytes) -> Mapping[str, Any]:
    """Run exifread on ``data`` with bounded work. Every parser failure becomes ``SourceUnavailable``."""
    exifread = _import_exifread()
    reader = _BudgetedReader(data, READ_BUDGET)
    try:
        # details=False: no MakerNote decoding (the largest, least tested attack surface).
        # debug=False: exifread's own XMP support uses xml.dom.minidom, which is not hardened.
        return exifread.process_file(reader, details=False, extract_thumbnail=False, debug=False, strict=False)
    except _ParseBudgetExceeded as e:
        raise SourceUnavailable('EXIF structure too complex (parser work limit reached): malformed or hostile') from e
    except SourceError:
        raise  # DeadlineExceeded: keep its meaning for the engine
    except Exception as e:  # any parser bug on hostile bytes, RecursionError included
        raise SourceUnavailable(f'EXIF parsing failed: {type(e).__name__}') from e


def webp_exif_payload(data: bytes) -> Optional[bytes]:
    """TIFF bytes of a WebP ``EXIF`` chunk, or ``None``.

    exifread 3.x assumes an ``Exif\\0\\0`` prefix inside the chunk, but the RIFF container spec (and
    libwebp/Pillow) store the TIFF header directly: without this, EXIF of compliant WebP files is lost.
    Each step advances at least 8 bytes, so the walk is bounded by the (capped) file size.
    """
    offset = 12
    while offset + 8 <= len(data):
        fourcc = data[offset : offset + 4]
        size = int.from_bytes(data[offset + 4 : offset + 8], 'little')
        if fourcc == b'EXIF':
            payload = data[offset + 8 : offset + 8 + size]
            return payload[6:] if payload.startswith(b'Exif\x00\x00') else payload
        offset += 8 + size + (size & 1)
    return None


def clean_text(value: Any, limit: int = MAX_TEXT) -> Optional[str]:
    """Printable, trimmed, length-capped text; ``None`` when nothing meaningful is left."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode('utf-8', 'replace')
    text = _CONTROL_CHARS.sub('', str(value)).strip()
    return text[:limit] or None


def _tag_text(tags: Mapping[str, Any], *names: str) -> Optional[str]:
    for name in names:
        tag = tags.get(name)
        if tag is None:
            continue
        values = getattr(tag, 'values', tag)
        if isinstance(values, list) and values and all(isinstance(v, int) and 0 <= v < 256 for v in values):
            text = clean_text(bytes(values))  # UNDEFINED/BYTE fields holding text
        elif isinstance(values, (str, bytes)):
            text = clean_text(values)
        else:
            text = clean_text(getattr(tag, 'printable', None))
        if text:
            return text
    return None


def _ratio(value: Any) -> Optional[float]:
    """A rational/int as float; ``None`` for a zero denominator or a non-number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) if math.isfinite(value) else None
    num, den = getattr(value, 'numerator', None), getattr(value, 'denominator', None)
    if not isinstance(num, int) or not isinstance(den, int) or den == 0:
        return None
    return num / den


def _tag_values(tags: Mapping[str, Any], name: str) -> List[Any]:
    values = getattr(tags.get(name), 'values', None)
    return values if isinstance(values, list) else []


def _iso_datetime(text: Optional[str]) -> Optional[str]:
    """EXIF ``YYYY:MM:DD HH:MM:SS`` -> ISO 8601; ``None`` for blank/zeroed/invalid values."""
    match = _EXIF_DATETIME.match(text or '')
    if not match:
        return None
    year, month, day, hour, minute, second = (int(g) for g in match.groups())
    try:
        return datetime(year, month, day, hour, minute, second).isoformat()
    except ValueError:
        return None


def dms_to_decimal(parts: List[Any], ref: Optional[str], limit: float, negative: str) -> Optional[float]:
    """Degrees/minutes/seconds (rationals) + hemisphere ref -> signed decimal degrees, range-checked.

    Returns ``None`` for malformed values (zero denominators, minutes/seconds >= 60, out of range,
    unknown hemisphere letter) instead of guessing.
    """
    if not 1 <= len(parts) <= 3:
        return None
    numbers = [n for n in (_ratio(p) for p in parts) if n is not None]
    if len(numbers) != len(parts):
        return None
    deg, minutes, seconds = (numbers + [0.0, 0.0])[:3]
    if deg < 0 or not 0 <= minutes < 60 or not 0 <= seconds < 60:
        return None
    value = deg + minutes / 60 + seconds / 3600
    if value > limit:
        return None
    letter = (ref or '').strip().upper()[:1]
    if letter and letter not in ('N', 'S', 'E', 'W'):
        return None
    if letter == negative:
        value = -value
    return round(value, 6) + 0.0  # + 0.0 turns -0.0 into 0.0


def _gps_block(lat: float, lon: float, altitude: Optional[float], timestamp: Optional[str]) -> Dict[str, Any]:
    return {
        'latitude': lat,
        'longitude': lon,
        'altitude_m': altitude,
        'timestamp': timestamp,
        'maps_url': f'https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}',
    }


def _exif_gps(tags: Mapping[str, Any], warnings: List[str]) -> Optional[Dict[str, Any]]:
    if 'GPS GPSLatitude' not in tags and 'GPS GPSLongitude' not in tags:
        return None
    lat = dms_to_decimal(_tag_values(tags, 'GPS GPSLatitude'), _tag_text(tags, 'GPS GPSLatitudeRef'), 90, 'S')
    lon = dms_to_decimal(_tag_values(tags, 'GPS GPSLongitude'), _tag_text(tags, 'GPS GPSLongitudeRef'), 180, 'W')
    if lat is None or lon is None:
        warnings.append('GPS coordinates malformed or out of range: ignored')
        return None

    altitude = None
    alt_values = _tag_values(tags, 'GPS GPSAltitude')
    alt = _ratio(alt_values[0]) if alt_values else None
    if alt is not None and abs(alt) < 100_000:
        below = _tag_values(tags, 'GPS GPSAltitudeRef')[:1] == [1]
        altitude = round(-alt if below else alt, 2) + 0.0

    timestamp = None
    date = _EXIF_DATE.match(_tag_text(tags, 'GPS GPSDate') or '')
    hms = [v for v in (_ratio(v) for v in _tag_values(tags, 'GPS GPSTimeStamp')) if v is not None]
    if date and len(hms) == 3:
        try:
            hour, minute, second = (int(v) for v in hms)
            year, month, day = (int(g) for g in date.groups())
            when = datetime(year, month, day, hour, minute, second)
            timestamp = when.isoformat() + 'Z'  # GPS time is UTC by definition
        except (ValueError, OverflowError):
            timestamp = None
    return _gps_block(lat, lon, altitude, timestamp)


# --- XMP ----------------------------------------------------------------------------------------------


def _find_xmp(data: bytes, warnings: List[str]) -> Optional[bytes]:
    """Locate the XMP packet bytes (JPEG APP1, PNG iTXt, TIFF tag 700, WebP chunk all embed it verbatim)."""
    start = data.find(b'<x:xmpmeta')
    if start < 0:
        return None
    # Include the xpacket header and anything between it and the root, so a DOCTYPE smuggled there is
    # seen (and rejected) by the parser instead of being silently cut away.
    header = data.rfind(b'<?xpacket begin', max(0, start - 4096), start)
    if header >= 0:
        start = header
    end = data.find(b'</x:xmpmeta>', start)
    if end < 0:
        warnings.append('XMP packet unterminated: ignored')
        return None
    end += len(b'</x:xmpmeta>')
    if end - start > MAX_XMP_BYTES:
        warnings.append(f'XMP packet too large ({end - start} bytes, limit {MAX_XMP_BYTES}): ignored')
        return None
    return data[start:end]


def _qname(name: str, prefixes: Mapping[str, str]) -> str:
    if name.startswith('{'):
        uri, _, local = name[1:].partition('}')
        # Known namespaces always get their canonical prefix: the document may bind any prefix it likes,
        # and lookups such as 'exif:GPSLatitude' (and the GPS filter below) rely on stable keys.
        prefix = _KNOWN_PREFIXES.get(uri) or prefixes.get(uri)
        return f'{prefix}:{local}' if prefix else local
    return name


def _xmp_value(element: Any, prefixes: Mapping[str, str], depth: int) -> Any:
    """Simple value, list (rdf:Seq/Bag/Alt) or struct (dict) of one XMP property element."""
    if depth > MAX_XMP_DEPTH:
        return None
    children = list(element)
    container = next((c for c in children if c.tag in _RDF_CONTAINERS), None)
    if container is not None:
        items = [_xmp_value(li, prefixes, depth + 1) for li in list(container)[:MAX_XMP_LIST]]
        return [i for i in items if i not in (None, '', {})]
    resource = element.get(f'{{{_RDF}}}resource')
    if resource is not None:
        return clean_text(resource)
    fields = {k: v for k, v in element.attrib.items() if not k.startswith((f'{{{_RDF}}}', f'{{{_XML}}}'))}
    if children or fields:
        struct: Dict[str, Any] = {}
        for key, value in fields.items():
            struct[_qname(key, prefixes)] = clean_text(value)
        for child in children:
            if len(struct) >= MAX_XMP_LIST:
                break
            if child.tag == f'{{{_RDF}}}Description':  # nested struct written as rdf:Description
                nested = _xmp_value(child, prefixes, depth + 1)
                if isinstance(nested, dict):
                    struct.update(nested)
                continue
            struct[_qname(child.tag, prefixes)] = _xmp_value(child, prefixes, depth + 1)
        return struct
    return clean_text(element.text)


def _flatten_xmp(root: Any, prefixes: Mapping[str, str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for rdf in root.iter(f'{{{_RDF}}}RDF'):
        for desc in rdf:
            if desc.tag != f'{{{_RDF}}}Description':
                continue
            entries = [(k, clean_text(v)) for k, v in desc.attrib.items() if not k.startswith(f'{{{_RDF}}}')]
            entries += [(child.tag, _xmp_value(child, prefixes, 1)) for child in desc]
            for key, value in entries:
                if len(out) >= MAX_XMP_PROPERTIES:
                    return out
                if value not in (None, '', [], {}):
                    out[_qname(key, prefixes)] = value
    return out


def parse_xmp(packet: bytes, warnings: List[str]) -> Dict[str, Any]:
    """Parse an XMP packet with defusedxml only (DTDs forbidden). Problems become warnings."""
    try:
        from defusedxml import DefusedXmlException
        from defusedxml import ElementTree as SafeElementTree
    except ImportError:
        # Never fall back to the stdlib parser for untrusted XML.
        warnings.append(f'XMP metadata present but not parsed: {INSTALL_HINT}')
        return {}
    try:
        root = SafeElementTree.fromstring(packet, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except DefusedXmlException as e:
        warnings.append(f'XMP packet rejected ({type(e).__name__}: DTD/entity declarations are not allowed)')
        return {}
    except Exception as e:  # ParseError, encoding errors... on hostile bytes
        warnings.append(f'XMP packet rejected (malformed XML: {type(e).__name__})')
        return {}
    text = packet.decode('utf-8', 'replace')
    prefixes: Dict[str, str] = {}
    for prefix, uri in _XMLNS.findall(text):
        prefixes.setdefault(uri, prefix)
    return _flatten_xmp(root, prefixes)


def _xmp_coordinate(value: Any, limit: float, negative: str) -> Optional[float]:
    """XMP ``DDD,MM,SSk`` / ``DDD,MM.mmk`` -> signed decimal degrees."""
    match = _XMP_COORD.fullmatch(value.strip()) if isinstance(value, str) else None
    if not match:
        return None
    deg, minutes, seconds, letter = match.groups()
    if letter.upper() not in ('NS' if limit == 90 else 'EW'):
        return None
    return dms_to_decimal([int(deg), float(minutes), float(seconds or 0)], letter, limit, negative)


def _xmp_gps(xmp: Mapping[str, Any], warnings: List[str]) -> Optional[Dict[str, Any]]:
    if 'exif:GPSLatitude' not in xmp and 'exif:GPSLongitude' not in xmp:
        return None
    lat = _xmp_coordinate(xmp.get('exif:GPSLatitude'), 90, 'S')
    lon = _xmp_coordinate(xmp.get('exif:GPSLongitude'), 180, 'W')
    if lat is None or lon is None:
        warnings.append('XMP GPS coordinates malformed or out of range: ignored')
        return None
    return _gps_block(lat, lon, None, None)


# --- Source -------------------------------------------------------------------------------------------


@register_source('image_exif')
class ImageExifSource(BaseSource):
    """EXIF/XMP metadata of a local image file: camera, serials, capture times, GPS, XMP properties.

    100% offline and never uploads the image. Not cached: the result describes a local file whose
    content can change, and caching would copy location data and serial numbers to disk. GPS keys
    (latitude/longitude/altitude_m/maps_url) are the 'location' privacy category: redacted by default.
    """

    cacheable = False
    client = None  # no HTTP client: this source never touches the network

    def fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metadata from the image file named by ``params['input']``.

        Args:
            params: Step parameters; ``input`` is a local image file path.

        Returns:
            ``{file, camera, timestamps, gps, xmp, authorship, warnings}`` (contract C5).

        Raises:
            SourceUnavailable: Missing/unsupported/hostile file, or the ``image`` extra is not installed.
            DeadlineExceeded: The step time budget ran out while parsing.
        """
        clamp_timeout(1.0)
        name, data = _read_image(self.require_input(params))
        mime = sniff_mime(data[:16])
        if mime is None:
            raise SourceUnavailable(
                f'not a recognised image format: {name} (JPEG, PNG, TIFF/RAW, WebP, HEIC/AVIF, JPEG XL)'
            )
        if mime == 'image/webp':
            payload = webp_exif_payload(data)
            tags = _parse_exif(payload) if payload else {}
        else:
            tags = _parse_exif(data)
        warnings: List[str] = []

        camera: Dict[str, Optional[str]] = {
            'make': _tag_text(tags, 'Image Make'),
            'model': _tag_text(tags, 'Image Model'),
            'serial': None,
            'lens': _tag_text(tags, 'EXIF LensModel', 'EXIF LensMake'),
            'software': _tag_text(tags, 'Image Software'),
        }
        serial_kind = None
        for key, kind in _SERIAL_TAGS:
            camera['serial'] = _tag_text(tags, key)
            if camera['serial']:
                serial_kind = kind
                break

        timestamps = {
            'original': _iso_datetime(_tag_text(tags, 'EXIF DateTimeOriginal')),
            'digitized': _iso_datetime(_tag_text(tags, 'EXIF DateTimeDigitized')),
            'modified': _iso_datetime(_tag_text(tags, 'Image DateTime')),
            'offset': None,
        }
        offset = _tag_text(tags, 'EXIF OffsetTimeOriginal', 'EXIF OffsetTime')
        if offset and _UTC_OFFSET.fullmatch(offset):
            timestamps['offset'] = offset

        authorship = {
            'artist': _tag_text(tags, 'Image Artist'),
            'copyright': _tag_text(tags, 'Image Copyright'),
            'owner': _tag_text(tags, 'EXIF CameraOwnerName', 'Image CameraOwnerName'),
        }

        gps = _exif_gps(tags, warnings)

        xmp: Dict[str, Any] = {}
        packet = _find_xmp(data, warnings)
        if packet is not None:
            xmp = parse_xmp(packet, warnings)
        if camera['serial'] is None:
            for key, kind in _XMP_SERIALS:
                camera['serial'] = clean_text(xmp.get(key)) if isinstance(xmp.get(key), str) else None
                if camera['serial']:
                    serial_kind = f'{kind} (XMP)'
                    break
        if gps is None:
            gps = _xmp_gps(xmp, warnings)
        # 'exif:GPS*' are not C3 location keys: kept here they would bypass the default redaction.
        # Location is reported only through the (redactable) gps block.
        xmp = {k: v for k, v in xmp.items() if not k.startswith('exif:GPS')}
        # Place names and altitudes are location too: moved under a location key so they are redacted by
        # default (and shown with --keep-location) instead of riding along in the free-form xmp block.
        xmp_location = {k: v for k, v in xmp.items() if _is_xmp_place_key(k)}
        xmp = {k: v for k, v in xmp.items() if k not in xmp_location}
        if xmp_location:
            warnings.append('XMP place names or altitude present: the photo discloses where it was taken')
        if authorship['artist'] is None and isinstance(xmp.get('dc:creator'), list) and xmp['dc:creator']:
            authorship['artist'] = clean_text(', '.join(str(c) for c in xmp['dc:creator'] if isinstance(c, str)))

        if not tags:
            warnings.append(NO_EXIF_WARNING)
        if gps is not None:
            warnings.append('GPS coordinates present: the photo discloses where it was taken')
            if gps['latitude'] == 0.0 and gps['longitude'] == 0.0:
                warnings.append('GPS 0,0 is commonly a placeholder written by devices without a fix')
        if serial_kind:
            warnings.append(
                f'{serial_kind} present: it uniquely identifies the device and can link photos across accounts'
            )
        if any(authorship.values()):
            warnings.append('artist/owner/copyright names present: personal data about the photographer')
        if timestamps['modified'] and timestamps['original'] and timestamps['modified'] != timestamps['original']:
            via = f' with {camera["software"]}' if camera['software'] else ''
            warnings.append(f'image modified after capture{via} (DateTime differs from DateTimeOriginal)')

        return {
            'file': {'name': name, 'size_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'mime': mime},
            'camera': camera,
            'timestamps': timestamps,
            'gps': gps,
            'xmp': xmp,
            'xmp_location': xmp_location or None,
            'authorship': authorship,
            'warnings': warnings,
        }
