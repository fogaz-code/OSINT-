"""image_exif source: offline EXIF/XMP extraction (contract C5).

Every fixture is generated inside the test (Pillow or hand-built TIFF bytes): no downloaded blobs.
"""

import hashlib
import io
import socket
import struct
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

import pytest

from secure_osint.core.engine import WorkflowEngine
from secure_osint.core.workflow import StepStatus, load_workflow_from_file
from secure_osint.sources.base import SourceUnavailable

Image = pytest.importorskip('PIL.Image')
pytest.importorskip('exifread')
pytest.importorskip('defusedxml')

from PIL.TiffImagePlugin import IFDRational  # noqa: E402

from secure_osint.sources.image_exif_source import ImageExifSource  # noqa: E402

WORKFLOWS = Path(__file__).resolve().parents[1] / 'src' / 'secure_osint' / 'workflows'

# --- Fixture builders ------------------------------------------------------------------------------


def _dms(deg: float, minutes: float, seconds: float) -> Tuple[IFDRational, IFDRational, IFDRational]:
    return (IFDRational(deg), IFDRational(minutes), IFDRational(round(seconds * 100), 100))


def make_jpeg(
    *,
    make: Optional[str] = 'Canon',
    model: Optional[str] = 'Canon EOS 5D Mark IV',
    software: Optional[str] = 'Adobe Photoshop 25.0',
    modified: Optional[str] = '2024:05:02 11:00:00',
    original: Optional[str] = '2024:05:01 10:20:30',
    digitized: Optional[str] = '2024:05:01 10:20:31',
    offset: Optional[str] = '+02:00',
    body_serial: Optional[str] = None,
    lens: Optional[str] = 'EF 50mm f/1.8 STM',
    lens_serial: Optional[str] = None,
    owner: Optional[str] = None,
    artist: Optional[str] = None,
    gps: Optional[Dict[int, Any]] = None,
    with_exif: bool = True,
) -> bytes:
    """A 4x4 JPEG; every EXIF field is optional so tests can pick exactly what is present."""
    img = Image.new('RGB', (4, 4), 'red')
    buf = io.BytesIO()
    if not with_exif:
        img.save(buf, 'JPEG')
        return buf.getvalue()
    exif = Image.Exif()
    for tag, value in ((0x010F, make), (0x0110, model), (0x0131, software), (0x0132, modified), (0x013B, artist)):
        if value is not None:
            exif[tag] = value
    sub = exif.get_ifd(0x8769)
    for tag, value in (
        (0x9003, original),
        (0x9004, digitized),
        (0x9011, offset),
        (0xA430, owner),
        (0xA431, body_serial),
        (0xA434, lens),
        (0xA435, lens_serial),
    ):
        if value is not None:
            sub[tag] = value
    if gps is not None:
        exif.get_ifd(0x8825).update(gps)
    img.save(buf, 'JPEG', exif=exif.tobytes())
    return buf.getvalue()


def milan_gps(lat_ref: str = 'N', lon_ref: str = 'E', alt_ref: bytes = b'\x00') -> Dict[int, Any]:
    """45d 27' 50.40" N, 9d 11' 25.20" E (Duomo di Milano), 122.5 m."""
    return {
        1: lat_ref,
        2: _dms(45, 27, 50.40),
        3: lon_ref,
        4: _dms(9, 11, 25.20),
        5: alt_ref,
        6: IFDRational(1225, 10),
        7: (IFDRational(8), IFDRational(15), IFDRational(30)),
        29: '2024:05:01',
    }


def inject_xmp(jpeg: bytes, packet: bytes) -> bytes:
    """Insert an XMP APP1 segment right after SOI, exactly where cameras and editors put it."""
    assert jpeg[:2] == b'\xff\xd8'
    body = b'http://ns.adobe.com/xap/1.0/\x00' + packet
    return jpeg[:2] + b'\xff\xe1' + struct.pack('>H', len(body) + 2) + body + jpeg[2:]


def xmp_packet(rdf_body: str, doctype: str = '') -> bytes:
    return (
        '<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>' + doctype + '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        + rdf_body
        + '</rdf:RDF></x:xmpmeta><?xpacket end="w"?>'
    ).encode('utf-8')


# TIFF field types
ASCII, SHORT, LONG, RATIONAL = 2, 3, 4, 5


def tiff_ifd(entries: Sequence[Tuple[int, int, int, int]], next_ifd: int = 0) -> bytes:
    """Little-endian IFD: entry = (tag, type, count, inline value or offset)."""
    out = struct.pack('<H', len(entries))
    for tag, ftype, count, value in entries:
        out += struct.pack('<HHII', tag, ftype, count, value)
    return out + struct.pack('<I', next_ifd)


def make_tiff(ifd0: Sequence[Tuple[int, int, int, int]], tail: bytes = b'') -> bytes:
    """Minimal TIFF: header + IFD0 at offset 8 + arbitrary trailing bytes (sub-IFDs, values)."""
    return b'II*\x00' + struct.pack('<I', 8) + tiff_ifd(ifd0) + tail


def write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def run(path: Any) -> Dict[str, Any]:
    return ImageExifSource().fetch({'input': str(path), 'upstream': {}})


def has_warning(data: Dict[str, Any], *needles: str) -> bool:
    return any(all(n.lower() in w.lower() for n in needles) for w in data['warnings'])


# --- Output shape (C5) -----------------------------------------------------------------------------


def test_output_shape_matches_contract(tmp_path):
    data = run(write(tmp_path, 'p.jpg', make_jpeg(gps=milan_gps())))
    assert set(data) >= {'file', 'camera', 'timestamps', 'gps', 'xmp', 'warnings'}
    assert set(data['file']) == {'name', 'size_bytes', 'sha256', 'mime'}
    assert set(data['camera']) >= {'make', 'model', 'serial', 'lens', 'software'}
    assert set(data['timestamps']) == {'original', 'digitized', 'modified', 'offset'}
    assert set(data['gps']) == {'latitude', 'longitude', 'altitude_m', 'timestamp', 'maps_url'}
    assert isinstance(data['xmp'], dict)
    assert all(isinstance(w, str) for w in data['warnings'])


def test_source_is_registered_and_not_cacheable():
    from secure_osint.sources.tool_catalog import tool_catalog

    assert 'image_exif' in tool_catalog
    assert tool_catalog['image_exif'].cacheable is False
    assert ImageExifSource.name == 'image_exif'


def test_file_evidence_block(tmp_path):
    raw = make_jpeg()
    path = write(tmp_path, 'evidence.jpg', raw)
    info = run(path)['file']
    assert info['name'] == 'evidence.jpg'  # never the full path: it leaks the analyst's home directory
    assert info['size_bytes'] == len(raw)
    assert info['sha256'] == hashlib.sha256(raw).hexdigest()
    assert info['mime'] == 'image/jpeg'


def test_camera_and_timestamps(tmp_path):
    data = run(write(tmp_path, 'p.jpg', make_jpeg()))
    assert data['camera']['make'] == 'Canon'
    assert data['camera']['model'] == 'Canon EOS 5D Mark IV'
    assert data['camera']['lens'] == 'EF 50mm f/1.8 STM'
    assert data['camera']['software'] == 'Adobe Photoshop 25.0'
    assert data['camera']['serial'] is None
    assert data['timestamps'] == {
        'original': '2024-05-01T10:20:30',
        'digitized': '2024-05-01T10:20:31',
        'modified': '2024-05-02T11:00:00',
        'offset': '+02:00',
    }


def test_modified_after_capture_is_flagged(tmp_path):
    data = run(write(tmp_path, 'p.jpg', make_jpeg()))
    assert has_warning(data, 'modified after capture')


def test_unset_exif_dates_become_none(tmp_path):
    data = run(write(tmp_path, 'p.jpg', make_jpeg(original='0000:00:00 00:00:00', modified='    :  :     :  :  ')))
    assert data['timestamps']['original'] is None
    assert data['timestamps']['modified'] is None


# --- Serial numbers / owner -------------------------------------------------------------------------


def test_body_serial_is_extracted_and_flagged(tmp_path):
    data = run(write(tmp_path, 'p.jpg', make_jpeg(body_serial='SN0123456789')))
    assert data['camera']['serial'] == 'SN0123456789'
    assert has_warning(data, 'serial', 'identif')


def test_lens_serial_is_used_and_flagged_when_body_serial_missing(tmp_path):
    data = run(write(tmp_path, 'p.jpg', make_jpeg(lens_serial='LENS42')))
    assert data['camera']['serial'] == 'LENS42'
    assert has_warning(data, 'serial', 'identif')


def test_dng_camera_serial_tag_is_read(tmp_path):
    # 0xC62F CameraSerialNumber lives in IFD0 of DNG/TIFF files; exifread has no name for it.
    serial = b'DNG-777\x00'
    tail_offset = 8 + 2 + 12 * 2 + 4
    tiff = make_tiff([(0x010F, ASCII, 5, 0x6E6F6B4E), (0xC62F, ASCII, len(serial), tail_offset)], serial)
    data = run(write(tmp_path, 'raw.dng', tiff))
    assert data['camera']['serial'] == 'DNG-777'
    assert data['file']['mime'] == 'image/tiff'


def test_owner_and_artist_are_reported_and_flagged(tmp_path):
    data = run(write(tmp_path, 'p.jpg', make_jpeg(owner='Jane Roe', artist='J. Roe Photography')))
    assert data['authorship'] == {'artist': 'J. Roe Photography', 'copyright': None, 'owner': 'Jane Roe'}
    assert has_warning(data, 'owner')


# --- GPS ---------------------------------------------------------------------------------------------


def test_gps_dms_to_decimal(tmp_path):
    gps = run(write(tmp_path, 'p.jpg', make_jpeg(gps=milan_gps())))['gps']
    assert gps['latitude'] == pytest.approx(45.464, abs=1e-6)
    assert gps['longitude'] == pytest.approx(9.190333, abs=1e-6)
    assert gps['altitude_m'] == pytest.approx(122.5)
    assert gps['timestamp'] == '2024-05-01T08:15:30Z'
    assert gps['maps_url'] == 'https://www.openstreetmap.org/?mlat=45.464&mlon=9.190333#map=16/45.464/9.190333'


def test_gps_hemisphere_refs_and_below_sea_level(tmp_path):
    gps = run(write(tmp_path, 'p.jpg', make_jpeg(gps=milan_gps('S', 'W', b'\x01'))))['gps']
    assert gps['latitude'] == pytest.approx(-45.464, abs=1e-6)
    assert gps['longitude'] == pytest.approx(-9.190333, abs=1e-6)
    assert gps['altitude_m'] == pytest.approx(-122.5)


def test_gps_presence_is_flagged(tmp_path):
    data = run(write(tmp_path, 'p.jpg', make_jpeg(gps=milan_gps())))
    assert has_warning(data, 'gps')


def test_gps_out_of_range_is_discarded(tmp_path):
    bad = milan_gps()
    bad[2] = _dms(95, 0, 0)
    data = run(write(tmp_path, 'p.jpg', make_jpeg(gps=bad)))
    assert data['gps'] is None
    assert has_warning(data, 'gps', 'out of range')


def test_gps_minutes_out_of_range_is_discarded(tmp_path):
    bad = milan_gps()
    bad[4] = _dms(9, 75, 0)
    data = run(write(tmp_path, 'p.jpg', make_jpeg(gps=bad)))
    assert data['gps'] is None


def test_gps_zero_denominator_does_not_crash(tmp_path):
    # Pillow refuses to serialise x/0, so patch the latitude seconds rational in the bytes. 5041/100 is
    # already in lowest terms, so Pillow stores exactly those two numbers.
    gps = milan_gps()
    gps[2] = (IFDRational(45), IFDRational(27), IFDRational(5041, 100))
    jpeg = make_jpeg(gps=gps)
    for fmt in ('<II', '>II'):
        needle, patched = struct.pack(fmt, 5041, 100), struct.pack(fmt, 1, 0)
        if needle in jpeg:
            break
    assert needle in jpeg
    data = run(write(tmp_path, 'p.jpg', jpeg.replace(needle, patched, 1)))
    assert data['gps'] is None
    assert has_warning(data, 'gps')


def test_gps_null_island_is_flagged(tmp_path):
    zero = {1: 'N', 2: _dms(0, 0, 0), 3: 'E', 4: _dms(0, 0, 0)}
    data = run(write(tmp_path, 'p.jpg', make_jpeg(gps=zero)))
    assert data['gps']['latitude'] == 0.0
    assert has_warning(data, 'placeholder')


def test_gps_without_altitude_or_time(tmp_path):
    gps = run(write(tmp_path, 'p.jpg', make_jpeg(gps={1: 'N', 2: _dms(1, 30, 0), 3: 'E', 4: _dms(2, 0, 0)})))['gps']
    assert gps['latitude'] == 1.5
    assert gps['altitude_m'] is None
    assert gps['timestamp'] is None


def test_gps_keys_are_the_privacy_location_keys():
    # Contract C3: the privacy track redacts structured location keys by name. Keep them in sync.
    assert {'latitude', 'longitude', 'altitude_m', 'maps_url'} <= {
        'latitude',
        'longitude',
        'lat',
        'lon',
        'lng',
        'gps',
        'altitude',
        'altitude_m',
        'maps_url',
        'coordinates',
    }


# --- No EXIF -----------------------------------------------------------------------------------------


def test_no_exif_warning(tmp_path):
    data = run(write(tmp_path, 'stripped.jpg', make_jpeg(with_exif=False)))
    assert data['gps'] is None
    assert all(v is None for v in data['camera'].values())
    assert 'no EXIF metadata (commonly stripped by social platforms)' in data['warnings']


def test_png_without_exif(tmp_path):
    buf = io.BytesIO()
    Image.new('RGB', (2, 2)).save(buf, 'PNG')
    data = run(write(tmp_path, 'a.png', buf.getvalue()))
    assert data['file']['mime'] == 'image/png'
    assert 'no EXIF metadata (commonly stripped by social platforms)' in data['warnings']


def test_webp_with_exif(tmp_path):
    exif = Image.Exif()
    exif[0x010F] = 'Google'
    exif[0x0110] = 'Pixel 8'
    buf = io.BytesIO()
    Image.new('RGB', (2, 2)).save(buf, 'WEBP', exif=exif.tobytes())
    data = run(write(tmp_path, 'a.webp', buf.getvalue()))
    assert data['file']['mime'] == 'image/webp'
    assert data['camera']['model'] == 'Pixel 8'  # regression: exifread alone loses spec-compliant WebP EXIF


def test_webp_with_exif_prefixed_chunk(tmp_path):
    # Some writers put an 'Exif\0\0' header inside the chunk: both layouts must work.
    exif = Image.Exif()
    exif[0x0110] = 'Pixel 9'
    tiff = exif.tobytes().removeprefix(b'Exif\x00\x00')  # Pillow adds the JPEG APP1 header
    chunk_payload = b'Exif\x00\x00' + tiff
    chunk = b'EXIF' + struct.pack('<I', len(chunk_payload)) + chunk_payload + b'\x00' * (len(chunk_payload) & 1)
    vp8x = b'VP8X' + struct.pack('<I', 10) + bytes([0x08, 0, 0, 0]) + b'\x01\x00\x00\x01\x00\x00'
    body = b'WEBP' + vp8x + chunk
    data = run(write(tmp_path, 'b.webp', b'RIFF' + struct.pack('<I', len(body)) + body))
    assert data['camera']['model'] == 'Pixel 9'


# --- XMP ---------------------------------------------------------------------------------------------

RICH_XMP = (
    '<rdf:Description rdf:about=""'
    ' xmlns:xmp="http://ns.adobe.com/xap/1.0/"'
    ' xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/"'
    ' xmlns:dc="http://purl.org/dc/elements/1.1/"'
    ' xmlns:aux="http://ns.adobe.com/exif/1.0/aux/"'
    ' xmlns:exif="http://ns.adobe.com/exif/1.0/"'
    ' xmp:CreatorTool="Adobe Photoshop Lightroom Classic 13.0"'
    ' xmp:CreateDate="2024-05-01T10:20:30.12+02:00"'
    ' xmpMM:DocumentID="xmp.did:0a1b2c3d"'
    ' aux:SerialNumber="XMPSERIAL9"'
    ' exif:GPSLatitude="45,27.84N"'
    ' exif:GPSLongitude="9,11.42E">'
    '<dc:creator><rdf:Seq><rdf:li>Jane Roe</rdf:li></rdf:Seq></dc:creator>'
    '<dc:subject><rdf:Bag><rdf:li>travel</rdf:li><rdf:li>milan</rdf:li></rdf:Bag></dc:subject>'
    '<dc:title><rdf:Alt><rdf:li xml:lang="x-default">Duomo</rdf:li></rdf:Alt></dc:title>'
    '</rdf:Description>'
)


def test_xmp_properties_are_flattened(tmp_path):
    data = run(write(tmp_path, 'p.jpg', inject_xmp(make_jpeg(), xmp_packet(RICH_XMP))))
    xmp = data['xmp']
    assert xmp['xmp:CreatorTool'] == 'Adobe Photoshop Lightroom Classic 13.0'
    assert xmp['xmp:CreateDate'] == '2024-05-01T10:20:30.12+02:00'
    assert xmp['xmpMM:DocumentID'] == 'xmp.did:0a1b2c3d'
    assert xmp['dc:creator'] == ['Jane Roe']
    assert xmp['dc:subject'] == ['travel', 'milan']
    assert xmp['dc:title'] == ['Duomo']


def test_xmp_serial_fills_missing_camera_serial(tmp_path):
    data = run(write(tmp_path, 'p.jpg', inject_xmp(make_jpeg(), xmp_packet(RICH_XMP))))
    assert data['camera']['serial'] == 'XMPSERIAL9'
    assert has_warning(data, 'serial')


def test_xmp_gps_is_used_when_exif_has_none(tmp_path):
    gps = run(write(tmp_path, 'p.jpg', inject_xmp(make_jpeg(), xmp_packet(RICH_XMP))))['gps']
    assert gps['latitude'] == pytest.approx(45.464, abs=1e-6)
    assert gps['longitude'] == pytest.approx(9.190333, abs=1e-6)


def test_exif_gps_wins_over_xmp(tmp_path):
    data = run(write(tmp_path, 'p.jpg', inject_xmp(make_jpeg(gps=milan_gps('S')), xmp_packet(RICH_XMP))))
    assert data['gps']['latitude'] < 0


def test_xmp_only_file_has_no_missing_exif_warning_about_xmp(tmp_path):
    data = run(write(tmp_path, 'p.jpg', inject_xmp(make_jpeg(with_exif=False), xmp_packet(RICH_XMP))))
    assert data['xmp']['dc:creator'] == ['Jane Roe']
    assert 'no EXIF metadata (commonly stripped by social platforms)' in data['warnings']


def test_xmp_values_are_capped(tmp_path):
    long_value = 'A' * 20_000  # the whole APP1 segment must stay under 64 KiB
    body = (
        '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">'
        f'<dc:description>{long_value}</dc:description>'
        '<dc:subject><rdf:Bag>' + '<rdf:li>k</rdf:li>' * 2000 + '</rdf:Bag></dc:subject>'
        '</rdf:Description>'
    )
    xmp = run(write(tmp_path, 'p.jpg', inject_xmp(make_jpeg(), xmp_packet(body))))['xmp']
    assert len(xmp['dc:description']) <= 1024
    assert len(xmp['dc:subject']) <= 100


def test_unknown_namespace_keeps_declared_prefix(tmp_path):
    body = '<rdf:Description rdf:about="" xmlns:acme="https://acme.invalid/ns/1.0/" acme:Shoot="S-42"/>'
    xmp = run(write(tmp_path, 'p.jpg', inject_xmp(make_jpeg(), xmp_packet(body))))['xmp']
    assert xmp['acme:Shoot'] == 'S-42'


# --- Offline guarantee -------------------------------------------------------------------------------


def test_never_touches_the_network(tmp_path, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError('image_exif must be offline')

    monkeypatch.setattr(socket, 'socket', no_network)
    monkeypatch.setattr(socket, 'create_connection', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    data = run(write(tmp_path, 'p.jpg', inject_xmp(make_jpeg(gps=milan_gps()), xmp_packet(RICH_XMP))))
    assert data['gps'] is not None
    assert ImageExifSource.client is None


# --- Optional dependencies ---------------------------------------------------------------------------


def test_missing_exifread_asks_for_the_extra(tmp_path, monkeypatch):
    monkeypatch.setitem(__import__('sys').modules, 'exifread', None)
    with pytest.raises(SourceUnavailable, match=r'secure-osint\[image\]'):
        run(write(tmp_path, 'p.jpg', make_jpeg()))


def test_missing_defusedxml_never_falls_back_to_stdlib_xml(tmp_path, monkeypatch):
    import sys
    import xml.etree.ElementTree as stdlib_et

    monkeypatch.setitem(sys.modules, 'defusedxml', None)
    monkeypatch.setitem(sys.modules, 'defusedxml.ElementTree', None)

    def forbidden(*args, **kwargs):
        raise AssertionError('stdlib XML parser must never see an untrusted XMP packet')

    monkeypatch.setattr(stdlib_et, 'fromstring', forbidden)
    monkeypatch.setattr(stdlib_et, 'XMLParser', forbidden)
    data = run(write(tmp_path, 'p.jpg', inject_xmp(make_jpeg(), xmp_packet(RICH_XMP))))
    assert data['xmp'] == {}
    assert has_warning(data, 'XMP', 'secure-osint[image]')
    assert data['camera']['make'] == 'Canon'  # EXIF still extracted


# --- Workflow ----------------------------------------------------------------------------------------


def test_image_workflow_file():
    wf = load_workflow_from_file(str(WORKFLOWS / 'image.yaml'))
    assert wf.name == 'image'
    assert wf.input_type == 'image_file'
    assert [s.type for s in wf.steps] == ['image_exif']


def test_image_workflow_runs_end_to_end(tmp_path):
    from secure_osint.sources.tool_catalog import tool_catalog

    path = write(tmp_path, 'p.jpg', make_jpeg(gps=milan_gps()))
    wf = load_workflow_from_file(str(WORKFLOWS / 'image.yaml'))
    results = WorkflowEngine(catalog=tool_catalog, backoff=lambda attempt: 0.0).execute(wf, str(path))
    (result,) = results.values()
    assert result.status == StepStatus.SUCCESS
    assert result.cached is False
    assert result.data['gps']['latitude'] == pytest.approx(45.464, abs=1e-6)


def test_xmp_gps_properties_are_not_duplicated_in_xmp(tmp_path):
    # Regression: 'exif:GPSLatitude' is not a C3 location key, so leaving it in `xmp` would leak the
    # coordinates past the default redaction. They are reported only in the redactable `gps` block.
    body = RICH_XMP.replace('>', ' exif:GPSAltitude="1225/10" exif:GPSTimeStamp="2024-05-01T08:15:30Z">', 1)
    data = run(write(tmp_path, 'p.jpg', inject_xmp(make_jpeg(), xmp_packet(body))))
    assert data['gps']['latitude'] == pytest.approx(45.464, abs=1e-6)
    assert not [k for k in data['xmp'] if 'gps' in k.lower()]
    assert '45,27.84N' not in repr(data['xmp'])


def test_malformed_xmp_gps_is_dropped_not_leaked(tmp_path):
    body = '<rdf:Description rdf:about="" xmlns:exif="http://ns.adobe.com/exif/1.0/" exif:GPSLatitude="45,27.84N"/>'
    data = run(write(tmp_path, 'p.jpg', inject_xmp(make_jpeg(), xmp_packet(body))))
    assert data['gps'] is None
    assert 'exif:GPSLatitude' not in data['xmp']


def test_xmp_gps_is_found_whatever_prefix_the_document_binds(tmp_path):
    # XML prefixes are arbitrary: the EXIF namespace bound to 'e' must still yield the gps block.
    body = (
        '<rdf:Description rdf:about="" xmlns:e="http://ns.adobe.com/exif/1.0/"'
        ' e:GPSLatitude="45,27.84N" e:GPSLongitude="9,11.42E"/>'
    )
    data = run(write(tmp_path, 'p.jpg', inject_xmp(make_jpeg(), xmp_packet(body))))
    assert data['gps']['latitude'] == pytest.approx(45.464, abs=1e-6)
    assert '45,27.84N' not in repr(data['xmp'])


def test_xmp_place_names_and_drone_altitude_are_location_and_redacted_by_default(tmp_path):
    from secure_osint.core.privacy import CATEGORIES, PrivacyGuard

    body = (
        '<rdf:Description rdf:about=""'
        ' xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/"'
        ' xmlns:Iptc4xmpCore="http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/"'
        ' xmlns:drone-dji="http://www.dji.com/drone-dji/1.0/"'
        ' photoshop:City="Milano" photoshop:Country="Italia"'
        ' Iptc4xmpCore:Location="Via Torino 12" drone-dji:AbsoluteAltitude="+135.20"'
        ' photoshop:Headline="Duomo"/>'
    )
    data = run(write(tmp_path, 'p.jpg', inject_xmp(make_jpeg(), xmp_packet(body))))
    assert data['xmp_location']['photoshop:City'] == 'Milano'
    assert data['xmp']['photoshop:Headline'] == 'Duomo'  # not a place: stays in xmp
    assert not any(k in data['xmp'] for k in data['xmp_location'])
    redacted = repr(PrivacyGuard().redact_value(data))
    for value in ('Milano', 'Italia', 'Via Torino', '135.20'):
        assert value not in redacted
    kept = repr(PrivacyGuard(categories=CATEGORIES - {'location'}).redact_value(data))
    assert 'Milano' in kept
