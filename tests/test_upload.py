import io
import ssl
import threading
from http.client import HTTPSConnection

import libarchive
import pytest
from test_server import get_loopback

from opendrop.config import AirDropConfig
from opendrop.server import AirDropServer


def make_archive(pathname, data):
    """Build a gzip'd cpio archive, the format AirDrop senders upload."""
    buf = io.BytesIO()
    with libarchive.custom_writer(buf.write, "cpio", filter_name="gzip") as archive:
        archive.add_file_from_memory(pathname, len(data), data)
    return buf.getvalue()


@pytest.fixture
def receiver(tmp_path, monkeypatch):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.chdir(inbox)  # the server extracts into the current directory
    config = AirDropConfig(
        interface=get_loopback(),
        airdrop_dir=str(tmp_path / "config"),
        server_port=0,  # let the OS pick a free port
    )
    server = AirDropServer(config)
    threading.Thread(target=server.start_server, daemon=True).start()
    yield inbox, server.http_server.server_address[1]
    server.http_server.shutdown()
    server.zeroconf.close()


def upload(port, body):
    conn = HTTPSConnection("::1", port, context=ssl._create_unverified_context())
    conn.request(
        "POST",
        "/Upload",
        body=iter([body]),
        headers={"Content-Type": "application/x-cpio"},
        encode_chunked=True,
    )
    return conn.getresponse().status


def test_upload_extracts_into_inbox(receiver):
    inbox, port = receiver
    assert upload(port, make_archive("./hello.txt", b"hi")) == 200
    assert (inbox / "hello.txt").read_bytes() == b"hi"


@pytest.mark.parametrize("pathname", ["../escaped.txt", "./a/../../escaped.txt"])
def test_upload_rejects_parent_paths(receiver, pathname):
    inbox, port = receiver
    assert upload(port, make_archive(pathname, b"x")) == 400
    assert not (inbox.parent / "escaped.txt").exists()


def test_upload_rejects_absolute_paths(receiver):
    inbox, port = receiver
    target = inbox.parent / "absolute.txt"
    assert upload(port, make_archive(str(target), b"x")) == 400
    assert not target.exists()
