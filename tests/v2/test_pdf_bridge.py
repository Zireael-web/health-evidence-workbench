import os
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from health_analyzer.ingest.models import BlockDraft, BlockKind
from health_analyzer.v2.common import V2Error
from health_analyzer.v2 import pdf_bridge


def synthetic_extractor(content):
    return [BlockDraft(BlockKind.TEXT, text="Synthetic " + content.decode("ascii"), page=1)], ["Synthetic test extractor"]


def client(bridge):
    return pdf_bridge._PdfRuntimeClient(*(os.dup(fd) for fd in bridge.client_fds))


def test_bridge_sends_bytes_and_validates_original_block_protocol():
    received = []
    def extractor(content):
        received.append(content)
        return synthetic_extractor(content)
    with pdf_bridge.PdfBridgeBootstrap(extractor) as bridge:
        connection = client(bridge)
        try:
            blocks, limitations = connection.extract(b"%PDF synthetic bytes")
            assert received == [b"%PDF synthetic bytes"]
            assert blocks[0]["text"] == "Synthetic %PDF synthetic bytes"
            assert blocks[0]["page"] == 1
            assert limitations == ["Synthetic test extractor"]
        finally:
            connection.close()


def test_bridge_serializes_concurrent_requests_and_preserves_each_response():
    with pdf_bridge.PdfBridgeBootstrap(synthetic_extractor) as bridge:
        connection = client(bridge)
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(connection.extract, [b"one", b"two"]))
            assert [item[0][0]["text"] for item in results] == ["Synthetic one", "Synthetic two"]
        finally:
            connection.close()


def test_valid_worker_failure_has_no_fallback_and_channel_remains_usable():
    def extractor(content):
        if content == b"bad":
            raise V2Error("pdf_read_error", "No synthetic result")
        return synthetic_extractor(content)
    with pdf_bridge.PdfBridgeBootstrap(extractor) as bridge:
        connection = client(bridge)
        try:
            with pytest.raises(V2Error) as error:
                connection.extract(b"bad")
            assert error.value.code == "pdf_read_error"
            assert connection.extract(b"good")[0][0]["text"] == "Synthetic good"
        finally:
            connection.close()


def test_closed_bridge_fails_and_never_uses_direct_parser():
    with pdf_bridge.PdfBridgeBootstrap(synthetic_extractor) as bridge:
        connection = client(bridge)
        connection.close()
        with pytest.raises(V2Error) as error:
            connection.extract(b"synthetic")
        assert error.value.code == "PDF_BRIDGE_CLOSED"


def test_frame_cap_rejects_header_before_receiving_or_parsing_body():
    called = []
    with pdf_bridge.PdfBridgeBootstrap(lambda content: called.append(content)) as bridge:
        os.write(bridge.client_fds[0], (pdf_bridge.MAX_REQUEST + 1).to_bytes(8, "big"))
        assert pdf_bridge._read_exact(bridge.client_fds[1], 1,
                                     deadline=time.monotonic() + 2, idle_header=True) is None
        assert called == []


def test_invalid_regular_fd_and_duplicate_fd_rejected(tmp_path):
    source = tmp_path / "regular.txt"
    source.write_bytes(b"synthetic")
    fd = os.open(source, os.O_RDONLY)
    try:
        with pytest.raises(V2Error, match="pipe"):
            pdf_bridge._PdfRuntimeClient(fd, fd + 1)
    finally:
        os.close(fd)
    read, write = os.pipe()
    try:
        with pytest.raises(V2Error, match="Separate"):
            pdf_bridge._PdfRuntimeClient(write, write)
    finally:
        os.close(read)
        os.close(write)


def test_timeout_breaks_channel_instead_of_falling_back(monkeypatch):
    monkeypatch.setattr(pdf_bridge, "RPC_TIMEOUT", 0.1)
    def slow_extractor(content):
        time.sleep(0.3)
        return synthetic_extractor(content)
    with pdf_bridge.PdfBridgeBootstrap(slow_extractor) as bridge:
        connection = client(bridge)
        try:
            with pytest.raises(V2Error) as error:
                connection.extract(b"synthetic")
            assert error.value.code == "PDF_BRIDGE_TIMEOUT"
            with pytest.raises(V2Error) as error:
                connection.extract(b"synthetic")
            assert error.value.code == "PDF_BRIDGE_CLOSED"
        finally:
            connection.close()
