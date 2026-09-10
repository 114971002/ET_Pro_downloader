from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path
import sys
import logging

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from config import AppConfig
from downloader import Downloader, DownloadError


LOGGER = logging.getLogger("test_downloader")
LOGGER.addHandler(logging.NullHandler())
LOGGER.propagate = False


class FakeResponse:
    def __init__(self, status_code: int, chunks=None) -> None:
        self.status_code = status_code
        self.chunks = chunks or []
        self.closed = False

    def iter_content(self, chunk_size: int):
        for chunk in self.chunks:
            yield chunk

    def close(self) -> None:
        self.closed = True


class FakeSession:
    def __init__(self, responses) -> None:
        self.responses = list(responses)
        self.calls = []

    def get(self, url, stream, timeout):
        self.calls.append((url, stream, timeout))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class DownloaderTests(unittest.TestCase):
    def make_config(self, root: Path) -> AppConfig:
        return AppConfig.from_env(
            project_root=root,
            env={"ETPRO_OINKCODE": "abcdef123456"},
        )

    def test_successful_download_writes_dated_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            config.ensure_directories()
            session = FakeSession([FakeResponse(200, [b"abc", b"def"])])
            sleeps = []

            result = Downloader(
                config,
                session=session,
                sleep=sleeps.append,
                logger=LOGGER,
            ).download(datetime(2026, 5, 15))

            self.assertEqual(result.path.name, "20260515_etpro.rules.tar.gz")
            self.assertEqual(result.path.read_bytes(), b"abcdef")
            self.assertEqual(result.attempts, 1)
            self.assertEqual(sleeps, [])

    def test_failed_download_retries_ten_times(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            config.ensure_directories()
            session = FakeSession([FakeResponse(500)] * 11)
            sleeps = []

            with self.assertRaises(DownloadError):
                Downloader(
                    config,
                    session=session,
                    sleep=sleeps.append,
                    logger=LOGGER,
                ).download(datetime(2026, 5, 15))

            self.assertEqual(len(session.calls), 11)
            self.assertEqual(sleeps, [180] * 10)

    def test_existing_valid_download_is_reused(self) -> None:
        import tarfile
        import io
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            config.ensure_directories()
            now = datetime(2026, 5, 15)
            destination = config.download_path(now)
            
            # Create a valid tar.gz archive with a .rules file
            with tarfile.open(destination, mode="w:gz") as tar:
                info = tarfile.TarInfo(name="test.rules")
                content = b"alert tcp any any -> any any (msg:\"test\"; sid:1;)"
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
            
            session = FakeSession([FakeResponse(200, [b"new"])])

            result = Downloader(
                config,
                session=session,
                sleep=lambda _: None,
                logger=LOGGER,
            ).download(now)

            self.assertEqual(result.path, destination)
            self.assertEqual(result.attempts, 0)
            self.assertEqual(result.status_code, 200)
            self.assertEqual(session.calls, [])  # No download attempted

    def test_existing_invalid_download_is_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            config.ensure_directories()
            now = datetime(2026, 5, 15)
            destination = config.download_path(now)
            destination.write_bytes(b"invalid_archive_content")
            
            session = FakeSession([FakeResponse(200, [b"new_data"])])

            result = Downloader(
                config,
                session=session,
                sleep=lambda _: None,
                logger=LOGGER,
            ).download(now)

            self.assertEqual(result.path, destination)
            self.assertEqual(destination.read_bytes(), b"new_data")
            self.assertEqual(result.attempts, 1)
            self.assertEqual(len(session.calls), 1)

    def test_existing_invalid_download_unlink_failure_raises_error(self) -> None:
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp))
            config.ensure_directories()
            now = datetime(2026, 5, 15)
            destination = config.download_path(now)
            destination.write_bytes(b"invalid_archive_content")
            
            session = FakeSession([FakeResponse(200, [b"new_data"])])

            # Mock Path.unlink to raise OSError (e.g. PermissionError or file in use)
            with patch.object(Path, "unlink", side_effect=OSError("Permission denied")):
                with self.assertRaises(DownloadError) as ctx:
                    Downloader(
                        config,
                        session=session,
                        sleep=lambda _: None,
                        logger=LOGGER,
                    ).download(now)
                self.assertIn("could not be deleted", str(ctx.exception))
                
            self.assertEqual(destination.read_bytes(), b"invalid_archive_content")
            self.assertEqual(session.calls, [])  # No download attempted

    def test_existing_valid_download_is_overwritten_if_force_download_enabled(self) -> None:
        import tarfile
        import io
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig.from_env(
                project_root=Path(tmp),
                env={"ETPRO_OINKCODE": "abcdef123456", "ETPRO_FORCE_DOWNLOAD": "true"},
            )
            config.ensure_directories()
            now = datetime(2026, 5, 15)
            destination = config.download_path(now)
            
            # Create a valid tar.gz archive with a .rules file
            with tarfile.open(destination, mode="w:gz") as tar:
                info = tarfile.TarInfo(name="test.rules")
                content = b"alert tcp any any -> any any (msg:\"test\"; sid:1;)"
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
            
            session = FakeSession([FakeResponse(200, [b"new_data"])])

            result = Downloader(
                config,
                session=session,
                sleep=lambda _: None,
                logger=LOGGER,
            ).download(now)

            self.assertEqual(result.path, destination)
            self.assertEqual(destination.read_bytes(), b"new_data")
            self.assertEqual(result.attempts, 1)
            self.assertEqual(len(session.calls), 1)

    def test_force_download_unlink_failure_raises_error(self) -> None:
        from unittest.mock import patch
        import tarfile
        import io
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig.from_env(
                project_root=Path(tmp),
                env={"ETPRO_OINKCODE": "abcdef123456", "ETPRO_FORCE_DOWNLOAD": "true"},
            )
            config.ensure_directories()
            now = datetime(2026, 5, 15)
            destination = config.download_path(now)
            
            # Create a valid tar.gz archive with a .rules file
            with tarfile.open(destination, mode="w:gz") as tar:
                info = tarfile.TarInfo(name="test.rules")
                content = b"alert tcp any any -> any any (msg:\"test\"; sid:1;)"
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
            
            session = FakeSession([FakeResponse(200, [b"new_data"])])

            # Mock Path.unlink to raise OSError
            with patch.object(Path, "unlink", side_effect=OSError("Permission denied")):
                with self.assertRaises(DownloadError) as ctx:
                    Downloader(
                        config,
                        session=session,
                        sleep=lambda _: None,
                        logger=LOGGER,
                    ).download(now)
                self.assertIn("force_download is enabled, but the existing file could not be deleted", str(ctx.exception))
                
            self.assertEqual(session.calls, [])  # No download attempted


if __name__ == "__main__":
    unittest.main()
