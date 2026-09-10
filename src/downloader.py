from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from config import AppConfig

try:
    import requests
except ImportError:  # pragma: no cover - handled at runtime.
    requests = None


class DownloadError(RuntimeError):
    """Raised when the ET Pro archive cannot be downloaded."""


@dataclass(frozen=True)
class DownloadResult:
    path: Path
    attempts: int
    status_code: int


class Downloader:
    def __init__(
        self,
        config: AppConfig,
        session: Optional[object] = None,
        sleep: Callable[[float], None] = time.sleep,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.config = config
        self.session = session if session is not None else self._default_session()
        self.sleep = sleep
        self.logger = logger or logging.getLogger(__name__)

    def download(self, now: Optional[datetime] = None) -> DownloadResult:
        destination = self.config.download_path(now)
        temp_path = Path(str(destination) + ".part")
        destination.parent.mkdir(parents=True, exist_ok=True)

        if destination.exists():
            if self.config.force_download:
                self.logger.info(
                    "Destination file exists, but force_download is enabled. Proceeding with download: %s",
                    destination,
                )
                try:
                    destination.unlink()
                except OSError as exc:
                    raise DownloadError(
                        f"force_download is enabled, but the existing file could not be deleted: {exc}"
                    ) from exc
            else:
                from validator import validate_archive
                archive_result = validate_archive(destination)
                if archive_result.is_valid:
                    self.logger.info(
                        "Destination file already exists and is a valid archive. Skipping download: %s",
                        destination,
                    )
                    return DownloadResult(
                        path=destination,
                        attempts=0,
                        status_code=200,
                    )
                else:
                    self.logger.warning(
                        "Destination file already exists but is invalid (%s). Attempting to delete and re-download: %s",
                        "; ".join(archive_result.errors),
                        destination,
                    )
                    try:
                        destination.unlink()
                    except OSError as exc:
                        raise DownloadError(
                            f"Destination already exists and is invalid, but could not be deleted: {exc}"
                        ) from exc

        # DNS / Network Probe
        import socket
        from urllib.parse import urlparse
        from config import SHUTDOWN_EVENT

        parsed_url = urlparse(self.config.download_url)
        host = parsed_url.hostname
        if host:
            dns_resolved = False
            for probe in range(3):
                if SHUTDOWN_EVENT.is_set():
                    break
                try:
                    socket.getaddrinfo(host, None)
                    dns_resolved = True
                    break
                except socket.gaierror:
                    if probe < 2:
                        self.sleep(1.0)
            if not dns_resolved:
                if SHUTDOWN_EVENT.is_set():
                    raise DownloadError("Download aborted due to system shutdown during network probe.")
                self.logger.error("Network probe failed: Unable to resolve hostname '%s'. DNS or network appears to be offline.", host)
                raise DownloadError(f"Network probe failed: Hostname '{host}' could not be resolved. Failsafe abort.")

        last_error: Optional[Exception] = None
        for attempt in range(1, self.config.max_attempts + 1):
            if SHUTDOWN_EVENT.is_set():
                self.logger.info("Shutdown signal received. Aborting downloader.")
                raise DownloadError("Downloader aborted due to system shutdown.")
                
            response = None
            try:
                self.logger.info(
                    "Downloading ET Pro rules from %s, attempt %s/%s",
                    self.config.masked_download_url,
                    attempt,
                    self.config.max_attempts,
                )
                response = self.session.get(
                    self.config.download_url,
                    stream=True,
                    timeout=(
                        self.config.connect_timeout_seconds,
                        self.config.request_timeout_seconds,
                    ),
                )
                status_code = int(getattr(response, "status_code", 0))
                if status_code != 200:
                    raise DownloadError(f"HTTP status code: {status_code}")

                with temp_path.open("wb") as output:
                    for chunk in response.iter_content(chunk_size=8192):
                        if SHUTDOWN_EVENT.is_set():
                            raise DownloadError("Download aborted due to system shutdown during write.")
                        if chunk:
                            output.write(chunk)

                temp_path.replace(destination)
                self.logger.info("Downloaded ET Pro rules to %s", destination)
                return DownloadResult(
                    path=destination,
                    attempts=attempt,
                    status_code=status_code,
                )
            except Exception as exc:
                last_error = exc
                self._remove_partial_file(temp_path)
                self.logger.warning(
                    "Download attempt %s/%s failed: %s",
                    attempt,
                    self.config.max_attempts,
                    exc,
                )
                if attempt >= self.config.max_attempts:
                    break
                
                # Sleep checking for shutdown. If a custom sleep function is provided (e.g. for unit testing),
                # we call it directly with the total retry interval so as not to break mock expectations.
                if self.sleep == time.sleep:
                    sleep_remaining = float(self.config.retry_interval_seconds)
                    while sleep_remaining > 0:
                        if SHUTDOWN_EVENT.is_set():
                            self.logger.info("Shutdown signal received during retry wait. Aborting downloader.")
                            raise DownloadError("Downloader aborted due to system shutdown.")
                        sleep_time = min(1.0, sleep_remaining)
                        self.sleep(sleep_time)
                        sleep_remaining -= sleep_time
                else:
                    self.sleep(float(self.config.retry_interval_seconds))
            finally:
                if response is not None:
                    close = getattr(response, "close", None)
                    if callable(close):
                        close()

        raise DownloadError(
            f"Failed to download ET Pro rules after {self.config.max_attempts} attempts"
        ) from last_error

    @staticmethod
    def _remove_partial_file(path: Path) -> None:
        try:
            if path.exists():
                path.unlink()
        except OSError:
            logging.getLogger(__name__).warning("Could not remove partial file: %s", path)

    @staticmethod
    def _default_session() -> object:
        if requests is None:
            raise DownloadError("The 'requests' package is required. Run: pip install -r requirements.txt")
        return requests.Session()
