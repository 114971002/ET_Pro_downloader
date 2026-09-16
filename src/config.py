from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping, Optional

try:
    from zoneinfo import ZoneInfo
    from zoneinfo import ZoneInfoNotFoundError
except ImportError:  # pragma: no cover - for very old Python versions.
    ZoneInfo = None
    ZoneInfoNotFoundError = None


OINKCODE_ENV = "ETPRO_OINKCODE"
DEPLOY_TARGET_ENV = "ETPRO_DEPLOY_TARGET_PATH"

SURICATA_VERSION_ENV = "ETPRO_SURICATA_VERSION"
VALIDATION_ENABLED_ENV = "ETPRO_SURICATA_VALIDATION_ENABLED"
INTEL_SYNC_ENABLED_ENV = "ETPRO_INTEL_SYNC_ENABLED"
SURICATA_EXE_ENV = "ETPRO_SURICATA_EXE"
SURICATA_YAML_ENV = "ETPRO_SURICATA_YAML"
NPCAP_DIR_ENV = "ETPRO_NPCAP_DIR"
FORCE_DOWNLOAD_ENV = "ETPRO_FORCE_DOWNLOAD"
DEPLOY_ARCHIVE_ENV = "ETPRO_DEPLOY_ARCHIVE_PATH"
DEPLOY_ARCHIVE_RETENTION_ENV = "ETPRO_DEPLOY_ARCHIVE_RETENTION_DAYS"

TRANSFER_OUTPUT_DIR_ENV = "ETPRO_TRANSFER_OUTPUT_DIR"
TRANSFER_RETENTION_ENV = "ETPRO_TRANSFER_RETENTION_DAYS"

SURICATA_VERSION_DEFAULT = "8.0"
SURICATA_EXE_DEFAULT = r"C:\Program Files\Suricata\suricata.exe"
SURICATA_YAML_DEFAULT = r"C:\Program Files\Suricata\suricata.yaml"
NPCAP_DIR_DEFAULT = r"C:\Windows\System32\Npcap"

SOURCE_FILENAME = "etpro.rules.tar.gz"
DEPLOY_FILENAME = "deploy.rules"
DOWNLOAD_BASE_URL = "https://rules.emergingthreatspro.com"
TAIPEI_TZ = timezone(timedelta(hours=8), "Asia/Taipei")


class ConfigError(RuntimeError):
    """Raised when required runtime configuration is missing or invalid."""


@dataclass(frozen=True)
class AppConfig:
    project_root: Path
    etpro_oinkcode: str
    deploy_target_path: Optional[Path]
    downloads_dir: Path
    logs_dir: Path
    reports_dir: Path
    output_dir: Path
    deploy_dir: Path
    deploy_archive_dir: Path
    transfer_output_dir: Optional[Path] = None
    transfer_retention_days: int = 30
    deploy_archive_retention_days: int = 30
    suricata_version: str = SURICATA_VERSION_DEFAULT
    source_filename: str = SOURCE_FILENAME
    deploy_filename: str = DEPLOY_FILENAME
    retry_count: int = 10
    retry_interval_seconds: int = 180
    request_timeout_seconds: int = 60
    connect_timeout_seconds: int = 10
    download_retention_days: int = 30
    report_retention_days: int = 90
    suricata_validation_enabled: bool = True
    intel_sync_enabled: bool = True
    suricata_exe_path: Path = Path(SURICATA_EXE_DEFAULT)
    suricata_yaml_path: Path = Path(SURICATA_YAML_DEFAULT)
    npcap_dir_path: Path = Path(NPCAP_DIR_DEFAULT)
    force_download: bool = False

    @classmethod
    def from_env(
        cls,
        project_root: Optional[Path] = None,
        env: Optional[Mapping[str, str]] = None,
        require_oinkcode: bool = True,
    ) -> "AppConfig":
        env_map = env if env is not None else os.environ
        root = Path(project_root) if project_root is not None else default_project_root()
        root = root.resolve()

        def get_env_or_reg(var_name: str, default: str = "") -> str:
            val = env_map.get(var_name, "").strip()
            if not val and env is None and os.name == "nt":
                try:
                    import winreg
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                        reg_val, _ = winreg.QueryValueEx(key, var_name)
                        val = str(reg_val).strip()
                except Exception:
                    pass
            return val if val else default

        oinkcode = get_env_or_reg(OINKCODE_ENV)
        if require_oinkcode and not oinkcode:
            raise ConfigError(f"Missing required environment variable: {OINKCODE_ENV}")

        deploy_target_raw = get_env_or_reg(DEPLOY_TARGET_ENV)
        deploy_target_path = build_deploy_target_path(root, deploy_target_raw)

        validation_enabled_raw = get_env_or_reg(VALIDATION_ENABLED_ENV, "true").lower()
        validation_enabled = validation_enabled_raw in ("true", "1", "yes", "on")

        intel_sync_enabled_raw = get_env_or_reg(INTEL_SYNC_ENABLED_ENV, "true").lower()
        intel_sync_enabled = intel_sync_enabled_raw in ("true", "1", "yes", "on")

        suricata_version = get_env_or_reg(SURICATA_VERSION_ENV, SURICATA_VERSION_DEFAULT)

        suricata_exe = Path(get_env_or_reg(SURICATA_EXE_ENV, SURICATA_EXE_DEFAULT))
        suricata_yaml = Path(get_env_or_reg(SURICATA_YAML_ENV, SURICATA_YAML_DEFAULT))
        npcap_dir = Path(get_env_or_reg(NPCAP_DIR_ENV, NPCAP_DIR_DEFAULT))
        force_download_raw = get_env_or_reg(FORCE_DOWNLOAD_ENV, "false").lower()
        force_download = force_download_raw in ("true", "1", "yes", "on")

        deploy_archive_raw = env_map.get(DEPLOY_ARCHIVE_ENV, "").strip()
        if deploy_archive_raw:
            deploy_archive_dir = Path(deploy_archive_raw).expanduser()
            deploy_archive_dir = deploy_archive_dir if deploy_archive_dir.is_absolute() else root / deploy_archive_dir
        else:
            deploy_archive_dir = root / "deploy" / "archive"

        retention_days_raw = env_map.get(DEPLOY_ARCHIVE_RETENTION_ENV, "30").strip()
        try:
            deploy_archive_retention_days = int(retention_days_raw)
        except ValueError:
            deploy_archive_retention_days = 30

        transfer_output_raw = get_env_or_reg(TRANSFER_OUTPUT_DIR_ENV)
        if transfer_output_raw:
            transfer_output_dir = Path(transfer_output_raw).expanduser()
            transfer_output_dir = transfer_output_dir if transfer_output_dir.is_absolute() else root / transfer_output_dir
        else:
            transfer_output_dir = root / "output"

        transfer_retention_raw = get_env_or_reg(TRANSFER_RETENTION_ENV, "30").strip()
        try:
            transfer_retention_days = int(transfer_retention_raw)
        except ValueError:
            transfer_retention_days = 30

        return cls(
            project_root=root,
            etpro_oinkcode=oinkcode,
            deploy_target_path=deploy_target_path,
            downloads_dir=root / "downloads",
            logs_dir=root / "logs",
            reports_dir=root / "reports",
            output_dir=root / "output",
            deploy_dir=root / "deploy",
            deploy_archive_dir=deploy_archive_dir,
            deploy_archive_retention_days=deploy_archive_retention_days,
            transfer_output_dir=transfer_output_dir,
            transfer_retention_days=transfer_retention_days,
            suricata_version=suricata_version,
            suricata_validation_enabled=validation_enabled,
            intel_sync_enabled=intel_sync_enabled,
            suricata_exe_path=suricata_exe,
            suricata_yaml_path=suricata_yaml,
            npcap_dir_path=npcap_dir,
            force_download=force_download,
        )

    def ensure_directories(self) -> None:
        dirs_to_create = [
            self.downloads_dir,
            self.logs_dir,
            self.reports_dir,
            self.output_dir,
            self.deploy_dir,
            self.deploy_archive_dir,
        ]
        if self.transfer_output_dir is not None:
            dirs_to_create.append(self.transfer_output_dir)
        for directory in dirs_to_create:
            directory.mkdir(parents=True, exist_ok=True)

    @property
    def max_attempts(self) -> int:
        return self.retry_count + 1

    @property
    def download_url(self) -> str:
        if not self.etpro_oinkcode:
            return ""
        return (
            f"{DOWNLOAD_BASE_URL}/{self.etpro_oinkcode}/"
            f"suricata-{self.suricata_version}/{self.source_filename}"
        )

    @property
    def masked_download_url(self) -> str:
        if not self.etpro_oinkcode:
            return ""
        return self.download_url.replace(self.etpro_oinkcode, mask_secret(self.etpro_oinkcode))

    def date_stamp(self, now: Optional[datetime] = None) -> str:
        return taipei_now(now).strftime("%Y%m%d")

    def download_path(self, now: Optional[datetime] = None) -> Path:
        return self.downloads_dir / f"{self.date_stamp(now)}_{self.source_filename}"

    def report_path(self, now: Optional[datetime] = None) -> Path:
        return self.reports_dir / f"daily_analysis_{self.date_stamp(now)}.csv"

    def selected_rules_path(self, now: Optional[datetime] = None) -> Path:
        return self.output_dir / f"selected_rules_{self.date_stamp(now)}.rules"

    def staged_deploy_rules_path(self) -> Path:
        return self.output_dir / self.deploy_filename

    def transfer_path(self, now: Optional[datetime] = None) -> Path:
        target_dir = self.transfer_output_dir or self.output_dir
        return target_dir / f"{self.date_stamp(now)}_transfer.txt"

    def previous_date_stamp(self, now: Optional[datetime] = None) -> str:
        return (taipei_now(now) - timedelta(days=1)).strftime("%Y%m%d")


def default_project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def build_deploy_target_path(root: Path, raw_path: str) -> Optional[Path]:
    if not raw_path:
        return root / "deploy" / DEPLOY_FILENAME

    target_path = Path(raw_path).expanduser()
    target_path = target_path if target_path.is_absolute() else root / target_path
    if str(raw_path).endswith(("\\", "/")):
        return target_path / DEPLOY_FILENAME
    if target_path.exists() and target_path.is_dir():
        return target_path / DEPLOY_FILENAME
    return target_path


def taipei_timezone():
    if ZoneInfo is None:
        return TAIPEI_TZ

    try:
        return ZoneInfo("Asia/Taipei")
    except Exception as exc:
        if ZoneInfoNotFoundError is not None and isinstance(exc, ZoneInfoNotFoundError):
            return TAIPEI_TZ
        raise


def taipei_now(now: Optional[datetime] = None) -> datetime:
    if now is None:
        return datetime.now(taipei_timezone())
    if now.tzinfo is None:
        return now.replace(tzinfo=taipei_timezone())
    return now.astimezone(taipei_timezone())


def mask_secret(secret: str) -> str:
    if len(secret) <= 4:
        return "****"
    return f"{secret[:2]}****{secret[-2:]}"


# Global shutdown event for graceful termination of pipeline worker threads
SHUTDOWN_EVENT = threading.Event()
