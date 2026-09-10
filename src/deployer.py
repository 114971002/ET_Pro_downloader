from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class DeploymentError(RuntimeError):
    """Raised when selected rules cannot be deployed."""


@dataclass(frozen=True)
class DeploymentResult:
    source_path: Path
    target_path: Optional[Path]
    archived_path: Optional[Path]
    deployed: bool
    message: str


def deploy_rules_file(
    source_path: Path,
    target_path: Optional[Path],
    archive_dir: Optional[Path] = None,
    archive_date_stamp: Optional[str] = None,
) -> DeploymentResult:
    if target_path is None:
        return DeploymentResult(
            source_path=source_path,
            target_path=None,
            archived_path=None,
            deployed=False,
            message="Deployment skipped because target path is not configured.",
        )

    if not source_path.exists():
        raise DeploymentError(f"Selected rules file does not exist: {source_path}")

    destination = resolve_destination(source_path, target_path)
    if not destination.parent.exists():
        raise DeploymentError(f"Deployment target directory does not exist: {destination.parent}")

    archived_path = archive_existing_target(destination, archive_dir, archive_date_stamp)

    shutil.move(str(source_path), str(destination))
    return DeploymentResult(
        source_path=source_path,
        target_path=destination,
        archived_path=archived_path,
        deployed=True,
        message=f"Deployed selected rules to {destination}",
    )


def resolve_destination(source_path: Path, target_path: Path) -> Path:
    if target_path.exists() and target_path.is_dir():
        return target_path / source_path.name
    return target_path


def archive_existing_target(
    destination: Path,
    archive_dir: Optional[Path],
    archive_date_stamp: Optional[str],
) -> Optional[Path]:
    if not destination.exists():
        return None

    if archive_dir is None or archive_date_stamp is None:
        raise DeploymentError(
            f"Deployment target already exists but archive settings are incomplete: {destination}"
        )

    archive_dir.mkdir(parents=True, exist_ok=True)
    archived_path = archive_dir / f"{archive_date_stamp}_{destination.name}"
    if archived_path.exists():
        counter = 1
        while True:
            candidate_name = f"{archive_date_stamp}_{counter}_{destination.name}"
            candidate_path = archive_dir / candidate_name
            if not candidate_path.exists():
                archived_path = candidate_path
                break
            counter += 1

    shutil.move(str(destination), str(archived_path))
    return archived_path


def trigger_suricata_reload(config_object: Optional[object] = None) -> bool:
    """Triggers a zero-downtime hot reload of Suricata rules.
    Sends SIGHUP to the suricata process (on Unix) or triggers service control (on Windows).
    """
    import os
    import sys
    import subprocess
    import logging
    
    logger = logging.getLogger("deployer")
    logger.info("Initiating Suricata rule hot-reload...")
    
    # 1. Check if operating system is Windows
    if sys.platform.startswith("win"):
        try:
            result = subprocess.run(
                ["sc.exe", "control", "suricata", "128"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info("Successfully sent service control reload command to Suricata Windows Service.")
                return True
            else:
                logger.warning("SC command to reload Suricata service returned non-zero: %s. Suricata might not be running as a service.", result.stderr.strip())
        except Exception as e:
            logger.warning("Failed to execute sc.exe command: %s", e)
            
        # Fallback: check if suricata.exe is running as a process
        try:
            result = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq suricata.exe"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if "suricata.exe" in result.stdout:
                logger.info("Found active 'suricata.exe' process running. Service control failed, please check Suricata logs to confirm reload.")
            else:
                logger.warning("No active 'suricata.exe' process detected running on Windows.")
        except Exception as e:
            logger.warning("Failed to check tasklist: %s", e)
            
    else:
        # 2. Unix / Linux / macOS: Send SIGHUP signal
        pids = []
        pid_paths = [
            Path("/var/run/suricata.pid"),
            Path("/var/run/suricata/suricata.pid"),
            Path("/run/suricata.pid"),
        ]
        
        if config_object is not None:
            project_root = getattr(config_object, "project_root", None)
            if project_root:
                pid_paths.append(Path(project_root) / "deploy" / "suricata.pid")
                pid_paths.append(Path(project_root) / "run" / "suricata.pid")
                
        for path in pid_paths:
            if path.exists():
                try:
                    pid = int(path.read_text().strip())
                    pids.append(pid)
                except Exception:
                    pass
                    
        try:
            result = subprocess.run(
                ["pkill", "-HUP", "suricata"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info("Successfully sent SIGHUP signal to all 'suricata' processes via pkill.")
                return True
        except Exception:
            pass
            
        import signal
        success = False
        for pid in pids:
            try:
                os.kill(pid, signal.SIGHUP)
                logger.info("Successfully sent SIGHUP signal to Suricata process PID %d.", pid)
                success = True
            except ProcessLookupError:
                logger.warning("Suricata PID file exists but process PID %d was not found.", pid)
            except Exception as e:
                logger.warning("Failed to send SIGHUP signal to PID %d: %s", pid, e)
                
        if success:
            return True
            
        logger.warning("Could not trigger Suricata reload: No running Suricata processes found or permission denied.")
        
    return False
