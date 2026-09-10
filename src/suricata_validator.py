from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Optional

from config import AppConfig


class RuleValidationError(RuntimeError):
    """Raised when rule validation fails or cannot be executed."""
    def __init__(self, message: str, stdout: str = "", stderr: str = "") -> None:
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr


def validate_rules_file(
    rules_path: Path,
    config: AppConfig,
    logger: Optional[logging.Logger] = None,
) -> None:
    logger = logger or logging.getLogger(__name__)

    if not config.suricata_validation_enabled:
        logger.info("Suricata rules validation is disabled by configuration.")
        return

    logger.info("Starting Suricata dry-run rule validation on %s", rules_path)

    # Verify that executable and config exist
    if not config.suricata_exe_path.exists():
        raise RuleValidationError(f"Suricata executable not found at: {config.suricata_exe_path}")
    if not config.suricata_yaml_path.exists():
        raise RuleValidationError(f"Suricata config yaml not found at: {config.suricata_yaml_path}")
    if not rules_path.exists():
        raise RuleValidationError(f"Rules file to validate does not exist: {rules_path}")

    # Prepare command arguments
    # -T: Test configuration
    # -c: Path to configuration file
    # -S: Loaded exclusively
    # -l: Redirect logs to project log directory to avoid Program Files permission errors
    args = [
        str(config.suricata_exe_path),
        "-T",
        "-c",
        str(config.suricata_yaml_path),
        "-S",
        str(rules_path),
        "-l",
        str(config.logs_dir),
    ]

    # Prepend Npcap directory to PATH to load Npcap/WinPcap DLLs on Windows
    env = os.environ.copy()
    path_key = "PATH"
    for k in list(env.keys()):
        if k.upper() == "PATH":
            path_key = k
            break
    old_path = env.get(path_key, "")
    
    npcap_str = str(config.npcap_dir_path)
    if npcap_str not in old_path:
        env[path_key] = f"{npcap_str};{old_path}"

    logger.info("Executing Suricata dry-run validation...")
    try:
        result = subprocess.run(
            args,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuleValidationError("Suricata dry-run validation timed out after 120 seconds") from exc
    except Exception as exc:
        raise RuleValidationError(f"Failed to execute Suricata process: {exc}") from exc

    # Log stdout and stderr details
    if result.stdout.strip():
        logger.debug("Suricata stdout:\n%s", result.stdout)
    if result.stderr.strip():
        logger.debug("Suricata stderr:\n%s", result.stderr)

    if result.returncode != 0:
        # Extract meaningful error messages
        error_lines = []
        
        # Combine stdout and stderr outputs
        output_text = f"{result.stdout}\n{result.stderr}"
        for line in output_text.splitlines():
            line_stripped = line.strip()
            # Catch lines starting with E: (Suricata error prefix) or containing error/failed
            if line_stripped.startswith("E:") or "error" in line_stripped.lower() or "failed" in line_stripped.lower():
                error_lines.append(line_stripped)

        error_summary = "; ".join(error_lines) if error_lines else f"Exit code: {result.returncode}"
        logger.warning("Suricata dry-run validation failed: %s", error_summary)
        raise RuleValidationError(
            f"Suricata rule validation failed: {error_summary}",
            stdout=result.stdout,
            stderr=result.stderr,
        )

    logger.info("Suricata rules validation completed successfully.")
