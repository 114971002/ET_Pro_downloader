from __future__ import annotations

import logging
import sys
import time
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from analyzer import analyze_archive
from config import AppConfig, ConfigError, default_project_root, taipei_now, SHUTDOWN_EVENT
from deployer import deploy_rules_file
from downloader import Downloader
from retention import cleanup_old_files
from rule_exporter import export_uncommented_rules
from suricata_validator import RuleValidationError, validate_rules_file
from validator import raise_if_invalid, validate_archive



@dataclass(frozen=True)
class RunResult:
    download_path: Path
    report_path: Path
    deploy_rules_path: Path
    archived_deploy_rules_path: Optional[Path]
    deployed: bool
    deploy_rule_count: int
    total_rules: int
    deleted_downloads: int
    deleted_reports: int
    deleted_deploy_archives: int = 0


def setup_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)


def extract_error_for_line(error_text: str, line_idx: int) -> str:
    """Helper to parse a specific Suricata parsing error for a given line number."""
    lines = [line.strip() for line in error_text.split("\n") if line.strip()]
    relevant_errors = []
    
    for i, line in enumerate(lines):
        if f"at line {line_idx}" in line or f"line {line_idx}" in line:
            if i > 0 and lines[i-1].startswith("E: ") and "error parsing signature" not in lines[i-1]:
                msg = lines[i-1].split("E: ", 1)[-1].strip()
                relevant_errors.append(msg)
            
            m = re.match(r"^E:\s*([^:]+:\s*[^\"(]+)", line)
            if m:
                relevant_errors.append(m.group(1).strip())
                
    if relevant_errors:
        clean_msg = " | ".join(relevant_errors)
        return clean_msg[:200]
    return "Suricata validation failed"


def run_once(
    config: Optional[AppConfig] = None,
    now: Optional[datetime] = None,
    session: Optional[object] = None,
    sleep=None,
) -> RunResult:
    if SHUTDOWN_EVENT.is_set():
        raise RuntimeError("Job aborted due to system shutdown.")
    config = config or AppConfig.from_env(default_project_root())
    config.ensure_directories()

    logger = logging.getLogger(__name__)
    downloader = Downloader(
        config=config,
        session=session,
        sleep=sleep if sleep is not None else time.sleep,
        logger=logging.getLogger("downloader"),
    )

    date_stamp = config.date_stamp(now)
    logger.info("ET Pro daily job started for %s", date_stamp)

    download_result = downloader.download(now)
    validation_result = validate_archive(download_result.path)
    logger.info(
        "Validation result: valid=%s, rule_files=%s",
        validation_result.is_valid,
        len(validation_result.rule_files),
    )
    raise_if_invalid(validation_result)

    analysis_result = analyze_archive(
        archive_path=download_result.path,
        report_path=config.report_path(now),
        date_stamp=date_stamp,
    )
    logger.info(
        "Analysis report generated at %s with %s rules",
        analysis_result.report_path,
        analysis_result.total_rules,
    )

    export_result = export_uncommented_rules(
        archive_path=download_result.path,
        output_path=config.staged_deploy_rules_path(),
    )
    logger.info(
        "Deploy rules file staged at %s with %s uncommented rules",
        export_result.output_path,
        export_result.rule_count,
    )

    rules_path = export_result.output_path
    max_heal_attempts = 10
    attempt = 0
    run_timestamp_dir = None

    while attempt < max_heal_attempts:
        if SHUTDOWN_EVENT.is_set():
            logger.info("Shutdown signal received. Aborting auto-healing.")
            raise RuntimeError("Job aborted due to system shutdown.")
        attempt += 1
        try:
            validate_rules_file(
                rules_path=rules_path,
                config=config,
                logger=logger,
            )
            # Validation succeeded!
            if attempt > 1:
                logger.info("Rules file successfully validated after auto-healing (%d attempts).", attempt)
            break
        except RuleValidationError as exc:
            # If there's no output to parse, or if we have reached max attempts, propagate the exception.
            if not exc.stdout and not exc.stderr:
                logger.error("Catastrophic validation failure (no output logs): %s", exc)
                raise
            
            if attempt >= max_heal_attempts:
                logger.error("Reached maximum rules healing attempts (%d). Aborting.", max_heal_attempts)
                raise
            
            # Initialize debug directory on first failure
            if run_timestamp_dir is None:
                timestamp = taipei_now(now).strftime("%Y%m%d_%H%M%S")
                run_timestamp_dir = config.logs_dir / "failed_rules" / f"run_{timestamp}"
                run_timestamp_dir.mkdir(parents=True, exist_ok=True)
                logger.warning(
                    "Validation failed on attempt %d. Initiating auto-healing pipeline. Debug logs will be saved to %s",
                    attempt,
                    run_timestamp_dir,
                )
            
            # Parse line numbers from the error logs
            error_text = f"{exc.stdout}\n{exc.stderr}"
            pattern = re.compile(rf"{re.escape(rules_path.name)}\s+at\s+line\s+(\d+)", re.IGNORECASE)
            failed_lines = sorted(list(set(int(m) for m in pattern.findall(error_text))))
            
            if not failed_lines:
                logger.error("Validation failed but no rule line numbers could be parsed from output. Cannot auto-heal. Error: %s", exc)
                raise
            
            logger.info("Found %d failed rule lines to comment out in attempt %d: %s", len(failed_lines), attempt, failed_lines)
            
            # Read rules
            with rules_path.open("r", encoding="utf-8", errors="replace") as f:
                rules_lines = f.readlines()
            
            # Extract failed rules and save them
            failed_rules_content = []
            for line_idx in failed_lines:
                if 1 <= line_idx <= len(rules_lines):
                    failed_rules_content.append(f"Line {line_idx}: {rules_lines[line_idx - 1]}")
            
            # Write debug logs for this round
            failed_rules_file = run_timestamp_dir / f"round{attempt}_failed_rules.rules"
            failed_rules_file.write_text("".join(failed_rules_content), encoding="utf-8")
            
            suricata_log_file = run_timestamp_dir / f"round{attempt}_suricata_error.log"
            suricata_log_file.write_text(error_text, encoding="utf-8")
            
            # Comment out the failed lines in rules_lines
            for line_idx in failed_lines:
                if 1 <= line_idx <= len(rules_lines):
                    orig_line = rules_lines[line_idx - 1]
                    if not orig_line.lstrip().startswith("#"):
                        error_reason = extract_error_for_line(error_text, line_idx)
                        prefix = f"# [VALIDATION FAILED - {taipei_now(now).strftime('%Y-%m-%d %H:%M:%S')} - {error_reason}] "
                        rules_lines[line_idx - 1] = prefix + orig_line
            
            # Write back the modified rules
            with rules_path.open("w", encoding="utf-8", newline="\n") as f:
                f.writelines(rules_lines)


    deployment_result = deploy_rules_file(
        source_path=export_result.output_path,
        target_path=config.deploy_target_path,
        archive_dir=config.deploy_archive_dir,
        archive_date_stamp=config.previous_date_stamp(now),
    )
    logger.info(deployment_result.message)
    if deployment_result.archived_path is not None:
        logger.info("Archived previous deploy rules to %s", deployment_result.archived_path)
        
    # Trigger zero-downtime hot reload of Suricata rules
    from deployer import trigger_suricata_reload
    trigger_suricata_reload(config)

    cleanup_result = cleanup_old_files(
        downloads_dir=config.downloads_dir,
        reports_dir=config.reports_dir,
        now=now,
        download_retention_days=config.download_retention_days,
        report_retention_days=config.report_retention_days,
        deploy_archive_dir=config.deploy_archive_dir,
        deploy_archive_retention_days=config.deploy_archive_retention_days,
        logger=logger,
    )
    logger.info(
        "Retention cleanup finished: deleted_downloads=%s, deleted_reports=%s, deleted_deploy_archives=%s",
        cleanup_result.deleted_downloads,
        cleanup_result.deleted_reports,
        cleanup_result.deleted_deploy_archives,
    )
    logger.info("ET Pro daily job finished")

    return RunResult(
        download_path=download_result.path,
        report_path=analysis_result.report_path,
        deploy_rules_path=deployment_result.target_path or export_result.output_path,
        archived_deploy_rules_path=deployment_result.archived_path,
        deployed=deployment_result.deployed,
        deploy_rule_count=export_result.rule_count,
        total_rules=analysis_result.total_rules,
        deleted_downloads=cleanup_result.deleted_downloads,
        deleted_reports=cleanup_result.deleted_reports,
        deleted_deploy_archives=cleanup_result.deleted_deploy_archives,
    )


def main() -> int:
    project_root = default_project_root()
    setup_logging(project_root / "logs" / "download.log")
    logger = logging.getLogger(__name__)

    try:
        config = AppConfig.from_env(project_root)
        if config.intel_sync_enabled:
            logger.info("Synchronizing threat intelligence mappings from MITRE ATT&CK...")
            try:
                from update_intel import main as sync_intel
                sync_intel(config_dir=config.project_root / "config")
                logger.info("Threat intelligence mappings synchronization complete.")
            except Exception as sync_exc:
                logger.warning(
                    "Threat intelligence sync failed: %s. Using local configurations/defaults.", 
                    sync_exc
                )
        else:
            logger.info("Threat intelligence sync is disabled via configuration.")

        run_once(config=config)
        return 0
    except ConfigError as exc:
        logger.error("Configuration error: %s", exc)
        return 2
    except Exception:
        logger.exception("ET Pro daily job failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
