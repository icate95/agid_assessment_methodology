"""Core engine for AGID assessment methodology.

This module provides the main assessment engine that coordinates the execution of
security checks across different systems and environments.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type, Union

from pydantic import BaseModel, Field

from agid_assessment_methodology.checks import BaseCheck
from agid_assessment_methodology.config.settings import settings
from agid_assessment_methodology.core.reporter import Reporter
from agid_assessment_methodology.core.storage import AssessmentStore
from agid_assessment_methodology.utils.exceptions import AssessmentError

logger = logging.getLogger(__name__)


class TargetType(str, Enum):
    """Type of target system."""

    WINDOWS = "windows"
    LINUX = "linux"
    LOCAL = "local"


class Target(BaseModel):
    """Target system for assessment."""

    name: str
    host: str = Field(default="localhost")
    type: TargetType
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    key_file: Optional[Path] = None
    domain: Optional[str] = None  # For Windows domain authentication


class AssessmentResult(BaseModel):
    """Result of an individual check."""

    check_id: str
    target: str
    status: bool
    score: float
    details: Dict[str, Any]
    timestamp: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None


class AssessmentSummary(BaseModel):
    """Summary of all check results for a target."""

    target: str
    target_type: TargetType
    total_checks: int
    passed_checks: int
    failed_checks: int
    overall_score: float
    results: List[AssessmentResult]
    timestamp: str


class AssessmentEngine:
    """Main engine for running security assessments."""

    def __init__(
        self,
        storage: Optional[AssessmentStore] = None,
        reporter: Optional[Reporter] = None,
        max_workers: int = 10,
    ):
        """Initialize the assessment engine.

        Args:
            storage: Storage backend for assessment results
            reporter: Reporter for generating assessment reports
            max_workers: Maximum number of concurrent workers for parallel assessment
        """
        self.storage = storage or AssessmentStore()
        self.reporter = reporter or Reporter()
        self.max_workers = max_workers
        self.available_checks: Dict[str, Type[BaseCheck]] = {}
        self._discover_checks()

    def _discover_checks(self) -> None:
        """Discover all available security checks."""
        # This will be implemented to dynamically discover check modules
        # For now, we'll manually register checks in the specific module implementations
        logger.info("Discovering available security checks...")

    def register_check(self, check_class: Type[BaseCheck]) -> None:
        """Register a security check with the engine.

        Args:
            check_class: The check class to register
        """
        if not hasattr(check_class, "check_id"):
            raise AssessmentError(f"Check class {check_class.__name__} has no check_id")

        check_id = check_class.check_id
        self.available_checks[check_id] = check_class
        logger.debug(f"Registered check: {check_id}")

    def run_assessment(
        self,
        target: Target,
        check_ids: Optional[List[str]] = None,
        parallel: bool = True,
    ) -> AssessmentSummary:
        """Run an assessment on a target.

        Args:
            target: Target system to assess
            check_ids: List of check IDs to run, or None for all checks
            parallel: Whether to run checks in parallel

        Returns:
            Assessment summary with results
        """
        logger.info(f"Starting assessment on target: {target.name}")

        # Determine which checks to run
        checks_to_run = self._get_checks_to_run(target.type, check_ids)
        if not checks_to_run:
            logger.warning(f"No applicable checks found for target: {target.name}")
            raise AssessmentError(f"No applicable checks found for target: {target.name}")

        # Run the checks
        results = []
        if parallel and len(checks_to_run) > 1:
            results = self._run_parallel(target, checks_to_run)
        else:
            results = self._run_sequential(target, checks_to_run)

        # Create and store the summary
        summary = self._create_summary(target, results)
        self.storage.store_assessment(summary)

        logger.info(
            f"Assessment completed for {target.name}. "
            f"Score: {summary.overall_score:.2f}%"
        )
        return summary

    def _get_checks_to_run(
        self, target_type: TargetType, check_ids: Optional[List[str]] = None
    ) -> List[Type[BaseCheck]]:
        """Get the list of checks to run based on target type and requested checks.

        Args:
            target_type: Type of target system
            check_ids: List of check IDs to run, or None for all checks

        Returns:
            List of check classes to run
        """
        if not self.available_checks:
            logger.warning("No checks are registered with the engine")
            return []

        # Filter by check IDs if specified
        checks = (
            [
                check
                for check_id, check in self.available_checks.items()
                if check_id in check_ids
            ]
            if check_ids
            else list(self.available_checks.values())
        )

        # Filter by target type compatibility
        return [
            check
            for check in checks
            if not hasattr(check, "supported_systems")
            or target_type.value in check.supported_systems
        ]

    def _run_sequential(
        self, target: Target, checks: List[Type[BaseCheck]]
    ) -> List[AssessmentResult]:
        """Run checks sequentially.

        Args:
            target: Target system to assess
            checks: List of check classes to run

        Returns:
            List of assessment results
        """
        results = []
        for check_class in checks:
            try:
                check = check_class(target)
                result = check.run()
                results.append(result)
                logger.debug(
                    f"Check {check.check_id} on {target.name}: "
                    f"{'PASSED' if result.status else 'FAILED'}"
                )
            except Exception as e:
                logger.error(
                    f"Error running check {check_class.check_id} on {target.name}: {e}"
                )
                # Create a failure result
                # This will be implemented to handle check failures gracefully

        return results

    def _run_parallel(
        self, target: Target, checks: List[Type[BaseCheck]]
    ) -> List[AssessmentResult]:
        """Run checks in parallel.

        Args:
            target: Target system to assess
            checks: List of check classes to run

        Returns:
            List of assessment results
        """
        results = []
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(checks))) as executor:
            # Submit all checks
            futures = []
            for check_class in checks:
                try:
                    check = check_class(target)
                    future = executor.submit(check.run)
                    futures.append((check.check_id, future))
                except Exception as e:
                    logger.error(
                        f"Error initializing check {check_class.check_id} on {target.name}: {e}"
                    )
                    # Handle initialization failures

            # Collect results
            for check_id, future in futures:
                try:
                    result = future.result()
                    results.append(result)
                    logger.debug(
                        f"Check {check_id} on {target.name}: "
                        f"{'PASSED' if result.status else 'FAILED'}"
                    )
                except Exception as e:
                    logger.error(
                        f"Error running check {check_id} on {target.name}: {e}"
                    )
                    # Handle execution failures

        return results

    def _create_summary(
        self, target: Target, results: List[AssessmentResult]
    ) -> AssessmentSummary:
        """Create a summary of the assessment results.

        Args:
            target: Target system that was assessed
            results: List of assessment results

        Returns:
            Assessment summary
        """
        from datetime import datetime

        # Calculate overall statistics
        passed_checks = sum(1 for r in results if r.status)
        total_checks = len(results)
        overall_score = (
            sum(r.score for r in results) / total_checks if total_checks > 0 else 0.0
        )

        # Create the summary
        return AssessmentSummary(
            target=target.name,
            target_type=target.type,
            total_checks=total_checks,
            passed_checks=passed_checks,
            failed_checks=total_checks - passed_checks,
            overall_score=overall_score,
            results=results,
            timestamp=datetime.now().isoformat(),
        )

    def generate_report(
        self, summary: AssessmentSummary, format: str = "pdf", output_path: Optional[Path] = None
    ) -> Path:
        """Generate a report for an assessment.

        Args:
            summary: Assessment summary to generate a report for
            format: Report format ('pdf', 'html', 'json', 'csv')
            output_path: Path to save the report to, or None for default

        Returns:
            Path to the generated report
        """
        if not self.reporter:
            raise AssessmentError("No reporter configured")

        return self.reporter.generate_report(summary, format, output_path)
