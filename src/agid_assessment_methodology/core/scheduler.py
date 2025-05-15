"""Scheduler for assessment tasks.

This module provides a scheduler for running assessments on a schedule.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import schedule

from agid_assessment_methodology.config.settings import settings
from agid_assessment_methodology.core.engine import AssessmentEngine, Target
from agid_assessment_methodology.utils.exceptions import SchedulerError

logger = logging.getLogger(__name__)


class ScheduleInterval(str, Enum):
    """Schedule intervals."""

    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"


class ScheduledAssessment:
    """Scheduled assessment configuration."""

    def __init__(
        self,
        id: str,
        target: Target,
        interval: ScheduleInterval,
        check_ids: Optional[List[str]] = None,
        at_time: Optional[str] = None,
        day_of_week: Optional[int] = None,  # 0-6, Monday is 0
        day_of_month: Optional[int] = None,  # 1-31
        notify: bool = True,
        notification_recipients: Optional[List[str]] = None,
        generate_report: bool = True,
        report_format: str = "pdf",
        enabled: bool = True,
        tags: Optional[List[str]] = None,
        last_run: Optional[datetime] = None,
        next_run: Optional[datetime] = None,
    ):
        """Initialize scheduled assessment.

        Args:
            id: Unique identifier for the scheduled assessment
            target: Target to assess
            interval: Schedule interval
            check_ids: List of check IDs to run, or None for all checks
            at_time: Time of day to run the assessment (HH:MM format)
            day_of_week: Day of the week to run the assessment (0-6, Monday is 0)
            day_of_month: Day of the month to run the assessment (1-31)
            notify: Whether to send notifications after assessment
            notification_recipients: Recipients for notifications, or None for default
            generate_report: Whether to generate a report after assessment
            report_format: Format of the generated report
            enabled: Whether the scheduled assessment is enabled
            tags: Tags for the scheduled assessment
            last_run: Time of the last assessment run
            next_run: Time of the next scheduled assessment run
        """
        self.id = id
        self.target = target
        self.interval = interval
        self.check_ids = check_ids
        self.at_time = at_time
        self.day_of_week = day_of_week
        self.day_of_month = day_of_month
        self.notify = notify
        self.notification_recipients = notification_recipients
        self.generate_report = generate_report
        self.report_format = report_format
        self.enabled = enabled
        self.tags = tags or []
        self.last_run = last_run
        self.next_run = next_run

        self._job = None
        self._validate()

    def _validate(self) -> None:
        """Validate the scheduled assessment configuration."""
        # Validate interval-specific parameters
        if self.interval == ScheduleInterval.WEEKLY and self.day_of_week is None:
            raise SchedulerError("Day of week must be specified for weekly assessments")

        if self.interval == ScheduleInterval.MONTHLY and self.day_of_month is None:
            raise SchedulerError("Day of month must be specified for monthly assessments")

        # Validate at_time format
        if self.at_time:
            try:
                datetime.strptime(self.at_time, "%H:%M")
            except ValueError:
                raise SchedulerError("at_time must be in HH:MM format")

    def to_dict(self) -> Dict[str, Any]:
        """Convert the scheduled assessment to a dictionary.

        Returns:
            Dictionary representation of the scheduled assessment
        """
        return {
            "id": self.id,
            "target": {
                "name": self.target.name,
                "host": self.target.host,
                "type": self.target.type,
                "port": self.target.port,
                "username": self.target.username,
                "password": "********" if self.target.password else None,
                "key_file": str(self.target.key_file) if self.target.key_file else None,
                "domain": self.target.domain,
            },
            "interval": self.interval,
            "check_ids": self.check_ids,
            "at_time": self.at_time,
            "day_of_week": self.day_of_week,
            "day_of_month": self.day_of_month,
            "notify": self.notify,
            "notification_recipients": self.notification_recipients,
            "generate_report": self.generate_report,
            "report_format": self.report_format,
            "enabled": self.enabled,
            "tags": self.tags,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
        }


class AssessmentScheduler:
    """Scheduler for running assessments on a schedule."""

    def __init__(
        self,
        assessment_engine: Optional[AssessmentEngine] = None,
        storage_path: Optional[Path] = None,
    ):
        """Initialize the assessment scheduler.

        Args:
            assessment_engine: Engine for running assessments
            storage_path: Path to store scheduled assessments
        """
        self.assessment_engine = assessment_engine
        self.storage_path = storage_path or self._get_default_storage_path()
        self.scheduled_assessments: Dict[str, ScheduledAssessment] = {}
        self._running = False
        self._thread = None

        # Load scheduled assessments from storage
        self._load_scheduled_assessments()

        logger.info(f"Initialized assessment scheduler with {len(self.scheduled_assessments)} scheduled assessments")

    def _get_default_storage_path(self) -> Path:
        """Get the default storage path for scheduled assessments.

        Returns:
            Path to store scheduled assessments
        """
        path = Path.home() / ".agid_assessment" / "scheduled_assessments.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def _load_scheduled_assessments(self) -> None:
        """Load scheduled assessments from storage."""
        if not self.storage_path.exists():
            logger.debug("No scheduled assessments storage file found")
            return

        try:
            import json

            with open(self.storage_path, "r") as f:
                data = json.load(f)

            for item in data:
                target_data = item.pop("target")
                target = Target(**target_data)

                # Convert ISO format timestamps to datetime objects
                if item.get("last_run"):
                    item["last_run"] = datetime.fromisoformat(item["last_run"])
                if item.get("next_run"):
                    item["next_run"] = datetime.fromisoformat(item["next_run"])

                scheduled_assessment = ScheduledAssessment(
                    target=target,
                    **item
                )
                self.scheduled_assessments[scheduled_assessment.id] = scheduled_assessment

            logger.debug(f"Loaded {len(self.scheduled_assessments)} scheduled assessments from {self.storage_path}")

        except Exception as e:
            logger.error(f"Error loading scheduled assessments: {e}")

    def _save_scheduled_assessments(self) -> None:
        """Save scheduled assessments to storage."""
        try:
            import json

            data = [assessment.to_dict() for assessment in self.scheduled_assessments.values()]

            with open(self.storage_path, "w") as f:
                json.dump(data, f, indent=2)

            logger.debug(f"Saved {len(self.scheduled_assessments)} scheduled assessments to {self.storage_path}")

        except Exception as e:
            logger.error(f"Error saving scheduled assessments: {e}")

    def add_scheduled_assessment(self, assessment: ScheduledAssessment) -> None:
        """Add a scheduled assessment.

        Args:
            assessment: Scheduled assessment to add
        """
        if assessment.id in self.scheduled_assessments:
            raise SchedulerError(f"Scheduled assessment with ID {assessment.id} already exists")

        self.scheduled_assessments[assessment.id] = assessment

        # Schedule the assessment if the scheduler is running
        if self._running:
            self._schedule_assessment(assessment)

        self._save_scheduled_assessments()
        logger.info(f"Added scheduled assessment: {assessment.id}")

    def update_scheduled_assessment(self, assessment: ScheduledAssessment) -> None:
        """Update a scheduled assessment.

        Args:
            assessment: Scheduled assessment to update
        """
        if assessment.id not in self.scheduled_assessments:
            raise SchedulerError(f"Scheduled assessment with ID {assessment.id} does not exist")

        # Remove the old job if the scheduler is running
        if self._running:
            old_assessment = self.scheduled_assessments[assessment.id]
            if old_assessment._job:
                schedule.cancel_job(old_assessment._job)

            # Schedule the new assessment
            self._schedule_assessment(assessment)

        self.scheduled_assessments[assessment.id] = assessment
        self._save_scheduled_assessments()
        logger.info(f"Updated scheduled assessment: {assessment.id}")

    def remove_scheduled_assessment(self, assessment_id: str) -> None:
        """Remove a scheduled assessment.

        Args:
            assessment_id: ID of the scheduled assessment to remove
        """
        if assessment_id not in self.scheduled_assessments:
            raise SchedulerError(f"Scheduled assessment with ID {assessment_id} does not exist")

        # Remove the job if the scheduler is running
        assessment = self.scheduled_assessments[assessment_id]
        if self._running and assessment._job:
            schedule.cancel_job(assessment._job)

        del self.scheduled_assessments[assessment_id]
        self._save_scheduled_assessments()
        logger.info(f"Removed scheduled assessment: {assessment_id}")

    def get_scheduled_assessment(self, assessment_id: str) -> Optional[ScheduledAssessment]:
        """Get a scheduled assessment by ID.

        Args:
            assessment_id: ID of the scheduled assessment to get

        Returns:
            Scheduled assessment or None if not found
        """
        return self.scheduled_assessments.get(assessment_id)

    def get_scheduled_assessments(
        self,
        target_name: Optional[str] = None,
        interval: Optional[ScheduleInterval] = None,
        tags: Optional[List[str]] = None,
        enabled: Optional[bool] = None,
    ) -> List[ScheduledAssessment]:
        """Get scheduled assessments, optionally filtered.

        Args:
            target_name: Filter by target name
            interval: Filter by schedule interval
            tags: Filter by tags (assessment must have all specified tags)
            enabled: Filter by enabled status

        Returns:
            List of scheduled assessments matching the filters
        """
        result = list(self.scheduled_assessments.values())

        # Apply filters
        if target_name:
            result = [a for a in result if a.target.name == target_name]

        if interval:
            result = [a for a in result if a.interval == interval]

        if tags:
            result = [a for a in result if all(tag in a.tags for tag in tags)]

        if enabled is not None:
            result = [a for a in result if a.enabled == enabled]

        return result

    def enable_scheduled_assessment(self, assessment_id: str) -> None:
        """Enable a scheduled assessment.

        Args:
            assessment_id: ID of the scheduled assessment to enable
        """
        assessment = self.get_scheduled_assessment(assessment_id)
        if not assessment:
            raise SchedulerError(f"Scheduled assessment with ID {assessment_id} does not exist")

        if assessment.enabled:
            logger.debug(f"Scheduled assessment {assessment_id} is already enabled")
            return

        assessment.enabled = True

        # Schedule the assessment if the scheduler is running
        if self._running:
            self._schedule_assessment(assessment)

        self._save_scheduled_assessments()
        logger.info(f"Enabled scheduled assessment: {assessment_id}")

    def disable_scheduled_assessment(self, assessment_id: str) -> None:
        """Disable a scheduled assessment.

        Args:
            assessment_id: ID of the scheduled assessment to disable
        """
        assessment = self.get_scheduled_assessment(assessment_id)
        if not assessment:
            raise SchedulerError(f"Scheduled assessment with ID {assessment_id} does not exist")

        if not assessment.enabled:
            logger.debug(f"Scheduled assessment {assessment_id} is already disabled")
            return

        assessment.enabled = False

        # Remove the job if the scheduler is running
        if self._running and assessment._job:
            schedule.cancel_job(assessment._job)
            assessment._job = None

        self._save_scheduled_assessments()
        logger.info(f"Disabled scheduled assessment: {assessment_id}")

    def run_scheduled_assessment(self, assessment_id: str) -> None:
        """Run a scheduled assessment immediately.

        Args:
            assessment_id: ID of the scheduled assessment to run
        """
        assessment = self.get_scheduled_assessment(assessment_id)
        if not assessment:
            raise SchedulerError(f"Scheduled assessment with ID {assessment_id} does not exist")

        self._run_assessment(assessment)

    def _run_assessment(self, assessment: ScheduledAssessment) -> None:
        """Run an assessment.

        Args:
            assessment: Scheduled assessment to run
        """
        if not self.assessment_engine:
            logger.error("Cannot run assessment: no assessment engine provided")
            return

        try:
            logger.info(f"Running scheduled assessment: {assessment.id}")

            # Update last run time
            assessment.last_run = datetime.now()
            self._save_scheduled_assessments()

            # Run the assessment
            summary = self.assessment_engine.run_assessment(
                assessment.target,
                assessment.check_ids,
                parallel=settings.parallel_checks
            )

            # Generate report if configured
            if assessment.generate_report:
                report_path = self.assessment_engine.generate_report(
                    summary,
                    format=assessment.report_format
                )
                logger.info(f"Generated report for scheduled assessment {assessment.id}: {report_path}")

            # Send notifications if configured
            if assessment.notify and hasattr(self.assessment_engine, "reporter") and self.assessment_engine.reporter:
                from agid_assessment_methodology.core.notifier import Notifier

                notifier = Notifier()
                notifier.notify(
                    summary,
                    notification_type="email",
                    recipients=assessment.notification_recipients
                )

            logger.info(f"Completed scheduled assessment: {assessment.id}")

        except Exception as e:
            logger.error(f"Error running scheduled assessment {assessment.id}: {e}")

    def _schedule_assessment(self, assessment: ScheduledAssessment) -> None:
        """Schedule an assessment job.

        Args:
            assessment: Scheduled assessment to schedule
        """
        if not assessment.enabled:
            logger.debug(f"Not scheduling disabled assessment: {assessment.id}")
            return

        # Define the job function
        def job():
            self._run_assessment(assessment)

        # Schedule based on interval
        if assessment.interval == ScheduleInterval.HOURLY:
            if assessment.at_time:
                # Schedule at specific minute of each hour
                minute = int(assessment.at_time.split(":")[1])
                job_obj = schedule.every().hour.at(f":{minute:02d}").do(job)
            else:
                # Schedule every hour
                job_obj = schedule.every().hour.do(job)

        elif assessment.interval == ScheduleInterval.DAILY:
            # Schedule daily at specific time
            job_obj = schedule.every().day.at(assessment.at_time or "00:00").do(job)

        elif assessment.interval == ScheduleInterval.WEEKLY:
            # Get the day of week (schedule uses 0-6, where Monday is 0)
            day_of_week = assessment.day_of_week or 0

            # Map day number to schedule day
            days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
            day = days[day_of_week]

            # Schedule weekly on the specified day and time
            job_obj = schedule.every().__getattribute__(day).at(assessment.at_time or "00:00").do(job)

        elif assessment.interval == ScheduleInterval.MONTHLY:
            # Monthly scheduling is not directly supported by schedule
            # We'll implement a custom check in the scheduler loop

            # For now, store the intended schedule in the job object
            job_obj = schedule.every().day.do(lambda: None)  # Placeholder job that does nothing
            job_obj.cancel()  # Cancel it so it doesn't run

            # We'll handle monthly schedules in the run loop
            job_obj = None

        else:  # CUSTOM
            # Custom scheduling is not directly supported
            # Users should implement their own scheduling logic
            logger.warning(f"Custom scheduling not supported for assessment {assessment.id}")
            job_obj = None

        assessment._job = job_obj

        # Calculate the next run time
        if assessment.interval != ScheduleInterval.MONTHLY and job_obj:
            assessment.next_run = job_obj.next_run
            logger.debug(f"Scheduled assessment {assessment.id} to run at {assessment.next_run}")
        elif assessment.interval == ScheduleInterval.MONTHLY:
            # Calculate next monthly run
            now = datetime.now()
            day = assessment.day_of_month or 1
            time_parts = (assessment.at_time or "00:00").split(":")
            hour, minute = int(time_parts[0]), int(time_parts[1])

            # Start with this month
            next_run = datetime(now.year, now.month, min(day, 28), hour, minute)

            # If next_run is in the past, move to next month
            if next_run < now:
                if now.month == 12:
                    next_run = datetime(now.year + 1, 1, min(day, 31), hour, minute)
                else:
                    next_run = datetime(now.year, now.month + 1, min(day, 28), hour, minute)

            assessment.next_run = next_run
            logger.debug(f"Scheduled monthly assessment {assessment.id} to run at {assessment.next_run}")

    def start(self) -> None:
        """Start the scheduler."""
        if self._running:
            logger.warning("Scheduler is already running")
            return

        if not self.assessment_engine:
            logger.error("Cannot start scheduler: no assessment engine provided")
            return

        self._running = True

        # Schedule all assessments
        for assessment in self.scheduled_assessments.values():
            self._schedule_assessment(assessment)

        # Start the scheduler thread
        self._thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self._thread.start()

        logger.info("Started assessment scheduler")

    def stop(self) -> None:
        """Stop the scheduler."""
        if not self._running:
            logger.warning("Scheduler is not running")
            return

        self._running = False

        # Clear all jobs
        schedule.clear()

        # Wait for the thread to stop
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

        logger.info("Stopped assessment scheduler")

    def _run_scheduler(self) -> None:
        """Run the scheduler loop."""
        logger.debug("Scheduler thread started")

        while self._running:
            try:
                # Run pending jobs
                schedule.run_pending()

                # Check for monthly assessments that need to run
                now = datetime.now()
                for assessment in self.scheduled_assessments.values():
                    if (assessment.enabled
                        and assessment.interval == ScheduleInterval.MONTHLY
                        and assessment.next_run
                        and now >= assessment.next_run):

                        # Run the assessment
                        self._run_assessment(assessment)

                        # Reschedule for next month
                        day = assessment.day_of_month or 1
                        time_parts = (assessment.at_time or "00:00").split(":")
                        hour, minute = int(time_parts[0]), int(time_parts[1])

                        if now.month == 12:
                            next_run = datetime(now.year + 1, 1, min(day, 31), hour, minute)
                        else:
                            next_run = datetime(now.year, now.month + 1, min(day, 28), hour, minute)

                        assessment.next_run = next_run
                        logger.debug(f"Rescheduled monthly assessment {assessment.id} to run at {assessment.next_run}")

                # Sleep for a short time
                time.sleep(1)

            except Exception as e:
                logger.error(f"Error in scheduler thread: {e}")
                time.sleep(5)  # Sleep longer after an error

        logger.debug("Scheduler thread stopped")
