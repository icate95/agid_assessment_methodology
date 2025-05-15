"""Notifier for sending assessment notifications.

This module provides functionality for sending notifications
about assessment results via email and SMS.
"""

from __future__ import annotations

import logging
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union

import jinja2
import requests

from agid_assessment_methodology.config.settings import settings
from agid_assessment_methodology.core.engine import AssessmentSummary
from agid_assessment_methodology.utils.exceptions import NotifierError

logger = logging.getLogger(__name__)


class NotificationType(str, Enum):
    """Notification types."""

    EMAIL = "email"
    SMS = "sms"


class Notifier:
    """Notifier for sending assessment notifications."""

    def __init__(self, template_dir: Optional[Path] = None):
        """Initialize the notifier.

        Args:
            template_dir: Directory containing notification templates
        """
        self.template_dir = template_dir or self._get_default_template_dir()
        self._setup_jinja_env()
        logger.debug(f"Initialized notifier with template directory: {self.template_dir}")

    def _get_default_template_dir(self) -> Path:
        """Get the default template directory.

        Returns:
            Path to the default template directory
        """
        module_dir = Path(__file__).parent.parent
        template_dir = module_dir / "templates" / "notifications"
        if not template_dir.exists():
            template_dir.mkdir(parents=True, exist_ok=True)
            # Create default templates
            self._create_default_templates(template_dir)

        return template_dir

    def _create_default_templates(self, template_dir: Path) -> None:
        """Create default notification templates.

        Args:
            template_dir: Directory to create templates in
        """
        # Email template
        email_template_path = template_dir / "email_notification.html"
        if not email_template_path.exists():
            email_template = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Notification</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
        }
        .header {
            background-color: {% if summary.overall_score >= passing_threshold %}#4CAF50{% elif summary.overall_score >= warning_threshold %}#FFC107{% else %}#F44336{% endif %};
            color: white;
            padding: 20px;
            text-align: center;
        }
        .content {
            padding: 20px;
        }
        .summary {
            background-color: #f9f9f9;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        .summary-item {
            margin-bottom: 10px;
        }
        .summary-label {
            font-weight: bold;
            display: inline-block;
            width: 150px;
        }
        .failed-checks {
            background-color: #fff8f8;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
            border-left: 5px solid #F44336;
        }
        .check-item {
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 1px solid #eee;
        }
        .check-id {
            font-weight: bold;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            font-size: 0.9em;
            color: #777;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Notification</h1>
        <p>Assessment completed for: {{ summary.target }}</p>
    </div>

    <div class="content">
        <p>A security assessment has been completed with the following results:</p>

        <div class="summary">
            <h2>Assessment Summary</h2>

            <div class="summary-item">
                <span class="summary-label">Target:</span>
                <span>{{ summary.target }}</span>
            </div>

            <div class="summary-item">
                <span class="summary-label">Target Type:</span>
                <span>{{ summary.target_type }}</span>
            </div>

            <div class="summary-item">
                <span class="summary-label">Total Checks:</span>
                <span>{{ summary.total_checks }}</span>
            </div>

            <div class="summary-item">
                <span class="summary-label">Passed Checks:</span>
                <span>{{ summary.passed_checks }}</span>
            </div>

            <div class="summary-item">
                <span class="summary-label">Failed Checks:</span>
                <span>{{ summary.failed_checks }}</span>
            </div>

            <div class="summary-item">
                <span class="summary-label">Overall Score:</span>
                <span>{{ "%.2f"|format(summary.overall_score) }}%</span>
            </div>

            <div class="summary-item">
                <span class="summary-label">Timestamp:</span>
                <span>{{ timestamp }}</span>
            </div>
        </div>

        {% if summary.failed_checks > 0 %}
            <div class="failed-checks">
                <h2>Failed Checks</h2>

                {% for result in failed_results %}
                    <div class="check-item">
                        <div class="check-id">{{ result.check_id }}</div>
                        <div class="check-score">Score: {{ "%.2f"|format(result.score) }}%</div>
                        {% if result.remediation %}
                            <div class="check-remediation">
                                <strong>Remediation:</strong> {{ result.remediation }}
                            </div>
                        {% endif %}
                    </div>
                {% endfor %}
            </div>
        {% endif %}

        <p>For more details, please check the assessment report.</p>
    </div>

    <div class="footer">
        <p>This is an automated message from the AGID Assessment Methodology system.</p>
    </div>
</body>
</html>
"""
            with open(email_template_path, "w") as f:
                f.write(email_template)
            logger.debug(f"Created default email notification template: {email_template_path}")

        # SMS template
        sms_template_path = template_dir / "sms_notification.txt"
        if not sms_template_path.exists():
            sms_template = """AGID Security Assessment: {{ summary.target }} - Score: {{ "%.2f"|format(summary.overall_score) }}% ({{ summary.passed_checks }}/{{ summary.total_checks }} checks passed){% if summary.failed_checks > 0 %}. Action required!{% endif %}"""
            with open(sms_template_path, "w") as f:
                f.write(sms_template)
            logger.debug(f"Created default SMS notification template: {sms_template_path}")

    def _setup_jinja_env(self) -> None:
        """Set up the Jinja2 environment."""
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.template_dir)),
            autoescape=jinja2.select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def notify(
        self,
        summary: AssessmentSummary,
        notification_type: Union[str, NotificationType] = NotificationType.EMAIL,
        recipients: Optional[List[str]] = None,
    ) -> bool:
        """Send a notification about an assessment.

        Args:
            summary: Assessment summary to send a notification for
            notification_type: Type of notification to send
            recipients: List of recipients, or None to use default

        Returns:
            True if the notification was sent successfully, False otherwise
        """
        if isinstance(notification_type, str):
            try:
                notification_type = NotificationType(notification_type.lower())
            except ValueError:
                raise NotifierError(f"Unsupported notification type: {notification_type}")

        # Send the notification
        if notification_type == NotificationType.EMAIL:
            return self.send_email_notification(summary, recipients)
        elif notification_type == NotificationType.SMS:
            return self.send_sms_notification(summary, recipients)
        else:
            raise NotifierError(f"Unsupported notification type: {notification_type}")

    def send_email_notification(
        self,
        summary: AssessmentSummary,
        recipients: Optional[List[str]] = None,
    ) -> bool:
        """Send an email notification about an assessment.

        Args:
            summary: Assessment summary to send a notification for
            recipients: List of email recipients, or None to use default

        Returns:
            True if the email was sent successfully, False otherwise
        """
        if not settings.enable_email_notifications:
            logger.info("Email notifications are disabled")
            return False

        try:
            # Get recipients
            email_recipients = recipients or settings.email_to
            if not email_recipients:
                logger.warning("No email recipients configured")
                return False

            # Get the template
            template_name = "email_notification.html"
            template = self.jinja_env.get_template(template_name)

            # Get failed results
            failed_results = [r for r in summary.results if not r.status]

            # Render the template
            timestamp = datetime.fromisoformat(summary.timestamp).strftime("%Y-%m-%d %H:%M:%S")
            html_content = template.render(
                summary=summary,
                timestamp=timestamp,
                failed_results=failed_results,
                passing_threshold=settings.passing_score_threshold,
                warning_threshold=settings.warning_score_threshold,
            )

            # Create the email
            msg = MIMEMultipart()
            msg["Subject"] = f"Security Assessment: {summary.target} - Score: {summary.overall_score:.2f}%"
            msg["From"] = settings.email_from
            msg["To"] = ", ".join(email_recipients)

            # Attach the HTML content
            msg.attach(MIMEText(html_content, "html"))

            # Send the email
            with smtplib.SMTP(settings.email_smtp_server, settings.email_smtp_port) as server:
                if settings.email_username and settings.email_password:
                    server.starttls()
                    server.login(settings.email_username, settings.email_password)

                server.send_message(msg)

            logger.info(f"Sent email notification to {len(email_recipients)} recipients")
            return True

        except Exception as e:
            logger.error(f"Error sending email notification: {e}")
            return False

    def send_sms_notification(
        self,
        summary: AssessmentSummary,
        recipients: Optional[List[str]] = None,
    ) -> bool:
        """Send an SMS notification about an assessment.

        Args:
            summary: Assessment summary to send a notification for
            recipients: List of SMS recipients, or None to use default

        Returns:
            True if the SMS was sent successfully, False otherwise
        """
        if not settings.enable_sms_notifications:
            logger.info("SMS notifications are disabled")
            return False

        try:
            # Get recipients
            sms_recipients = recipients or settings.sms_to
            if not sms_recipients:
                logger.warning("No SMS recipients configured")
                return False

            # Check API credentials
            if not settings.sms_api_key or not settings.sms_api_secret:
                logger.warning("SMS API credentials not configured")
                return False

            # Get the template
            template_name = "sms_notification.txt"
            template = self.jinja_env.get_template(template_name)

            # Render the template
            sms_content = template.render(summary=summary)

            # Respect SMS length limitations (160 characters for standard SMS)
            if len(sms_content) > 160:
                sms_content = sms_content[:157] + "..."

            # Send the SMS to each recipient
            # This is a placeholder implementation. In a real system, you would
            # use a specific SMS gateway API (Twilio, Nexmo, etc.)
            success_count = 0
            for recipient in sms_recipients:
                try:
                    # Placeholder for SMS API call
                    # In a real implementation, you would use code specific to your SMS provider
                    # For example, with Twilio:
                    # from twilio.rest import Client
                    # client = Client(settings.sms_api_key, settings.sms_api_secret)
                    # message = client.messages.create(
                    #     body=sms_content,
                    #     from_=settings.sms_from,
                    #     to=recipient
                    # )

                    # Mock successful SMS sending for now
                    logger.debug(f"Would send SMS to {recipient}: {sms_content}")
                    success_count += 1

                except Exception as e:
                    logger.error(f"Error sending SMS to {recipient}: {e}")

            logger.info(f"Sent SMS notifications to {success_count}/{len(sms_recipients)} recipients")
            return success_count > 0

        except Exception as e:
            logger.error(f"Error sending SMS notifications: {e}")
            return False
