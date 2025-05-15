"""Reporter for generating assessment reports.

This module provides functionality for generating assessment reports
in various formats (PDF, HTML, JSON, CSV).
"""

from __future__ import annotations

import csv
import json
import logging
import os
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import jinja2
import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from agid_assessment_methodology.config.settings import settings
from agid_assessment_methodology.core.engine import AssessmentSummary
from agid_assessment_methodology.utils.exceptions import ReportingError

logger = logging.getLogger(__name__)


class ReportFormat(str, Enum):
    """Report formats."""

    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    CSV = "csv"


class Reporter:
    """Reporter for generating assessment reports."""

    def __init__(self, template_dir: Optional[Path] = None):
        """Initialize the reporter.

        Args:
            template_dir: Directory containing report templates
        """
        self.template_dir = template_dir or self._get_default_template_dir()
        self._setup_jinja_env()
        logger.debug(f"Initialized reporter with template directory: {self.template_dir}")

    def _get_default_template_dir(self) -> Path:
        """Get the default template directory.

        Returns:
            Path to the default template directory
        """
        module_dir = Path(__file__).parent.parent
        template_dir = module_dir / "templates" / "reports"
        if not template_dir.exists():
            template_dir.mkdir(parents=True, exist_ok=True)
            # Create default templates here if needed

        return template_dir

    def _setup_jinja_env(self) -> None:
        """Set up the Jinja2 environment."""
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.template_dir)),
            autoescape=jinja2.select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate_report(
        self,
        summary: AssessmentSummary,
        format: str = "pdf",
        output_path: Optional[Path] = None
    ) -> Path:
        """Generate a report for an assessment.

        Args:
            summary: Assessment summary to generate a report for
            format: Report format ('pdf', 'html', 'json', 'csv')
            output_path: Path to save the report to, or None for default

        Returns:
            Path to the generated report
        """
        try:
            report_format = ReportFormat(format.lower())
        except ValueError:
            raise ReportingError(f"Unsupported report format: {format}")

        # Generate the report
        if report_format == ReportFormat.PDF:
            return self._generate_pdf_report(summary, output_path)
        elif report_format == ReportFormat.HTML:
            return self._generate_html_report(summary, output_path)
        elif report_format == ReportFormat.JSON:
            return self._generate_json_report(summary, output_path)
        elif report_format == ReportFormat.CSV:
            return self._generate_csv_report(summary, output_path)
        else:
            raise ReportingError(f"Unsupported report format: {format}")

    def _get_output_path(self, summary: AssessmentSummary, extension: str, output_path: Optional[Path] = None) -> Path:
        """Get the output path for a report.

        Args:
            summary: Assessment summary to generate a report for
            extension: File extension for the report
            output_path: Path to save the report to, or None for default

        Returns:
            Path to save the report to
        """
        if output_path:
            return output_path

        # Use default report directory from settings
        report_dir = settings.report_dir
        if not report_dir:
            report_dir = Path.home() / ".agid_assessment" / "reports"

        # Create the directory if it doesn't exist
        report_dir.mkdir(parents=True, exist_ok=True)

        # Generate a filename based on the assessment summary
        timestamp = datetime.fromisoformat(summary.timestamp).strftime("%Y%m%d_%H%M%S")
        filename = f"assessment_{summary.target}_{timestamp}.{extension}"

        return report_dir / filename

    def _generate_pdf_report(self, summary: AssessmentSummary, output_path: Optional[Path] = None) -> Path:
        """Generate a PDF report for an assessment.

        Args:
            summary: Assessment summary to generate a report for
            output_path: Path to save the report to, or None for default

        Returns:
            Path to the generated report
        """
        # Get the output path
        report_path = self._get_output_path(summary, "pdf", output_path)

        # Create the PDF document
        doc = SimpleDocTemplate(str(report_path), pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        # Title
        title = Paragraph(f"Security Assessment Report: {summary.target}", styles["Title"])
        elements.append(title)
        elements.append(Spacer(1, 12))

        # Summary section
        summary_title = Paragraph("Assessment Summary", styles["Heading1"])
        elements.append(summary_title)
        elements.append(Spacer(1, 12))

        # Summary data
        data = [
            ["Target", summary.target],
            ["Target Type", summary.target_type],
            ["Total Checks", str(summary.total_checks)],
            ["Passed Checks", str(summary.passed_checks)],
            ["Failed Checks", str(summary.failed_checks)],
            ["Overall Score", f"{summary.overall_score:.2f}%"],
            ["Timestamp", datetime.fromisoformat(summary.timestamp).strftime("%Y-%m-%d %H:%M:%S")],
        ]

        summary_table = Table(data, colWidths=[150, 350])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.black),
            ("ALIGN", (0, 0), (0, -1), "LEFT"),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (0, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 24))

        # Results section
        results_title = Paragraph("Assessment Results", styles["Heading1"])
        elements.append(results_title)
        elements.append(Spacer(1, 12))

        # Add each result
        for result in summary.results:
            # Result title
            result_title = Paragraph(
                f"{result.check_id}: {'PASSED' if result.status else 'FAILED'} ({result.score:.2f}%)",
                styles["Heading2"]
            )
            elements.append(result_title)
            elements.append(Spacer(1, 6))

            # Result details
            for key, value in result.details.items():
                if isinstance(value, dict) or isinstance(value, list):
                    value_str = json.dumps(value, indent=2)
                    p = Paragraph(f"<b>{key}:</b><br/><pre>{value_str}</pre>", styles["Normal"])
                else:
                    p = Paragraph(f"<b>{key}:</b> {value}", styles["Normal"])
                elements.append(p)
                elements.append(Spacer(1, 6))

            # Remediation
            if result.remediation:
                remediation_title = Paragraph("Remediation", styles["Heading3"])
                elements.append(remediation_title)
                elements.append(Spacer(1, 6))
                remediation_text = Paragraph(result.remediation, styles["Normal"])
                elements.append(remediation_text)

            elements.append(Spacer(1, 12))

        # Build the PDF
        doc.build(elements)
        logger.info(f"Generated PDF report: {report_path}")

        return report_path

    def _generate_html_report(self, summary: AssessmentSummary, output_path: Optional[Path] = None) -> Path:
        """Generate an HTML report for an assessment.

        Args:
            summary: Assessment summary to generate a report for
            output_path: Path to save the report to, or None for default

        Returns:
            Path to the generated report
        """
        # Get the output path
        report_path = self._get_output_path(summary, "html", output_path)

        # Check if HTML template exists
        template_name = "assessment_report.html"
        if not (self.template_dir / template_name).exists():
            self._create_default_html_template()

        # Render the template
        template = self.jinja_env.get_template(template_name)
        html_content = template.render(
            title=f"Security Assessment Report: {summary.target}",
            summary=summary,
            datetime=datetime,
            json=json,
        )

        # Write the HTML file
        with open(report_path, "w") as f:
            f.write(html_content)

        logger.info(f"Generated HTML report: {report_path}")
        return report_path

    def _create_default_html_template(self) -> None:
        """Create a default HTML report template if none exists."""
        template_path = self.template_dir / "assessment_report.html"

        # Default template content
        template_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .summary-box {
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .summary-item {
            margin-bottom: 10px;
        }
        .summary-label {
            font-weight: bold;
            display: inline-block;
            width: 150px;
        }
        .check-result {
            margin-bottom: 30px;
            padding: 15px;
            border-radius: 5px;
        }
        .passed {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
        }
        .failed {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
        }
        .details-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            margin-bottom: 20px;
        }
        .details-table th, .details-table td {
            border: 1px solid #dee2e6;
            padding: 8px;
            text-align: left;
        }
        .details-table th {
            background-color: #e9ecef;
        }
        .remediation {
            background-color: #fff3cd;
            border: 1px solid #ffeeba;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
        }
        pre {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{ title }}</h1>

        <div class="summary-box">
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
                <span>{{ datetime.fromisoformat(summary.timestamp).strftime("%Y-%m-%d %H:%M:%S") }}</span>
            </div>
        </div>

        <h2>Assessment Results</h2>

        {% for result in summary.results %}
            <div class="check-result {{ 'passed' if result.status else 'failed' }}">
                <h3>{{ result.check_id }}: {{ "PASSED" if result.status else "FAILED" }} ({{ "%.2f"|format(result.score) }}%)</h3>

                <h4>Details</h4>
                {% for key, value in result.details.items() %}
                    <div class="detail-item">
                        <strong>{{ key }}:</strong>
                        {% if value is mapping or value is sequence and value is not string %}
                            <pre>{{ json.dumps(value, indent=2) }}</pre>
                        {% else %}
                            <span>{{ value }}</span>
                        {% endif %}
                    </div>
                {% endfor %}

                {% if result.remediation %}
                    <div class="remediation">
                        <h4>Remediation</h4>
                        <p>{{ result.remediation }}</p>
                    </div>
                {% endif %}
            </div>
        {% endfor %}
    </div>
</body>
</html>
"""

        # Write the template file
        with open(template_path, "w") as f:
            f.write(template_content)

        logger.debug(f"Created default HTML report template: {template_path}")

    def _generate_json_report(self, summary: AssessmentSummary, output_path: Optional[Path] = None) -> Path:
        """Generate a JSON report for an assessment.

        Args:
            summary: Assessment summary to generate a report for
            output_path: Path to save the report to, or None for default

        Returns:
            Path to the generated report
        """
        # Get the output path
        report_path = self._get_output_path(summary, "json", output_path)

        # Convert summary to dictionary
        summary_dict = summary.dict()

        # Write the JSON file
        with open(report_path, "w") as f:
            json.dump(summary_dict, f, indent=2)

        logger.info(f"Generated JSON report: {report_path}")
        return report_path

    def _generate_csv_report(self, summary: AssessmentSummary, output_path: Optional[Path] = None) -> Path:
        """Generate a CSV report for an assessment.

        Args:
            summary: Assessment summary to generate a report for
            output_path: Path to save the report to, or None for default

        Returns:
            Path to the generated report
        """
        # Get the output path
        report_path = self._get_output_path(summary, "csv", output_path)

        # Prepare the data
        rows = []

        # Add the summary row
        summary_row = {
            "Type": "Summary",
            "Target": summary.target,
            "Target Type": summary.target_type,
            "Total Checks": summary.total_checks,
            "Passed Checks": summary.passed_checks,
            "Failed Checks": summary.failed_checks,
            "Overall Score": f"{summary.overall_score:.2f}%",
            "Timestamp": summary.timestamp,
            "Check ID": "",
            "Status": "",
            "Score": "",
            "Details": "",
            "Remediation": "",
        }
        rows.append(summary_row)

        # Add a row for each result
        for result in summary.results:
            result_row = {
                "Type": "Result",
                "Target": summary.target,
                "Target Type": summary.target_type,
                "Total Checks": "",
                "Passed Checks": "",
                "Failed Checks": "",
                "Overall Score": "",
                "Timestamp": result.timestamp,
                "Check ID": result.check_id,
                "Status": "PASSED" if result.status else "FAILED",
                "Score": f"{result.score:.2f}%",
                "Details": json.dumps(result.details),
                "Remediation": result.remediation or "",
            }
            rows.append(result_row)

        # Write the CSV file
        with open(report_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

        logger.info(f"Generated CSV report: {report_path}")
        return report_path
