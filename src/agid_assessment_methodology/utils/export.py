"""Export utilities for assessment results.

This module provides utilities for exporting assessment results
to various formats (JSON, CSV, etc.).
"""

from __future__ import annotations

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pandas as pd

from agid_assessment_methodology.core.engine import AssessmentResult, AssessmentSummary
from agid_assessment_methodology.utils.exceptions import ReportingError

logger = logging.getLogger(__name__)


def export_to_json(
    data: Union[AssessmentSummary, List[AssessmentResult]],
    output_path: Path,
    pretty: bool = True,
) -> Path:
    """Export data to JSON format.

    Args:
        data: Data to export (assessment summary or list of results)
        output_path: Path to write the JSON file to
        pretty: Whether to format the JSON for readability

    Returns:
        Path to the exported file
    """
    try:
        logger.debug(f"Exporting data to JSON: {output_path}")

        # Convert the data to a dictionary
        if isinstance(data, AssessmentSummary):
            # Export the entire summary
            data_dict = data.dict()
        elif isinstance(data, list) and all(isinstance(r, AssessmentResult) for r in data):
            # Export a list of results
            data_dict = [r.dict() for r in data]
        else:
            # Export other data as is
            data_dict = data

        # Write the JSON file
        with open(output_path, "w") as f:
            if pretty:
                json.dump(data_dict, f, indent=2)
            else:
                json.dump(data_dict, f)

        logger.info(f"Exported data to JSON: {output_path}")
        return output_path

    except Exception as e:
        raise ReportingError(f"Error exporting data to JSON: {e}")


def export_to_csv(
    data: Union[AssessmentSummary, List[AssessmentResult], List[Dict[str, Any]]],
    output_path: Path,
    include_summary: bool = True,
) -> Path:
    """Export data to CSV format.

    Args:
        data: Data to export (assessment summary, list of results, or list of dictionaries)
        output_path: Path to write the CSV file to
        include_summary: Whether to include a summary row for assessment summaries

    Returns:
        Path to the exported file
    """
    try:
        logger.debug(f"Exporting data to CSV: {output_path}")

        # Prepare the data rows
        rows = []

        if isinstance(data, AssessmentSummary):
            # Export an assessment summary
            if include_summary:
                # Add a summary row
                summary_row = {
                    "Type": "Summary",
                    "Target": data.target,
                    "Target Type": data.target_type,
                    "Total Checks": data.total_checks,
                    "Passed Checks": data.passed_checks,
                    "Failed Checks": data.failed_checks,
                    "Overall Score": f"{data.overall_score:.2f}%",
                    "Timestamp": data.timestamp,
                    "Check ID": "",
                    "Status": "",
                    "Score": "",
                    "Details": "",
                    "Remediation": "",
                }
                rows.append(summary_row)

            # Add a row for each result
            for result in data.results:
                result_row = {
                    "Type": "Result",
                    "Target": data.target,
                    "Target Type": data.target_type,
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

        elif isinstance(data, list) and all(isinstance(r, AssessmentResult) for r in data):
            # Export a list of results
            for result in data:
                result_row = {
                    "Target": result.target,
                    "Timestamp": result.timestamp,
                    "Check ID": result.check_id,
                    "Status": "PASSED" if result.status else "FAILED",
                    "Score": f"{result.score:.2f}%",
                    "Details": json.dumps(result.details),
                    "Remediation": result.remediation or "",
                }
                rows.append(result_row)

        elif isinstance(data, list) and all(isinstance(r, dict) for r in data):
            # Export a list of dictionaries
            rows = data

        else:
            raise ReportingError("Unsupported data type for CSV export")

        # Write the CSV file
        if rows:
            with open(output_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
        else:
            # No data to export
            with open(output_path, "w", newline="") as f:
                f.write("")

        logger.info(f"Exported data to CSV: {output_path}")
        return output_path

    except Exception as e:
        raise ReportingError(f"Error exporting data to CSV: {e}")


def export_to_excel(
    data: Union[AssessmentSummary, List[AssessmentResult], List[Dict[str, Any]]],
    output_path: Path,
    include_summary: bool = True,
) -> Path:
    """Export data to Excel format.

    Args:
        data: Data to export (assessment summary, list of results, or list of dictionaries)
        output_path: Path to write the Excel file to
        include_summary: Whether to include a summary sheet for assessment summaries

    Returns:
        Path to the exported file
    """
    try:
        logger.debug(f"Exporting data to Excel: {output_path}")

        # Create a Pandas Excel writer
        with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
            if isinstance(data, AssessmentSummary):
                # Export an assessment summary
                if include_summary:
                    # Create a summary sheet
                    summary_data = {
                        "Property": [
                            "Target",
                            "Target Type",
                            "Total Checks",
                            "Passed Checks",
                            "Failed Checks",
                            "Overall Score",
                            "Timestamp",
                        ],
                        "Value": [
                            data.target,
                            data.target_type,
                            data.total_checks,
                            data.passed_checks,
                            data.failed_checks,
                            f"{data.overall_score:.2f}%",
                            data.timestamp,
                        ],
                    }
                    summary_df = pd.DataFrame(summary_data)
                    summary_df.to_excel(writer, sheet_name="Summary", index=False)

                # Create a results sheet
                results_data = []
                for result in data.results:
                    result_data = {
                        "Check ID": result.check_id,
                        "Status": "PASSED" if result.status else "FAILED",
                        "Score": f"{result.score:.2f}%",
                        "Timestamp": result.timestamp,
                    }

                    # Add details fields
                    for key, value in result.details.items():
                        if isinstance(value, (dict, list)):
                            result_data[f"Detail: {key}"] = json.dumps(value)
                        else:
                            result_data[f"Detail: {key}"] = value

                    # Add remediation
                    if result.remediation:
                        result_data["Remediation"] = result.remediation

                    results_data.append(result_data)

                if results_data:
                    results_df = pd.DataFrame(results_data)
                    results_df.to_excel(writer, sheet_name="Results", index=False)

            elif isinstance(data, list) and all(isinstance(r, AssessmentResult) for r in data):
                # Export a list of results
                results_data = []
                for result in data:
                    result_data = {
                        "Target": result.target,
                        "Check ID": result.check_id,
                        "Status": "PASSED" if result.status else "FAILED",
                        "Score": f"{result.score:.2f}%",
                        "Timestamp": result.timestamp,
                    }

                    # Add details fields
                    for key, value in result.details.items():
                        if isinstance(value, (dict, list)):
                            result_data[f"Detail: {key}"] = json.dumps(value)
                        else:
                            result_data[f"Detail: {key}"] = value

                    # Add remediation
                    if result.remediation:
                        result_data["Remediation"] = result.remediation

                    results_data.append(result_data)

                if results_data:
                    results_df = pd.DataFrame(results_data)
                    results_df.to_excel(writer, sheet_name="Results", index=False)

            elif isinstance(data, list) and all(isinstance(r, dict) for r in data):
                # Export a list of dictionaries
                df = pd.DataFrame(data)
                df.to_excel(writer, sheet_name="Data", index=False)

            else:
                raise ReportingError("Unsupported data type for Excel export")

        logger.info(f"Exported data to Excel: {output_path}")
        return output_path

    except Exception as e:
        raise ReportingError(f"Error exporting data to Excel: {e}")


def export_to_html(
    data: Union[AssessmentSummary, List[AssessmentResult]],
    output_path: Path,
    template_path: Optional[Path] = None,
) -> Path:
    """Export data to HTML format.

    Args:
        data: Data to export (assessment summary or list of results)
        output_path: Path to write the HTML file to
        template_path: Path to an HTML template file, or None to use the default template

    Returns:
        Path to the exported file
    """
    try:
        logger.debug(f"Exporting data to HTML: {output_path}")

        # Import Jinja2 for templating
        import jinja2

        # Get the template
        if template_path and template_path.exists():
            # Use the provided template
            with open(template_path, "r") as f:
                template_content = f.read()
        else:
            # Use the default template
            template_content = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Assessment Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
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
    {% if summary %}
        <h1>Security Assessment Report: {{ summary.target }}</h1>

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
                <span>{{ summary.timestamp }}</span>
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
                            <pre>{{ value|tojson(indent=2) }}</pre>
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
    {% elif results %}
        <h1>Security Assessment Results</h1>

        {% for result in results %}
            <div class="check-result {{ 'passed' if result.status else 'failed' }}">
                <h3>{{ result.check_id }} ({{ result.target }}): {{ "PASSED" if result.status else "FAILED" }} ({{ "%.2f"|format(result.score) }}%)</h3>

                <div class="summary-item">
                    <span class="summary-label">Timestamp:</span>
                    <span>{{ result.timestamp }}</span>
                </div>

                <h4>Details</h4>
                {% for key, value in result.details.items() %}
                    <div class="detail-item">
                        <strong>{{ key }}:</strong>
                        {% if value is mapping or value is sequence and value is not string %}
                            <pre>{{ value|tojson(indent=2) }}</pre>
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
    {% else %}
        <h1>Security Assessment Report</h1>
        <p>No assessment data available.</p>
    {% endif %}
</body>
</html>
"""

        # Create the Jinja2 environment
        env = jinja2.Environment()
        template = env.from_string(template_content)

        # Prepare the template context
        context = {}

        if isinstance(data, AssessmentSummary):
            # Export an assessment summary
            context["summary"] = data.dict()
            context["results"] = None

        elif isinstance(data, list) and all(isinstance(r, AssessmentResult) for r in data):
            # Export a list of results
            context["summary"] = None
            context["results"] = [r.dict() for r in data]

        else:
            raise ReportingError("Unsupported data type for HTML export")

        # Render the template
        html_content = template.render(**context)

        # Write the HTML file
        with open(output_path, "w") as f:
            f.write(html_content)

        logger.info(f"Exported data to HTML: {output_path}")
        return output_path

    except Exception as e:
        raise ReportingError(f"Error exporting data to HTML: {e}")
