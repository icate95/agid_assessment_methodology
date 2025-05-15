"""Commands module for AGID assessment methodology CLI.

This module contains the command definitions for the CLI interface of the security assessment framework.
Each command represents a specific functionality of the assessment methodology.
"""

import os
import sys
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Union

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn

# Import internal modules
from agid_assessment_methodology.core.assessment import Assessment
from agid_assessment_methodology.core.scanner import Scanner
from agid_assessment_methodology.utils.config import load_config, save_config
from agid_assessment_methodology.utils.reporting import generate_report, ExportFormat
from agid_assessment_methodology.utils.logger import setup_logger

# Initialize console for rich output
console = Console()
logger = logging.getLogger(__name__)

# Create commands app
commands_app = typer.Typer(help="AGID Assessment Methodology Commands")


@commands_app.command()
def scan(
    target: str = typer.Argument(..., help="Target system to scan (hostname, IP, or path)"),
    config_file: Path = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    output: Path = typer.Option(
        None, "--output", "-o", help="Output file path for scan results"
    ),
    format: str = typer.Option(
        "json", "--format", "-f", help="Output format (json, csv, html, pdf)"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress all output except errors"),
):
    """
    Perform a security assessment scan on the target system.

    This command runs a comprehensive security audit against the specified target,
    checking for compliance with ABSC minimum security measures.
    """
    # Setup logging based on verbosity
    log_level = logging.ERROR if quiet else (logging.DEBUG if verbose else logging.INFO)
    setup_logger(log_level)

    try:
        # Load configuration
        config = load_config(config_file) if config_file else {}

        # Create progress display
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            # Initialize scanner
            scan_task = progress.add_task("[green]Scanning target...", total=100)
            scanner = Scanner(target, config)

            # Run the scan
            scanner.setup()
            progress.update(scan_task, completed=30)

            results = scanner.execute()
            progress.update(scan_task, completed=90)

            # Process scan results
            assessment = Assessment(results)
            report = assessment.evaluate()
            progress.update(scan_task, completed=100)

        # Display summary results
        console.print("\n[bold green]Scan Complete![/bold green]")

        summary_table = Table(title="Security Assessment Summary")
        summary_table.add_column("Category", style="cyan")
        summary_table.add_column("Status", style="green")
        summary_table.add_column("Compliance", style="yellow")

        for category, data in report.get("summary", {}).items():
            status = "✅" if data.get("compliant", False) else "❌"
            compliance = f"{data.get('compliance_percentage', 0)}%"
            summary_table.add_row(category, status, compliance)

        console.print(summary_table)

        # Save report to output file if specified
        if output:
            export_format = ExportFormat(format.lower())
            save_path = generate_report(report, output, export_format)
            console.print(f"\nReport saved to: [bold]{save_path}[/bold]")

    except Exception as e:
        logger.error(f"Error during scan: {str(e)}", exc_info=verbose)
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise typer.Exit(code=1)


@commands_app.command()
def list_checks(
    category: str = typer.Option(None, "--category", "-c", help="Filter checks by category"),
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, json)"),
):
    """List all available security checks in the assessment methodology."""
    try:
        # Get all available checks from scanner
        scanner = Scanner("dummy")
        available_checks = scanner.get_available_checks()

        # Filter by category if specified
        if category:
            available_checks = {
                k: v for k, v in available_checks.items()
                if k.lower() == category.lower() or any(c.get("category", "").lower() == category.lower() for c in v)
            }

        if format.lower() == "json":
            console.print_json(json.dumps(available_checks))
        else:
            # Display as table
            for category, checks in available_checks.items():
                check_table = Table(title=f"Category: {category}")
                check_table.add_column("ID", style="cyan")
                check_table.add_column("Description", style="green")
                check_table.add_column("Severity", style="yellow")

                for check in checks:
                    check_table.add_row(
                        check.get("id", "N/A"),
                        check.get("description", "N/A"),
                        check.get("severity", "N/A")
                    )

                console.print(check_table)
                console.print("")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise typer.Exit(code=1)


@commands_app.command()
def configure(
    output: Path = typer.Option(
        Path.home() / ".agid_assessment" / "config.json",
        "--output",
        "-o",
        help="Path to save the configuration file"
    ),
    interactive: bool = typer.Option(
        True,
        "--interactive/--no-interactive",
        help="Run in interactive mode to set configuration options"
    ),
):
    """
    Create or update the configuration for the assessment tool.

    This command helps set up the configuration for the security assessment tool,
    including scan parameters, reporting preferences, and authentication details.
    """
    try:
        # Create default config template
        config = {
            "scan": {
                "timeout": 300,
                "parallel": True,
                "max_threads": 10
            },
            "checks": {
                "enabled_categories": ["authentication", "backup", "malware", "updates", "network", "logging"],
                "excluded_checks": []
            },
            "reporting": {
                "include_details": True,
                "include_recommendations": True,
                "default_format": "pdf"
            },
            "credentials": {
                "windows": {
                    "username": "",
                    "password": "",
                    "domain": ""
                },
                "linux": {
                    "username": "",
                    "use_key": False,
                    "key_path": ""
                }
            }
        }

        # If interactive mode, prompt for configuration options
        if interactive:
            console.print("[bold]AGID Assessment Tool Configuration[/bold]")
            console.print("Please configure the following settings:")

            # Scan settings
            config["scan"]["timeout"] = typer.prompt(
                "Scan timeout in seconds",
                default=config["scan"]["timeout"],
                type=int
            )

            config["scan"]["parallel"] = typer.confirm(
                "Enable parallel scanning?",
                default=config["scan"]["parallel"]
            )

            if config["scan"]["parallel"]:
                config["scan"]["max_threads"] = typer.prompt(
                    "Maximum number of parallel threads",
                    default=config["scan"]["max_threads"],
                    type=int
                )

            # Check categories
            categories = [
                "authentication", "backup", "malware", "updates",
                "network", "logging", "encryption", "inventory"
            ]

            selected_categories = []
            for category in categories:
                if typer.confirm(f"Enable {category} checks?", default=True):
                    selected_categories.append(category)

            config["checks"]["enabled_categories"] = selected_categories

            # Credentials
            configure_creds = typer.confirm("Configure authentication credentials?", default=False)
            if configure_creds:
                # Windows credentials
                console.print("\n[bold]Windows Authentication[/bold]")
                config["credentials"]["windows"]["username"] = typer.prompt(
                    "Windows username",
                    default="",
                    show_default=False
                )

                if config["credentials"]["windows"]["username"]:
                    config["credentials"]["windows"]["password"] = typer.prompt(
                        "Windows password",
                        default="",
                        hide_input=True,
                        show_default=False
                    )
                    config["credentials"]["windows"]["domain"] = typer.prompt(
                        "Windows domain (leave empty for local)",
                        default=""
                    )

                # Linux credentials
                console.print("\n[bold]Linux Authentication[/bold]")
                config["credentials"]["linux"]["username"] = typer.prompt(
                    "Linux username",
                    default="",
                    show_default=False
                )

                if config["credentials"]["linux"]["username"]:
                    config["credentials"]["linux"]["use_key"] = typer.confirm(
                        "Use SSH key authentication?",
                        default=True
                    )

                    if config["credentials"]["linux"]["use_key"]:
                        config["credentials"]["linux"]["key_path"] = typer.prompt(
                            "Path to SSH private key",
                            default=str(Path.home() / ".ssh" / "id_rsa")
                        )

        # Ensure output directory exists
        os.makedirs(os.path.dirname(output), exist_ok=True)

        # Save configuration
        save_config(config, output)
        console.print(f"[bold green]Configuration saved to:[/bold green] {output}")

    except Exception as e:
        console.print(f"[bold red]Error saving configuration:[/bold red] {str(e)}")
        raise typer.Exit(code=1)


@commands_app.command()
def verify_compliance(
    report_file: Path = typer.Argument(..., help="Path to assessment report file"),
    compliance_level: str = typer.Option(
        "standard",
        "--level",
        "-l",
        help="Compliance level to verify against (basic, standard, advanced)"
    ),
    output: Path = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file for compliance verification report"
    ),
):
    """
    Verify a scan report against ABSC compliance requirements.

    This command analyzes a previously generated assessment report and determines
    whether it meets the requirements for the specified compliance level.
    """
    try:
        # Load the report file
        if not report_file.exists():
            console.print(f"[bold red]Error:[/bold red] Report file not found: {report_file}")
            raise typer.Exit(code=1)

        with open(report_file, 'r') as f:
            try:
                report_data = json.load(f)
            except json.JSONDecodeError:
                console.print(f"[bold red]Error:[/bold red] Invalid JSON in report file")
                raise typer.Exit(code=1)

        # Verify compliance
        assessment = Assessment(report_data)
        compliance_result = assessment.verify_compliance(compliance_level)

        # Display compliance results
        console.print(f"\n[bold]Compliance Verification: {compliance_level.title()} Level[/bold]")

        result_table = Table()
        result_table.add_column("Category", style="cyan")
        result_table.add_column("Status", style="green")
        result_table.add_column("Required", style="yellow")
        result_table.add_column("Implemented", style="yellow")

        overall_status = "✅" if compliance_result.get("compliant", False) else "❌"

        for category, data in compliance_result.get("categories", {}).items():
            status = "✅" if data.get("compliant", False) else "❌"
            required = str(data.get("required_checks", 0))
            implemented = str(data.get("implemented_checks", 0))
            result_table.add_row(category, status, required, implemented)

        console.print(result_table)
        console.print(f"\n[bold]Overall Compliance:[/bold] {overall_status}")
        console.print(f"Compliance Score: {compliance_result.get('compliance_score', 0)}%")

        # Output compliance report if requested
        if output:
            compliance_report = {
                "timestamp": datetime.now().isoformat(),
                "report_file": str(report_file),
                "compliance_level": compliance_level,
                "result": compliance_result
            }

            # Ensure output directory exists
            os.makedirs(os.path.dirname(output), exist_ok=True)

            with open(output, 'w') as f:
                json.dump(compliance_report, f, indent=2)

            console.print(f"\nCompliance report saved to: [bold]{output}[/bold]")

    except Exception as e:
        console.print(f"[bold red]Error during compliance verification:[/bold red] {str(e)}")
        raise typer.Exit(code=1)


@commands_app.command()
def schedule(
    target: str = typer.Argument(..., help="Target system to scan (hostname, IP, or path)"),
    frequency: str = typer.Option(
        "daily",
        "--frequency",
        "-f",
        help="Scan frequency (daily, weekly, monthly)"
    ),
    time: str = typer.Option(
        "03:00",
        "--time",
        "-t",
        help="Time to run the scan (HH:MM format)"
    ),
    config_file: Path = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file"
    ),
    output_dir: Path = typer.Option(
        Path.home() / ".agid_assessment" / "reports",
        "--output-dir",
        "-o",
        help="Directory to store scan reports"
    ),
):
    """
    Schedule recurring security assessment scans.

    This command sets up automated scanning for the specified target on a
    recurring schedule. It creates appropriate system scheduler entries
    (cron jobs on Linux or scheduled tasks on Windows).
    """
    try:
        # Validate parameters
        if frequency not in ["daily", "weekly", "monthly"]:
            console.print("[bold red]Error:[/bold red] Invalid frequency. Choose from: daily, weekly, monthly")
            raise typer.Exit(code=1)

        # Validate time format
        try:
            hour, minute = map(int, time.split(":"))
            if not (0 <= hour < 24 and 0 <= minute < 60):
                raise ValueError("Invalid time range")
        except ValueError:
            console.print("[bold red]Error:[/bold red] Invalid time format. Use HH:MM (24-hour format)")
            raise typer.Exit(code=1)

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Build command to be scheduled
        config_param = f"--config {config_file}" if config_file else ""
        output_pattern = f"{output_dir}/scan_%Y%m%d_%H%M.json"

        # Command to run (will be used in scheduler)
        scan_command = f"agid-assessment scan {target} {config_param} --output '{output_pattern}' --format json"

        # Create appropriate scheduler entry based on the platform
        if sys.platform == "win32":
            # Windows Task Scheduler
            task_name = f"AGID_Assessment_{target.replace('.', '_')}"

            # Map frequency to appropriate Windows schedule type
            schedule_type = {
                "daily": "DAILY",
                "weekly": "WEEKLY",
                "monthly": "MONTHLY"
            }[frequency]

            schedule_cmd = (
                f"schtasks /create /tn {task_name} /tr \"{scan_command}\" "
                f"/sc {schedule_type} /st {time.replace(':', '')} /f"
            )

            # Execute the schedule command
            import subprocess
            result = subprocess.run(schedule_cmd, shell=True, capture_output=True, text=True)

            if result.returncode != 0:
                console.print(f"[bold red]Error creating scheduled task:[/bold red] {result.stderr}")
                raise typer.Exit(code=1)

            console.print(f"[bold green]Scheduled task created:[/bold green] {task_name}")
            console.print(f"Frequency: {frequency} at {time}")

        else:
            # Linux/Unix crontab
            # Convert frequency to cron format
            cron_schedule = {
                "daily": f"{minute} {hour} * * *",
                "weekly": f"{minute} {hour} * * 0",
                "monthly": f"{minute} {hour} 1 * *"
            }[frequency]

            # Create temporary file with current crontab entries plus new entry
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
                # Get current crontab
                subprocess.run(["crontab", "-l"], stdout=temp_file, stderr=subprocess.DEVNULL)

                # Add our new entry
                temp_file.write(f"\n# AGID Assessment scan for {target}\n")
                temp_file.write(f"{cron_schedule} {scan_command}\n")
                temp_file_path = temp_file.name

            # Install the new crontab
            result = subprocess.run(["crontab", temp_file_path], capture_output=True, text=True)
            os.unlink(temp_file_path)  # Remove temp file

            if result.returncode != 0:
                console.print(f"[bold red]Error creating cron job:[/bold red] {result.stderr}")
                raise typer.Exit(code=1)

            console.print(f"[bold green]Scheduled scan created for target:[/bold green] {target}")
            console.print(f"Cron schedule: {cron_schedule}")

        console.print(f"Reports will be saved to: {output_dir}")

    except Exception as e:
        console.print(f"[bold red]Error scheduling scan:[/bold red] {str(e)}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    commands_app()
