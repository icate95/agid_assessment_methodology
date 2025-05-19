import logging
import sys
from pathlib import Path
from typing import List, Optional  # <-- Aggiungere Optional qui
import traceback

import typer
from rich.console import Console
from rich.table import Table

# Inizializza console e logger
console = Console()
logger = logging.getLogger(__name__)

# Crea l'applicazione Typer
app = typer.Typer(
    name="agid-assessment",
    help="AGID Assessment Methodology - Security Assessment Tool",
    no_args_is_help=True
)

# Resto del codice rimane uguale...

@app.command()
def version():
    """Show version information."""
    try:
        from .. import __version__
        console.print(f"AGID Assessment Methodology v{__version__}")
    except ImportError:
        console.print("AGID Assessment Methodology v0.1.0")


@app.command()
def info():
    """Show system and tool information."""
    import platform

    table = Table(title="System Information")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Platform", platform.platform())
    table.add_row("Python Version", platform.python_version())
    table.add_row("Architecture", platform.architecture()[0])

    try:
        from .. import __version__
        table.add_row("Tool Version", __version__)
    except ImportError:
        table.add_row("Tool Version", "0.1.0")

    console.print(table)


@app.command()
def scan(
    target: str = typer.Argument(
        help="Target to scan (hostname, IP address, or 'localhost')"
    ),
    config_file: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to configuration file"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
    format: str = typer.Option(
        "json", "--format", "-f", help="Output format (json, csv, html, xml, pdf)"
    ),
    categories: Optional[List[str]] = typer.Option(
        None, "--categories", "-cat", help="Specific categories to scan"
    ),
    checks: Optional[List[str]] = typer.Option(
        None, "--checks", "-ch", help="Specific checks to run"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable verbose output"
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Quiet mode - minimal output"
    )
):
    """Perform a security assessment scan on the target system."""
    try:
        # Setup logging based on verbosity
        if quiet:
            log_level = logging.ERROR
        elif verbose:
            log_level = logging.DEBUG
        else:
            log_level = logging.INFO

        # Setup logger - correzione della chiamata
        from ..utils.logger import setup_logger
        setup_logger(level=log_level)  # Rimosso file_logging=False

        # Load configuration - fix the string/dict issue
        if config_file:
            from ..utils.config import load_config
            config = load_config(config_file)
        else:
            config = {}

        # Ensure config is a dictionary
        if not isinstance(config, dict):
            console.print(f"[red]Error: Configuration must be a dictionary, got {type(config)}")
            raise typer.Exit(1)

        # Override config with command line options
        if not quiet:
            console.print(f"[blue]Starting scan of target: {target}")

        # Initialize scanner
        from ..core.scanner import Scanner
        scanner = Scanner(target, config)

        # Override enabled categories if specified
        if categories:
            if 'checks' not in config:
                config['checks'] = {}
            config['checks']['enabled_categories'] = categories

        # Perform scan
        results = scanner.scan(
            enabled_categories=categories,
            specific_checks=checks
        )

        # Generate output if requested
        if output:
            from ..utils.reporting import ReportGenerator
            generator = ReportGenerator()

            report_path = generator.generate_report(
                results,
                output,
                format,
                include_raw_data=True
            )

            if not quiet:
                console.print(f"[green]Report saved to: {report_path}")
        else:
            # Display summary to console
            _display_scan_summary(results)

        if not quiet:
            console.print("[green]Scan completed successfully!")

    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        console.print(f"[red]Scan failed: {str(e)}")
        if verbose:
            console.print(f"[red]Traceback:\n{traceback.format_exc()}")
        raise typer.Exit(1)


@app.command()
def configure(
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Path to save configuration file"
    ),
    interactive: bool = typer.Option(
        True, "--interactive/--no-interactive", help="Run in interactive mode"
    )
):
    """Create or update configuration file."""
    try:
        from ..utils.config import create_default_config, get_user_config_dir

        if output is None:
            config_dir = get_user_config_dir()
            output = config_dir / "config.json"

        # Ensure parent directory exists
        output.parent.mkdir(parents=True, exist_ok=True)

        if interactive:
            console.print("[bold blue]AGID Assessment Configuration Setup[/bold blue]")
            config = _interactive_config_setup()
        else:
            config = create_default_config()

        # Save configuration
        from ..utils.config import save_config
        save_config(config, output)

        console.print(f"[green]Configuration saved to: {output}")

    except Exception as e:
        logger.error(f"Configuration error: {str(e)}")
        console.print(f"[red]Configuration failed: {str(e)}")
        raise typer.Exit(1)


@app.command()
def list_checks(
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Filter by category"
    ),
    os_type: Optional[str] = typer.Option(
        None, "--os", help="Filter by OS type (windows, linux, macos)"
    )
):
    """List available security checks."""
    try:
        from ..checks.registry import CheckRegistry

        registry = CheckRegistry()
        checks = registry.get_all_checks()

        # Apply filters
        if category:
            checks = {k: v for k, v in checks.items() if k == category}

        if os_type:
            filtered_checks = {}
            for cat, check_list in checks.items():
                filtered_list = [c for c in check_list if c.is_applicable(os_type)]
                if filtered_list:
                    filtered_checks[cat] = filtered_list
            checks = filtered_checks

        # Display results
        if not checks:
            console.print("[yellow]No checks found matching the criteria.")
            return

        for category_name, check_list in checks.items():
            table = Table(title=f"Category: {category_name}")
            table.add_column("Check ID", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Severity", style="yellow")
            table.add_column("OS Support", style="blue")

            for check in check_list:
                os_support = ", ".join(check.supported_os)
                table.add_row(
                    check.check_id,
                    check.name,
                    check.severity,
                    os_support
                )

            console.print(table)
            console.print()

    except Exception as e:
        logger.error(f"List checks error: {str(e)}")
        console.print(f"[red]Failed to list checks: {str(e)}")
        raise typer.Exit(1)


@app.command()
def report(
    scan_file: Path = typer.Argument(help="Path to scan results file"),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
    format: str = typer.Option(
        "html", "--format", "-f", help="Output format (json, csv, html, xml, pdf)"
    ),
    include_raw: bool = typer.Option(
        False, "--include-raw", help="Include raw scan data in report"
    )
):
    """Generate a report from scan results."""
    try:
        import json

        # Check if scan file exists
        if not scan_file.exists():
            console.print(f"[red]Scan file not found: {scan_file}")
            raise typer.Exit(1)

        # Load scan results
        try:
            with open(scan_file, 'r') as f:
                scan_results = json.load(f)
        except json.JSONDecodeError:
            console.print(f"[red]Invalid JSON in scan file: {scan_file}")
            raise typer.Exit(1)

        # Generate output file name if not provided
        if output is None:
            output = scan_file.with_suffix(f".report.{format}")

        # Generate report
        from ..utils.reporting import ReportGenerator
        generator = ReportGenerator()

        report_path = generator.generate_report(
            scan_results,
            output,
            format,
            include_raw_data=include_raw
        )

        console.print(f"[green]Report generated: {report_path}")

    except Exception as e:
        logger.error(f"Report generation error: {str(e)}")
        console.print(f"[red]Report generation failed: {str(e)}")
        raise typer.Exit(1)


# Helper functions
def _display_scan_summary(results: dict):
    """Display a summary of scan results."""
    if not results:
        console.print("[yellow]No scan results to display.")
        return

    table = Table(title="Scan Summary")
    table.add_column("Category", style="cyan")
    table.add_column("Checks", style="blue")
    table.add_column("Status", style="green")

    for category, checks in results.items():
        if category == "scan_metadata":
            continue

        check_count = len(checks) if isinstance(checks, dict) else 1

        # Simple status determination
        status = "✅ Pass" if check_count > 0 else "❌ No checks"

        table.add_row(category, str(check_count), status)

    console.print(table)


def _interactive_config_setup() -> dict:
    """Interactive configuration setup."""
    from ..utils.config import create_default_config

    config = create_default_config()

    # Logging configuration
    console.print("\n[bold]Logging Configuration[/bold]")
    log_level = typer.prompt(
        "Log level (DEBUG, INFO, WARNING, ERROR)",
        default="INFO"
    )
    config["logging"]["level"] = log_level.upper()

    file_logging = typer.confirm("Enable file logging?", default=True)
    config["logging"]["file_logging"] = file_logging

    if file_logging:
        log_file = typer.prompt(
            "Log file path",
            default=str(Path.home() / ".agid_assessment" / "logs" / "assessment.log")
        )
        config["logging"]["log_file"] = log_file

    # Scan configuration
    console.print("\n[bold]Scan Configuration[/bold]")
    timeout = typer.prompt("Scan timeout (seconds)", default=300, type=int)
    config["scan"]["timeout"] = timeout

    parallel = typer.confirm("Enable parallel scanning?", default=True)
    config["scan"]["parallel"] = parallel

    if parallel:
        max_workers = typer.prompt("Max worker threads", default=4, type=int)
        config["scan"]["max_workers"] = max_workers

    # Check categories
    console.print("\n[bold]Check Categories[/bold]")
    console.print("Available categories: system, authentication, network, logging")

    categories = []
    for category in ["system", "authentication", "network", "logging"]:
        if typer.confirm(f"Enable {category} checks?", default=True):
            categories.append(category)

    config["checks"]["enabled_categories"] = categories

    return config


# Entry point for CLI
def main():
    """Main entry point for the CLI."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user.")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Unexpected error: {str(e)}")
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()