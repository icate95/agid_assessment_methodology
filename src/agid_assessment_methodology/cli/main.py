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

# Aggiungi callback per --version globale
def version_callback(value: bool):
    if value:
        try:
            from .. import __version__
            console.print(f"AGID Assessment Methodology v{__version__}")
        except ImportError:
            console.print("AGID Assessment Methodology v0.1.0")
        raise typer.Exit()

# Aggiungi opzione globale --version
@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", callback=version_callback,
        help="Show version and exit"
    )
):
    """AGID Assessment Methodology - Security Assessment Tool."""
    pass

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
        None, "--categories", "-cat", help="Specific categories to scan (can be used multiple times)"
    ),
    checks: Optional[List[str]] = typer.Option(
        None, "--checks", "-ch", help="Specific checks to run (can be used multiple times)"
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

        print(results)
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

    # Rimuovi scan_metadata dai risultati per il summary
    summary_results = {k: v for k, v in results.items() if k != "scan_metadata"}
    print(results)
    for category, checks in summary_results.items():
        if isinstance(checks, dict):
            # Se è un dizionario di checks, conta gli elementi
            check_count = len(checks)

            # Determina lo status basato sui risultati
            if check_count > 0:
                # Controlla se ci sono check con status specifici
                statuses = []
                for check_name, check_data in checks.items():
                    if isinstance(check_data, dict) and "status" in check_data:
                        statuses.append(check_data["status"])

                # Determina status complessivo
                if statuses:
                    if any(s in ["fail", "error"] for s in statuses):
                        status = "❌ Issues Found"
                    elif any(s == "warning" for s in statuses):
                        status = "⚠️ Warnings"
                    else:
                        status = "✅ Pass"
                else:
                    status = "✅ Pass"
            else:
                status = "❌ No checks"
        else:
            # Se non è un dizionario, considera come singolo check
            check_count = 1
            status = "✅ Pass"

        print(category)
        table.add_row(category, str(check_count), status)

    console.print(table)


def _interactive_config_setup() -> dict:
    """Interactive configuration setup."""
    from ..utils.config import create_default_config

    config = create_default_config()

    # Logging configuration
    console.print("\n[bold]Logging Configuration[/bold]")
    log_level = typer.prompt(
        "Log level",
        default="INFO",
        show_default=True
    )
    config["logging"]["level"] = log_level.upper()

    file_logging = typer.confirm(
        "Enable file logging?",
        default=True,
        show_default=True
    )
    config["logging"]["file_logging"] = file_logging

    if file_logging:
        # Usa il percorso corretto per il log
        default_log_path = Path.home() / ".agid_assessment" / "logs" / "assessment.log"
        log_file = typer.prompt(
            "Log file path",
            default=str(default_log_path),
            show_default=True
        )
        config["logging"]["log_file"] = log_file

        # Assicurati che la directory del log esista
        log_dir = Path(log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)

    # Scan configuration
    console.print("\n[bold]Scan Configuration[/bold]")
    timeout = typer.prompt(
        "Scan timeout (seconds)",
        default=300,
        type=int,
        show_default=True
    )
    config["scan"]["timeout"] = timeout

    parallel = typer.confirm(
        "Enable parallel scanning?",
        default=True,
        show_default=True
    )
    config["scan"]["parallel"] = parallel

    if parallel:
        max_workers = typer.prompt(
            "Max worker threads",
            default=4,
            type=int,
            show_default=True
        )
        config["scan"]["max_workers"] = max_workers

    # Check categories
    console.print("\n[bold]Check Categories[/bold]")
    console.print("Available categories: system, authentication, network, logging")

    categories = []
    for category in ["system", "authentication", "network", "logging"]:
        if typer.confirm(
            f"Enable {category} checks?",
            default=True,
            show_default=True
        ):
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