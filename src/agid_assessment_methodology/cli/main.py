import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional
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
        None, "--category", "-c", help="Filter checks by category"
    ),
    os_type: Optional[str] = typer.Option(
        None, "--os", help="Filter by OS type (windows, linux, macos)"
    )
):
    """List available security checks."""
    try:
        # Debug imports
        import sys
        import importlib

        console.print("[bold]Python Path:[/bold]")
        for path in sys.path:
            console.print(path)

        console.print("\n[bold]Checking imports...[/bold]")

        # Forza l'importazione dei moduli
        modules_to_check = [
            'agid_assessment_methodology.checks.system.system_info',
            'agid_assessment_methodology.checks.system.basic_security',
            'agid_assessment_methodology.checks.authentication.password_policy',
            'agid_assessment_methodology.checks.network.firewall',
            'agid_assessment_methodology.checks.network.open_ports',
            'agid_assessment_methodology.checks.network.ssl_tls',
            'agid_assessment_methodology.checks.malware.antivirus',
            'agid_assessment_methodology.checks.malware.definitions',
            'agid_assessment_methodology.checks.malware.quarantine'
        ]

        for module_name in modules_to_check:
            try:
                module = importlib.import_module(module_name)
                console.print(f"[green]Imported:[/green] {module_name}")
            except ImportError as e:
                console.print(f"[red]Failed to import:[/red] {module_name}")
                console.print(f"Error: {e}")

        # Importa il registro dei controlli
        from ..checks.registry import CheckRegistry

        registry = CheckRegistry()
        checks = registry.get_registry_info()

        console.print(f"\n[bold]Total Checks in Registry:[/bold] {len(registry._checks)}")

        for check_id, check in registry._checks.items():
            console.print(f"[yellow]Check:[/yellow] {check_id}")
            console.print(f"  Name: {check.name}")
            console.print(f"  Category: {check.category}")
            console.print(f"  Severity: {check.severity}")
            console.print(f"  Supported OS: {check.supported_os}")
            console.print()
        # Se non ci sono controlli registrati, mostra tutti i controlli disponibili
        if not checks.get('available_checks'):
            console.print("[yellow]No checks are registered. Showing all available checks in the system.[/yellow]")

        # Se nessun filtro è stato applicato, mostra tutti i controlli
        available_checks = checks.get('available_checks', [])

        # Applica filtri se specificati
        if category:
            available_checks = [
                check for check in available_checks
                if check['category'].lower() == category.lower()
            ]

        if os_type:
            available_checks = [
                check for check in available_checks
                if os_type.lower() in [os.lower() for os in check['supported_os']]
            ]

        # Se non ci sono check dopo i filtri, mostra un messaggio
        if not available_checks:
            console.print("[yellow]No checks found matching the specified criteria.[/yellow]")

            # Se nessun filtro è stato applicato, mostra tutti i controlli disponibili nel sistema
            if not category and not os_type:
                console.print("\n[bold]All Available Checks:[/bold]")
                available_checks = registry.get_registry_info().get('available_checks', [])

        # Crea una tabella per visualizzare i controlli
        table = Table(title="Security Checks")
        table.add_column("Check ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Category", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Supported OS", style="blue")

        for check in available_checks:
            table.add_row(
                check.get('id', 'N/A'),
                check.get('name', 'N/A'),
                check.get('category', 'N/A'),
                check.get('severity', 'N/A'),
                ", ".join(check.get('supported_os', [])) if check.get('supported_os') else 'N/A'
            )

        # Stampa la tabella
        console.print(table)

        # Stampa il numero totale di controlli
        console.print(f"\n[bold]Total Checks:[/bold] {len(available_checks)}")

    except Exception as e:
        console.print(f"[red]Critical Error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise typer.Exit(code=1)

def get_registry_info(self) -> Dict[str, any]:
    """
    Ottiene informazioni sul registro.

    Returns:
        Informazioni sul registro
    """
    # Se non ci sono controlli, restituisci una lista vuota ma con una struttura consistente
    if not self._checks:
        return {
            "total_checks": 0,
            "categories": {},
            "available_checks": []
        }

    return {
        "total_checks": len(self._checks),
        "categories": {
            category: len(checks)
            for category, checks in self._checks_by_category.items()
        },
        "available_checks": [
            {
                "id": check.id,
                "name": check.name,
                "category": check.category,
                "severity": check.severity,
                "supported_os": check.supported_os
            }
            for check in self._checks.values()
        ]
    }

@app.command()
def list_categories(
    show_counts: bool = typer.Option(
        False, "--counts", "-c", help="Show check counts for each category"
    )
):
    """List all available check categories."""
    try:
        from ..checks.registry import CheckRegistry

        registry = CheckRegistry()

        # Verifica se il registry è vuoto
        if len(registry) == 0:
            console.print("[yellow]No checks are registered. Make sure checks are properly loaded.[/yellow]")
            console.print("[dim]Tip: Check if your check modules are being imported correctly.[/dim]")
            return

        categories = registry.get_categories()

        if not categories:
            console.print("[yellow]No categories found.")
            return

        table = Table(title="Available Check Categories")
        table.add_column("Category", style="cyan")
        table.add_column("Description", style="green")

        if show_counts:
            table.add_column("Check Count", style="blue")

        # Definisci descrizioni per le categorie (puoi personalizzarle)
        category_descriptions = {
            "system": "System configuration and security checks",
            "authentication": "Authentication and authorization checks",
            "network": "Network security and configuration checks",
            "logging": "Logging and monitoring configuration checks",
            "compliance": "Compliance and regulatory checks",
            "encryption": "Encryption and cryptographic checks"
        }

        for category_name in sorted(categories):
            description = category_descriptions.get(category_name, "Security checks")
            check_count = len(registry.get_checks_by_category(category_name))

            if show_counts:
                table.add_row(
                    category_name,
                    description,
                    str(check_count)
                )
            else:
                table.add_row(category_name, description)

        console.print(table)
        console.print(f"\n[dim]Total categories: {len(categories)}[/dim]")

        if not show_counts:
            console.print("[dim]Use --counts to see the number of checks per category[/dim]")

    except Exception as e:
        logger.error(f"List categories error: {str(e)}")
        console.print(f"[red]Failed to list categories: {str(e)}")
        raise typer.Exit(1)

# Comando di debug per verificare lo stato del registry
@app.command()
def debug_registry():
    """Debug command to check registry status."""
    try:
        from ..checks.registry import CheckRegistry

        registry = CheckRegistry()
        info = registry.get_registry_info()

        console.print("[bold blue]Registry Debug Information[/bold blue]")
        console.print(f"Total checks: {info['total_checks']}")
        console.print(f"Categories: {len(info['categories'])}")

        if info['categories']:
            console.print("\nCategories breakdown:")
            for cat, count in info['categories'].items():
                console.print(f"  - {cat}: {count} checks")
        else:
            console.print("[yellow]No categories found - registry appears to be empty[/yellow]")
            console.print("[dim]This suggests that checks are not being registered properly.[/dim]")

    except Exception as e:
        console.print(f"[red]Debug failed: {str(e)}")
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


@app.command()
def schedule(
        target: str = typer.Argument(..., help="Target to schedule assessment for"),
        frequency: str = typer.Option("daily", help="Frequency of assessment"),
        time: str = typer.Option("02:00", help="Time of day for assessment"),
        categories: Optional[List[str]] = typer.Option(None, help="Specific check categories"),
        output: Optional[Path] = typer.Option(None, help="Output directory for reports")
):
    """Schedule recurring security assessments."""
    from ..scheduler import AssessmentScheduler

    scheduler = AssessmentScheduler()
    task_id = scheduler.schedule_assessment(
        target,
        frequency=frequency,
        time_of_day=time,
        categories=categories,
        output_dir=output
    )

    console.print(f"[green]Assessment scheduled with ID: {task_id}")
    scheduler.start()


@app.command()
def list_scheduled():
    """List scheduled security assessments."""
    from ..scheduler import AssessmentScheduler

    scheduler = AssessmentScheduler()
    tasks = scheduler.list_scheduled_tasks()

    table = Table(title="Scheduled Assessments")
    table.add_column("Target", style="cyan")
    table.add_column("Frequency", style="green")
    table.add_column("Time", style="yellow")

    for task in tasks:
        table.add_row(
            task['target'],
            task['frequency'],
            task['time']
        )

    console.print(table)


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