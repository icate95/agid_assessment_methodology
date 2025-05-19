"""Entry point principale per la CLI di AGID Assessment Methodology."""

import typer
from rich.console import Console
from pathlib import Path

# Import utilities
from agid_assessment_methodology.utils import (
    load_config, save_config, setup_logger_from_config,
    get_user_config_dir, ensure_config_dir
)

# Crea l'applicazione typer principale
app = typer.Typer(
    name="agid-assessment",
    help="Framework per audit di sicurezza ABSC",
    add_completion=False,
)

# Console per output colorato
console = Console()


@app.command()
def version():
    """Mostra la versione del software."""
    try:
        from agid_assessment_methodology import __version__
        console.print(f"AGID Assessment Methodology v{__version__}")
    except ImportError:
        console.print("Versione non disponibile")


@app.command()
def info():
    """Mostra informazioni sul progetto."""
    console.print("[bold blue]AGID Assessment Methodology[/bold blue]")
    console.print("Framework per audit di sicurezza basato sui requisiti minimi ABSC")
    console.print("\n[bold]Features principali:[/bold]")
    console.print("• Controlli di sicurezza automatizzati")
    console.print("• Verifica della compliance")
    console.print("• Report multipli formati")
    console.print("• Supporto Windows e Linux")


@app.command()
def scan(
    target: str = typer.Argument("localhost", help="Target system to scan"),
    config_file: Path = typer.Option(None, "--config", "-c", help="Path to config file"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file for report"),
    format: str = typer.Option("json", "--format", "-f", help="Report format (json, csv, html, pdf)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output")
):
    """Esegue una scansione di sicurezza base sul target specificato."""
    from agid_assessment_methodology.core import Scanner, Assessment

    # Carica configurazione
    config = load_config(config_file)

    # Setup logging basato sulla configurazione
    logger = setup_logger_from_config(config)

    console.print(f"[bold blue]Avvio scansione di {target}...[/bold blue]")

    try:
        # Crea scanner e esegui scansione
        scanner = Scanner(target, config)
        console.print(f"• Rilevamento sistema operativo...")
        os_type = scanner.detect_os()
        console.print(f"  Sistema rilevato: [green]{os_type}[/green]")

        console.print("• Esecuzione scansione base...")
        scan_results = scanner.run_basic_scan()

        # Crea assessment e analizza risultati
        console.print("• Analisi risultati...")
        assessment = Assessment(scan_results)
        analysis = assessment.analyze_security_posture()

        # Mostra riepilogo
        console.print("\n[bold]📊 Riepilogo Scansione[/bold]")
        summary = analysis["summary"]
        console.print(f"Controlli totali: {summary['total_checks']}")
        console.print(f"Controlli completati: [green]{summary['completed_checks']}[/green]")
        console.print(f"Tasso di successo: [yellow]{summary['success_rate']}%[/yellow]")
        console.print(f"Livello di rischio: [red]{summary['risk_level']}[/red]")

        # Mostra compliance
        console.print("\n[bold]✅ Stato Compliance[/bold]")
        for level in ["basic", "standard", "advanced"]:
            compliance = assessment.check_compliance(level)
            status_color = "green" if compliance["status"] == "compliant" else "red"
            console.print(f"{level.capitalize()}: [{status_color}]{compliance['compliance_percentage']}%[/{status_color}]")

        if verbose:
            console.print("\n[bold]📋 Dettagli per categoria:[/bold]")
            for category, details in analysis["categories"].items():
                console.print(f"• {category}: {details['status']}")
                if details.get("critical_issues"):
                    console.print(f"  [red]⚠ {len(details['critical_issues'])} problemi critici[/red]")

        # Genera report se richiesto
        if output:
            console.print(f"\n• Generazione report in formato {format}...")
            report_path = assessment.generate_report(str(output), format)
            console.print(f"Report salvato: [bold]{report_path}[/bold]")

        console.print("\n[bold green]✨ Scansione completata![/bold green]")

    except Exception as e:
        console.print(f"[bold red]❌ Errore durante la scansione: {str(e)}[/bold red]")
        logger.error(f"Scan error: {str(e)}", exc_info=verbose)
        if verbose:
            console.print_exception()
        raise typer.Exit(code=1)


@app.command()
def configure(
    output: Path = typer.Option(
        None,
        "--output",
        "-o",
        help="Path to save configuration file"
    ),
    interactive: bool = typer.Option(
        True,
        "--interactive/--no-interactive",
        help="Run in interactive mode"
    )
):
    """Crea o aggiorna la configurazione del tool."""
    # Determina il percorso di output
    if not output:
        config_dir = ensure_config_dir()
        output = config_dir / "config.json"

    console.print("[bold blue]🔧 Configurazione AGID Assessment[/bold blue]\n")

    if interactive:
        console.print("Configurazione interattiva dei parametri:")

        # Carica configurazione esistente se presente
        current_config = load_config(output if output.exists() else None)

        # Configurazione scan
        console.print("\n[bold]Impostazioni Scansione[/bold]")
        timeout = typer.prompt(
            "Timeout scansione (secondi)",
            default=current_config["scan"]["timeout"],
            type=int
        )

        parallel = typer.confirm(
            "Abilita scansione parallela?",
            default=current_config["scan"]["parallel"]
        )

        max_threads = typer.prompt(
            "Numero massimo thread",
            default=current_config["scan"]["max_threads"],
            type=int
        ) if parallel else 1

        # Configurazione controlli
        console.print("\n[bold]Configurazione Controlli[/bold]")
        from agid_assessment_methodology.checks import registry

        all_categories = registry.get_categories()
        console.print(f"Categorie disponibili: {', '.join(all_categories)}")

        enabled_categories = []
        for category in all_categories:
            if typer.confirm(f"Abilita categoria '{category}'?", default=True):
                enabled_categories.append(category)

        # Configurazione reporting
        console.print("\n[bold]Configurazione Report[/bold]")
        include_details = typer.confirm(
            "Includi dettagli nei report?",
            default=current_config["reporting"]["include_details"]
        )

        include_recommendations = typer.confirm(
            "Includi raccomandazioni nei report?",
            default=current_config["reporting"]["include_recommendations"]
        )

        default_format = typer.prompt(
            "Formato report predefinito",
            default=current_config["reporting"]["default_format"],
            type=typer.Choice(["json", "csv", "html", "pdf"])
        )

        # Configurazione logging
        console.print("\n[bold]Configurazione Logging[/bold]")
        log_level = typer.prompt(
            "Livello di log",
            default=current_config["logging"]["level"],
            type=typer.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        )

        file_logging = typer.confirm(
            "Abilita logging su file?",
            default=current_config["logging"]["file_logging"]
        )

        # Costruisce la nuova configurazione
        new_config = {
            "scan": {
                "timeout": timeout,
                "parallel": parallel,
                "max_threads": max_threads,
                "retry_attempts": current_config["scan"]["retry_attempts"],
                "retry_delay": current_config["scan"]["retry_delay"]
            },
            "checks": {
                "enabled_categories": enabled_categories,
                "excluded_checks": current_config["checks"]["excluded_checks"],
                "severity_threshold": current_config["checks"]["severity_threshold"],
                "custom_thresholds": current_config["checks"]["custom_thresholds"]
            },
            "reporting": {
                "include_details": include_details,
                "include_recommendations": include_recommendations,
                "include_raw_data": current_config["reporting"]["include_raw_data"],
                "default_format": default_format,
                "output_directory": current_config["reporting"]["output_directory"],
                "template_directory": current_config["reporting"]["template_directory"]
            },
            "credentials": current_config["credentials"],
            "logging": {
                "level": log_level,
                "file_logging": file_logging,
                "log_directory": current_config["logging"]["log_directory"],
                "max_file_size": current_config["logging"]["max_file_size"],
                "backup_count": current_config["logging"]["backup_count"],
                "format": current_config["logging"]["format"]
            },
            "database": current_config["database"]
        }
    else:
        # Usa configurazione predefinita
        from agid_assessment_methodology.utils.config import DEFAULT_CONFIG
        new_config = DEFAULT_CONFIG.copy()

    # Salva la configurazione
    if save_config(new_config, output):
        console.print(f"\n[bold green]✅ Configurazione salvata in: {output}[/bold green]")

        # Mostra riepilogo
        console.print("\n[bold]📋 Riepilogo Configurazione:[/bold]")
        console.print(f"• Timeout scansione: {new_config['scan']['timeout']}s")
        console.print(f"• Scansione parallela: {'Sì' if new_config['scan']['parallel'] else 'No'}")
        console.print(f"• Categorie abilitate: {len(new_config['checks']['enabled_categories'])}")
        console.print(f"• Formato report predefinito: {new_config['reporting']['default_format']}")
        console.print(f"• Livello logging: {new_config['logging']['level']}")
    else:
        console.print(f"[bold red]❌ Errore nel salvataggio della configurazione[/bold red]")


@app.command()
def report(
    assessment_file: Path = typer.Argument(..., help="Path to assessment results file"),
    output: Path = typer.Option(None, "--output", "-o", help="Output path for report"),
    format: str = typer.Option("html", "--format", "-f", help="Report format"),
    template: str = typer.Option(None, "--template", "-t", help="Template name to use")
):
    """Genera un report da file di risultati assessment esistente."""
    import json

    if not assessment_file.exists():
        console.print(f"[bold red]❌ File non trovato: {assessment_file}[/bold red]")
        raise typer.Exit(code=1)

    try:
        # Carica i risultati dell'assessment
        with open(assessment_file, 'r') as f:
            assessment_data = json.load(f)

        # Determina il percorso di output
        if not output:
            output = assessment_file.parent / f"{assessment_file.stem}_report.{format}"

        # Genera il report
        from agid_assessment_methodology.utils.reporting import ReportGenerator
        generator = ReportGenerator()

        report_path = generator.generate_report(
            assessment_data,
            output,
            format,
            template_name=template,
            include_raw_data=True
        )

        console.print(f"[bold green]✅ Report generato: {report_path}[/bold green]")

        # Mostra statistiche
        if isinstance(assessment_data, dict):
            summary = assessment_data.get("summary", {})
            if summary:
                console.print(f"\n[bold]📊 Statistiche Report:[/bold]")
                console.print(f"• Controlli totali: {summary.get('total_checks', 'N/A')}")
                console.print(f"• Tasso successo: {summary.get('success_rate', 'N/A')}%")
                console.print(f"• Livello rischio: {summary.get('risk_level', 'N/A')}")

    except json.JSONDecodeError:
        console.print(f"[bold red]❌ File JSON non valido: {assessment_file}[/bold red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]❌ Errore nella generazione del report: {str(e)}[/bold red]")
        raise typer.Exit(code=1)


@app.command()
def list_checks(
    category: str = typer.Option(None, "--category", "-c", help="Filter by category"),
    os_type: str = typer.Option(None, "--os", "-o", help="Filter by OS type")
):
    """Elenca tutti i controlli di sicurezza disponibili."""
    from agid_assessment_methodology.checks import registry

    # Ottieni informazioni sui controlli
    registry_info = registry.get_registry_info()

    console.print("[bold blue]📋 Controlli di Sicurezza Disponibili[/bold blue]\n")

    if category:
        checks = registry.get_checks_by_category(category)
        console.print(f"[bold]Categoria: {category}[/bold]")
    elif os_type:
        checks = registry.get_checks_for_os(os_type)
        console.print(f"[bold]Sistema Operativo: {os_type}[/bold]")
    else:
        checks = registry.get_all_checks()
        console.print(f"[bold]Tutti i controlli ({len(checks)} totali)[/bold]")

    # Raggruppa per categoria
    by_category = {}
    for check in checks:
        cat = check.category
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(check)

    # Mostra i controlli per categoria
    for cat, cat_checks in by_category.items():
        console.print(f"\n[bold green]🔍 {cat.title()}[/bold green]")

        for check in cat_checks:
            # Colore basato sulla severità
            severity_colors = {
                "low": "green",
                "medium": "yellow",
                "high": "red",
                "critical": "bold red"
            }
            severity_color = severity_colors.get(check.severity, "white")

            console.print(f"  • [cyan]{check.id}[/cyan]: {check.name}")
            console.print(f"    [dim]{check.description}[/dim]")
            console.print(f"    Severità: [{severity_color}]{check.severity}[/{severity_color}] | OS: {', '.join(check.supported_os)}")

    # Statistiche
    console.print(f"\n[bold]📊 Statistiche[/bold]")
    console.print(f"Controlli totali: {registry_info['total_checks']}")
    console.print(f"Categorie: {len(registry_info['categories'])}")

    for cat, count in registry_info['categories'].items():
        console.print(f"  • {cat}: {count} controlli")


if __name__ == "__main__":
    app()