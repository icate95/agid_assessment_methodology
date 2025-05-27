# AGID Assessment Methodology - Documentazione Completa

## Indice

1. [Introduzione](#introduzione)
2. [Installazione](#installazione)
3. [Configurazione](#configurazione)
4. [Guida ai Comandi](#guida-ai-comandi)
5. [Casi d'Uso](#casi-duso)
6. [Struttura dei Report](#struttura-dei-report)
7. [API Reference](#api-reference)
8. [FAQ](#faq)

---

## Introduzione

AGID Assessment Methodology è un framework completo per audit di sicurezza basato sulle misure minime di sicurezza ABSC. Il sistema fornisce controlli automatizzati di sicurezza, verifica di compliance, generazione di report e funzionalità di scheduling per la valutazione della sicurezza dell'infrastruttura IT.

### Caratteristiche Principali

- **Architettura modulare** per supporto Windows e Linux
- **Controlli di sicurezza integrati** per:
  - Inventario dispositivi
  - Gestione vulnerabilità
  - Protezione malware
  - Politiche di autenticazione
  - Procedure di backup
  - Crittografia
  - Pratiche di logging
- **Storage flessibile** (SQLite/PostgreSQL)
- **Export multipli** (JSON, CSV, HTML, PDF, XML)
- **Interfaccia CLI completa**
- **Supporto per Web UI e REST API** (pianificato)

---

## Installazione

### Prerequisiti

- Python 3.6 o superiore
- pip (package installer per Python)

### Installazione da PyPI

```bash
pip install agid-assessment-methodology
```

### Installazione da sorgenti

```bash
git clone https://github.com/icate95/agid_assessment_methodology.git
cd agid_assessment_methodology
pip install -e .
```

### Verifica installazione

```bash
agid-assessment --version
agid-assessment info
```

---

## Configurazione

### Configurazione Automatica

```bash
# Configurazione interattiva
agid-assessment configure

# Configurazione non interattiva con valori di default
agid-assessment configure --no-interactive

# Salva in percorso personalizzato
agid-assessment configure --output /path/to/custom/config.json
```

### Struttura File di Configurazione

```json
{
  "logging": {
    "level": "INFO",
    "file_logging": true,
    "log_file": "~/.agid_assessment/logs/assessment.log",
    "max_file_size": "10MB",
    "backup_count": 5
  },
  "scan": {
    "timeout": 300,
    "parallel": true,
    "max_workers": 4,
    "retry_attempts": 3
  },
  "checks": {
    "enabled_categories": ["system", "authentication", "network", "logging"],
    "excluded_checks": [],
    "custom_checks_path": null
  },
  "reporting": {
    "include_raw_data": true,
    "default_format": "html",
    "output_directory": "~/.agid_assessment/reports"
  },
  "credentials": {
    "store_encrypted": true,
    "use_system_credentials": true
  }
}
```

---

## Guida ai Comandi

### 1. Informazioni Sistema

```bash
# Mostra informazioni versione e sistema
agid-assessment version
agid-assessment info
```

**Output esempio:**
```
System Information
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property       ┃ Value                        ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Platform       │ Linux-5.4.0-x86_64          │
│ Python Version │ 3.8.10                       │
│ Architecture   │ 64bit                        │
│ Tool Version   │ 0.1.0                        │
└────────────────┴──────────────────────────────┘
```

### 2. Scansione Sistema

#### Scansione Base

```bash
# Scansione del sistema locale
agid-assessment scan localhost

# Scansione con output specifico
agid-assessment scan localhost --output report.json --format json

# Scansione con configurazione personalizzata
agid-assessment scan localhost --config myconfig.json
```

#### Scansione Avanzata

```bash
# Scansione di categorie specifiche
agid-assessment scan localhost --categories system authentication

# Scansione con controlli specifici
agid-assessment scan localhost --checks system_info basic_security

# Modalità verbosa o silenziosa
agid-assessment scan localhost --verbose
agid-assessment scan localhost --quiet
```

#### Formati di Output Supportati

- `json` - Dati strutturati JSON
- `csv` - Tabella CSV
- `html` - Report HTML interattivo
- `pdf` - Documento PDF
- `xml` - Struttura XML

### 3. Lista Controlli Disponibili

```bash
# Lista tutti i controlli
agid-assessment list-checks

# Filtra per categoria
agid-assessment list-checks --category authentication

# Filtra per sistema operativo
agid-assessment list-checks --os linux
```

**Output esempio:**
```
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┓
┃ Check ID             ┃ Name                                         ┃ Severity  ┃ OS Support           ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩
│ system_info          │ System Information Collection                │ LOW       │ windows, linux, macos│
│ basic_security       │ Basic Security Configuration                 │ HIGH      │ windows, linux       │
│ password_policy      │ Password Policy Assessment                   │ HIGH      │ windows, linux       │
└──────────────────────┴──────────────────────────────────────────────┴───────────┴──────────────────────┘
```

### 4. Generazione Report

```bash
# Genera report da file di scansione esistente
agid-assessment report scan_results.json --format html

# Report con output personalizzato
agid-assessment report scan_results.json --output security_report.pdf --format pdf

# Include dati grezzi nel report
agid-assessment report scan_results.json --include-raw --format html
```

### 5. Configurazione

```bash
# Setup interattivo
agid-assessment configure

# Setup non interattivo (usa defaults)
agid-assessment configure --no-interactive

# Output personalizzato
agid-assessment configure --output /etc/agid/config.json
```

---

## Casi d'Uso

### Caso d'Uso 1: Audit Iniziale Sistema

**Scenario:** Prima valutazione di sicurezza di un nuovo server

```bash
# 1. Configura tool
agid-assessment configure --no-interactive

# 2. Esegui scansione completa
agid-assessment scan localhost --output initial_audit.json --verbose

# 3. Genera report HTML dettagliato
agid-assessment report initial_audit.json --format html --include-raw

# 4. Lista problemi trovati
agid-assessment list-checks --category authentication
```

### Caso d'Uso 2: Monitoraggio Compliance Periodico

**Scenario:** Verifica mensile compliance ABSC

```bash
# 1. Scansione focalizzata su compliance
agid-assessment scan localhost \
  --categories authentication backup malware \
  --output "compliance_$(date +%Y%m%d).json" \
  --format json

# 2. Genera report esecutivo
agid-assessment report "compliance_$(date +%Y%m%d).json" \
  --format pdf \
  --output "compliance_report_$(date +%Y%m%d).pdf"

# 3. Genera anche CSV per analisi
agid-assessment report "compliance_$(date +%Y%m%d).json" \
  --format csv \
  --output "compliance_data_$(date +%Y%m%d).csv"
```

### Caso d'Uso 3: Audit Pre-Produzione

**Scenario:** Verifica sicurezza prima del deployment

```bash
# 1. Configura per ambiente di test
agid-assessment configure --output test_config.json

# 2. Scansione completa con configurazione test
agid-assessment scan test-server \
  --config test_config.json \
  --output pre_prod_audit.json \
  --categories system authentication network

# 3. Report dettagliato per team
agid-assessment report pre_prod_audit.json \
  --format html \
  --include-raw \
  --output pre_prod_security_report.html
```

### Caso d'Uso 4: Audit Multi-Sistema

**Scenario:** Valutazione sicurezza di più sistemi

```bash
#!/bin/bash
# Script per audit multi-sistema

SYSTEMS=("web-server" "db-server" "app-server")
DATE=$(date +%Y%m%d)

# Crea directory per reports
mkdir -p reports/$DATE

for system in "${SYSTEMS[@]}"; do
    echo "Scanning $system..."
    
    # Scansione sistema
    agid-assessment scan $system \
      --output "reports/$DATE/${system}_scan.json" \
      --quiet
    
    # Genera report
    agid-assessment report "reports/$DATE/${system}_scan.json" \
      --format html \
      --output "reports/$DATE/${system}_report.html"
done

echo "Multi-system audit completed in reports/$DATE/"
```

### Caso d'Uso 5: Controlli Personalizzati

**Scenario:** Focus su categorie specifiche per diversi team

```bash
# Team di Rete - Focus networking
agid-assessment scan localhost \
  --categories network \
  --output network_audit.json

# Team di Autenticazione - Focus auth
agid-assessment scan localhost \
  --categories authentication \
  --output auth_audit.json

# Team di Sistema - Focus configurazione base
agid-assessment scan localhost \
  --categories system logging \
  --output system_audit.json

# Genera report consolidato (manualmente o tramite script)
```

---

## Struttura dei Report

### Report JSON

```json
{
  "metadata": {
    "report_generated": "2025-01-15T10:30:00Z",
    "tool_version": "0.1.0",
    "report_version": "1.0"
  },
  "executive_summary": {
    "overall_risk_level": "medium",
    "total_checks": 15,
    "passed_checks": 12,
    "failed_checks": 3,
    "critical_issues": 1,
    "scan_timestamp": "2025-01-15T10:00:00Z"
  },
  "compliance_summary": {
    "overall_compliance_score": 85.5,
    "basic_compliance": {
      "level": "basic",
      "compliance_percentage": 90.0,
      "completed_checks": ["system_info", "basic_security"],
      "missing_checks": ["backup_policy"]
    }
  },
  "detailed_results": [
    {
      "category": "system",
      "status": "passed",
      "checks": [
        {
          "name": "system_info",
          "status": "pass",
          "score": 95,
          "issues_count": 0,
          "recommendations_count": 1
        }
      ]
    }
  ],
  "recommendations": [
    {
      "priority": "high",
      "category": "authentication",
      "check": "password_policy",
      "description": "Implementare policy password più restrittive"
    }
  ]
}
```

### Report HTML

Il report HTML include:

- **Executive Summary**: Panoramica con grafici
- **Compliance Dashboard**: Status compliance per livello
- **Detailed Results**: Risultati per categoria
- **Risk Analysis**: Analisi dei rischi identificati
- **Recommendations**: Raccomandazioni prioritizzate
- **Raw Data** (opzionale): Dati completi della scansione

### Report PDF

Struttura professionale con:

- Copertina con logo e metadata
- Executive summary con grafici
- Sezioni dettagliate per categoria
- Appendici con dati tecnici
- Footer con informazioni di compliance

---

## API Reference

### Uso Programmatico

```python
from agid_assessment_methodology.core import Scanner, Assessment
from agid_assessment_methodology.utils.reporting import ReportGenerator

# Inizializza scanner
scanner = Scanner("localhost")

# Esegui scansione
results = scanner.run_basic_scan()

# Crea assessment
assessment = Assessment(results)

# Genera report
report_path = assessment.generate_report("report.html", "html")
```

### Configurazione Programmatica

```python
from agid_assessment_methodology.utils.config import load_config, save_config

# Carica configurazione
config = load_config("config.json")

# Modifica configurazione
config["scan"]["timeout"] = 600

# Salva configurazione
save_config(config, "updated_config.json")
```

---

## FAQ

### Q: Come installo il tool su sistemi senza accesso internet?

**A:** Scarica il pacchetto wheel e installa offline:

```bash
# Su sistema con internet
pip download agid-assessment-methodology

# Su sistema offline
pip install agid-assessment-methodology-0.1.0-py3-none-any.whl
```

### Q: Posso eseguire scansioni su sistemi remoti?

**A:** Attualmente supportiamo principalmente scansioni locali. Il supporto per sistemi remoti via SSH/WinRM è in sviluppo.

### Q: Come posso aggiungere controlli personalizzati?

**A:** Puoi estendere il sistema creando nuovi check:

```python
from agid_assessment_methodology.checks.base import BaseCheck

class CustomCheck(BaseCheck):
    def __init__(self):
        super().__init__()
        self.check_id = "custom_check"
        self.name = "Custom Security Check"
        self.category = "custom"
        self.severity = "medium"
    
    def execute(self, context):
        # Implementa la logica del check
        pass
```

### Q: Come interpreto i livelli di compliance?

**A:** 
- **Basic**: Controlli essenziali di sicurezza
- **Standard**: Conformità alle best practice
- **Advanced**: Controlli avanzati per alta sicurezza

### Q: Posso schedulare scansioni automatiche?

**A:** Usa il sistema di scheduling del tuo OS:

```bash
# Crontab per scansione settimanale
0 3 * * 1 /usr/local/bin/agid-assessment scan localhost --output /var/log/security/weekly_scan.json
```

### Q: Come esporto solo specifici risultati?

**A:** Usa i filtri di categoria durante la scansione:

```bash
agid-assessment scan localhost --categories authentication network --output filtered_scan.json
```

### Q: Il tool richiede privilegi amministrativi?

**A:** Alcuni controlli richiedono privilegi elevati. Esegui come amministratore/root per risultati completi.

### Q: Come contribuisco al progetto?

**A:** Vedi [CONTRIBUTING.md](CONTRIBUTING.md) per linee guida su:
- Reporting bug
- Richieste feature
- Invio di pull request
- Setup ambiente di sviluppo

---

## Supporto

- **Repository**: https://github.com/icate95/agid_assessment_methodology
- **Issues**: https://github.com/icate95/agid_assessment_methodology/issues
- **Documentation**: https://agid-assessment-methodology.readthedocs.io
- **Email**: ianesellicaterina@gmail.com

---

*Questa documentazione è aggiornata alla versione 0.1.0*