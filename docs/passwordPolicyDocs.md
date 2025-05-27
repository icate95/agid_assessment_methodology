# Password Policy Check

## Panoramica
Il modulo `PasswordPolicyCheck` implementa un controllo completo e multipiattaforma per le policy delle password, verificando la sicurezza delle configurazioni su Windows, Linux e macOS.

## Funzionalità Principali
- Verifica lunghezza minima delle password
- Controllo complessità delle password
- Analisi della scadenza delle password
- Valutazione dei meccanismi di blocco account
- Supporto per Windows, Linux e macOS

## Requisiti Minimi di Sicurezza
- Lunghezza minima password: 12 caratteri
- Complessità: Richiede maiuscole, minuscole, numeri e caratteri speciali
- Scadenza massima: 90 giorni
- Periodo minimo tra cambi: 1 giorno
- Tentativi di blocco: Massimo 5 tentativi

## Metodi di Verifica per Sistema Operativo

### Windows
- Utilizza `net accounts` e `secedit` per estrarre le policy
- Verifica la complessità tramite registro di sistema
- Controlla lunghezza, scadenza e storia delle password

### Linux
- Analizza `/etc/login.defs`
- Verifica le configurazioni PAM
- Controlla moduli come `pam_pwquality` e `pam_cracklib`

### macOS
- Usa il comando `pwpolicy`
- Verifica le policy di sistema per lunghezza e complessità
- Controlla i meccanismi di blocco account

## Esempi di Utilizzo

```python
from agid_assessment_methodology.checks.authentication.password_policy import PasswordPolicyCheck

# Crea un'istanza del check
check = PasswordPolicyCheck()

# Esegui il controllo 
context = {"os_type": "linux"}
result = check.execute(context)

# Verifica lo stato
print(result.status)  # Pass/Fail/Warning
print(result.message)  # Descrizione del risultato
print(result.details)  # Dettagli completi delle policy
print(result.recommendations)  # Suggerimenti per migliorare
```

## Output Tipico
```json
{
    "status": "pass",
    "message": "Tutte le policy delle password soddisfano i requisiti minimi di sicurezza",
    "details": {
        "min_password_length": 12,
        "complexity_enabled": true,
        "max_password_age": 90,
        "lockout_threshold": 5
    },
    "recommendations": []
}
```

## Best Practice
1. Mantenere una lunghezza minima di almeno 12 caratteri
2. Abilitare sempre la complessità delle password
3. Impostare scadenze regol