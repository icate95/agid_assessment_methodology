"""
Modulo per il controllo delle policy delle password.

Questo modulo fornisce un meccanismo di verifica completo per le policy delle
password su diversi sistemi operativi, con supporto per Windows, Linux e macOS.
"""

import os
import re
import json
import tempfile
import subprocess
import platform
import logging
from typing import Dict, Any, List, Optional, Tuple

from agid_assessment_methodology.checks.base import BaseCheck, CheckResult, CheckStatus


class PasswordPolicyCheck(BaseCheck):
    """
    Classe per la verifica delle policy delle password.

    Effettua controlli dettagliati su:
    - Lunghezza delle password
    - Complessità
    - Scadenza
    - Meccanismi di blocco account
    """

    def __init__(self):
        """Inizializza il controllo delle password con requisiti di sicurezza."""
        super().__init__()
        self.id = "password_policy"
        self.name = "Password Policy Security Check"
        self.description = "Verifica la conformità delle policy delle password agli standard di sicurezza"
        self.category = "authentication"
        self.severity = "high"
        self.supported_os = ["windows", "linux", "macos"]

        # Requisiti minimi di sicurezza per le password
        self.security_requirements = {
            "min_length": 12,
            "max_length": 128,
            "min_complexity": {
                "uppercase": True,
                "lowercase": True,
                "numbers": True,
                "special_chars": True
            },
            "max_age_days": 90,
            "min_age_days": 1,
            "password_history": 5,
            "lockout_threshold": 5,
            "lockout_duration_minutes": 30
        }

    def execute(self, context: Dict[str, Any]) -> CheckResult:
        """
        Esegue il controllo delle policy delle password.

        Args:
            context: Contesto di esecuzione contenente informazioni di sistema

        Returns:
            Risultato del controllo delle password
        """
        os_type = context.get('os_type', platform.system().lower())

        try:
            # Seleziona il metodo di controllo specifico per il sistema operativo
            password_policy_methods = {
                'windows': self._check_windows_password_policy,
                'linux': self._check_linux_password_policy,
                'darwin': self._check_macos_password_policy
            }

            # Esegui il metodo specifico per l'OS
            if os_type in password_policy_methods:
                return password_policy_methods[os_type]()
            else:
                return CheckResult(
                    status=CheckStatus.SKIPPED,
                    message=f"Password policy check non supportato per {os_type}"
                )

        except Exception as e:
            self._logger.error(f"Errore durante il controllo delle password policy: {str(e)}")
            return CheckResult(
                status=CheckStatus.ERROR,
                message=f"Errore nel controllo delle password policy: {str(e)}"
            )

    def _check_windows_password_policy(self) -> CheckResult:
        """
        Controlla le policy delle password su sistemi Windows.

        Returns:
            Risultato del controllo delle password per Windows
        """
        try:
            # Usa net accounts per ottenere informazioni di base
            net_accounts_result = subprocess.run(
                ['net', 'accounts'],
                capture_output=True, text=True, timeout=10
            )

            # Usa secedit per ottenere impostazioni di sicurezza più dettagliate
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                secedit_temp = temp_file.name
                subprocess.run(
                    ['secedit', '/export', '/cfg', secedit_temp],
                    capture_output=True, timeout=10
                )

            # Analizza i risultati
            policy_details = self._parse_windows_password_policy(
                net_accounts_result.stdout,
                secedit_temp
            )

            # Rimuovi il file temporaneo
            os.unlink(secedit_temp)

            # Valuta la conformità
            return self._evaluate_password_policy(policy_details)

        except Exception as e:
            self._logger.error(f"Errore nel controllo policy Windows: {str(e)}")
            return CheckResult(
                status=CheckStatus.FAIL,
                message=f"Errore nel controllo policy Windows: {str(e)}"
            )

    def _parse_windows_password_policy(self, net_output: str, secedit_path: str) -> Dict[str, Any]:
        """
        Analizza l'output dei comandi Windows per estrarre le policy delle password.

        Args:
            net_output: Output del comando net accounts
            secedit_path: Percorso al file temporaneo di secedit

        Returns:
            Dizionario con i dettagli delle policy
        """
        policy_details = {
            "source": "windows",
            "min_password_length": None,
            "max_password_age": None,
            "min_password_age": None,
            "password_history": None,
            "lockout_threshold": None,
            "complexity_enabled": False
        }

        # Parsing net accounts
        for line in net_output.split('\n'):
            line = line.strip()
            match_length = re.search(r'Minimum password length:\s*(\d+)', line, re.IGNORECASE)
            match_max_age = re.search(r'Maximum password age:\s*(\d+)\s*days', line, re.IGNORECASE)
            match_min_age = re.search(r'Minimum password age:\s*(\d+)\s*day', line, re.IGNORECASE)
            match_history = re.search(r'Password history length:\s*(\d+)', line, re.IGNORECASE)
            match_lockout = re.search(r'Lockout threshold:\s*(\d+)', line, re.IGNORECASE)

            if match_length:
                policy_details["min_password_length"] = int(match_length.group(1))
            if match_max_age:
                policy_details["max_password_age"] = int(match_max_age.group(1))
            if match_min_age:
                policy_details["min_password_age"] = int(match_min_age.group(1))
            if match_history:
                policy_details["password_history"] = int(match_history.group(1))
            if match_lockout:
                policy_details["lockout_threshold"] = int(match_lockout.group(1))

        # Parsing secedit per complessità
        try:
            with open(secedit_path, 'r') as f:
                secedit_content = f.read()
                policy_details["complexity_enabled"] = 'PasswordComplexity = 1' in secedit_content

        except Exception as e:
            self._logger.warning(f"Errore nel parsing secedit: {str(e)}")

        return policy_details

    def _check_linux_password_policy(self) -> CheckResult:
        """
        Controlla le policy delle password su sistemi Linux.

        Returns:
            Risultato del controllo delle password per Linux
        """
        try:
            # Analizza /etc/login.defs
            login_defs = self._parse_linux_login_defs()

            # Controlla configurazioni PAM
            pam_config = self._parse_linux_pam_config()

            # Combina i risultati
            policy_details = {
                "source": "linux",
                **login_defs,
                **pam_config
            }

            # Valuta la conformità
            return self._evaluate_password_policy(policy_details)

        except Exception as e:
            self._logger.error(f"Errore nel controllo policy Linux: {str(e)}")
            return CheckResult(
                status=CheckStatus.ERROR,
                message=f"Errore nel controllo policy Linux: {str(e)}"
            )

    def _parse_linux_login_defs(self) -> Dict[str, Any]:
        """
        Analizza /etc/login.defs per ottenere le policy delle password.

        Returns:
            Dizionario con i dettagli delle policy
        """
        policy_details = {
            "min_password_length": None,
            "max_password_age": None,
            "min_password_age": None
        }

        try:
            with open('/etc/login.defs', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('PASS_MIN_LEN'):
                        parts = line.split()
                        if len(parts) > 1:
                            policy_details["min_password_length"] = int(parts[1])

                    elif line.startswith('PASS_MAX_DAYS'):
                        parts = line.split()
                        if len(parts) > 1:
                            policy_details["max_password_age"] = int(parts[1])

                    elif line.startswith('PASS_MIN_DAYS'):
                        parts = line.split()
                        if len(parts) > 1:
                            policy_details["min_password_age"] = int(parts[1])

        except FileNotFoundError:
            self._logger.warning("File /etc/login.defs non trovato")
        except Exception as e:
            self._logger.error(f"Errore nel parsing login.defs: {str(e)}")

        return policy_details

    def _parse_linux_pam_config(self) -> Dict[str, Any]:
        """
        Controlla le configurazioni PAM per complessità delle password.

        Returns:
            Dizionario con dettagli di complessità
        """
        policy_details = {
            "complexity_enabled": False,
            "lockout_threshold": None
        }

        pam_files = [
            '/etc/pam.d/common-password',
            '/etc/pam.d/system-auth',
            '/etc/security/pwquality.conf'
        ]

        try:
            for pam_file in pam_files:
                if os.path.exists(pam_file):
                    with open(pam_file, 'r') as f:
                        content = f.read()

                        # Cerca moduli di complessità
                        if 'pam_pwquality.so' in content or 'pam_cracklib.so' in content:
                            policy_details["complexity_enabled"] = True

                        # Cerca impostazioni di lockout
                        lockout_match = re.search(r'deny=(\d+)', content)
                        if lockout_match:
                            policy_details["lockout_threshold"] = int(lockout_match.group(1))

        except Exception as e:
            self._logger.error(f"Errore nel parsing configurazioni PAM: {str(e)}")

        return policy_details

    def _check_macos_password_policy(self) -> CheckResult:
        """
        Controlla le policy delle password su macOS.

        Returns:
            Risultato del controllo delle password per macOS
        """
        try:
            # Usa pwpolicy per ottenere le policy
            pwpolicy_result = subprocess.run(
                ['pwpolicy', 'getaccountpolicies'],
                capture_output=True, text=True, timeout=10
            )

            # Analizza i risultati
            policy_details = self._parse_macos_password_policy(pwpolicy_result.stdout)

            # Valuta la conformità
            return self._evaluate_password_policy(policy_details)

        except Exception as e:
            self._logger.error(f"Errore nel controllo policy macOS: {str(e)}")
            return CheckResult(
                status=CheckStatus.ERROR,
                message=f"Errore nel controllo policy macOS: {str(e)}"
            )


    def _parse_macos_password_policy(self, pwpolicy_output: str) -> Dict[str, Any]:
        """
        Analizza l'output di pwpolicy per macOS.

        Args:
            pwpolicy_output: Output del comando pwpolicy

        Returns:
            Dizionario con i dettagli delle policy
        """
        policy_details = {
            "source": "macos",
            "min_password_length": None,
            "max_password_age": None,
            "complexity_enabled": False,
            "lockout_threshold": None
        }

        try:
            # Cerca la lunghezza minima della password
            length_match = re.search(r'policyAttributePasswordMinimumLength\s+(\d+)', pwpolicy_output)
            if length_match:
                policy_details["min_password_length"] = int(length_match.group(1))

            # Cerca la complessità
            if (re.search(r'policyAttributePasswordRequiresAlpha', pwpolicy_output) and
                re.search(r'policyAttributePasswordRequiresNumeric', pwpolicy_output)):
                policy_details["complexity_enabled"] = True

            # Cerca il blocco degli account
            lockout_match = re.search(r'policyAttributeMaximumFailedAuthentications\s+(\d+)', pwpolicy_output)
            if lockout_match:
                policy_details["lockout_threshold"] = int(lockout_match.group(1))

        except Exception as e:
            self._logger.error(f"Errore nel parsing policy macOS: {str(e)}")

        return policy_details

    def _evaluate_password_policy(self, policy: Dict[str, Any]) -> CheckResult:
        """
        Valuta la conformità delle policy delle password.

        Args:
            policy: Dizionario con i dettagli delle policy

        Returns:
            Risultato del controllo delle password
        """
        issues = []
        recommendations = []

        # Controllo lunghezza minima
        min_length = policy.get("min_password_length", 0)
        if min_length < self.security_requirements["min_length"]:
            issues.append(f"Lunghezza minima password insufficiente: {min_length}")
            recommendations.append(
                f"Aumentare la lunghezza minima a {self.security_requirements['min_length']} caratteri"
            )

        # Controllo complessità
        if not policy.get("complexity_enabled", False):
            issues.append("Complessità delle password non abilitata")
            recommendations.append(
                "Abilitare requisiti di complessità delle password (maiuscole, minuscole, numeri, caratteri speciali)"
            )

        # Controllo scadenza password
        max_age = policy.get("max_password_age")
        if max_age is None or max_age > self.security_requirements["max_age_days"]:
            issues.append(f"Scadenza password troppo lunga: {max_age} giorni")
            recommendations.append(
                f"Impostare la scadenza massima a {self.security_requirements['max_age_days']} giorni"
            )

        # Controllo periodo minimo tra cambi password
        min_age = policy.get("min_password_age", 0)
        if min_age < self.security_requirements["min_age_days"]:
            issues.append(f"Periodo minimo tra cambi password insufficiente: {min_age} giorni")
            recommendations.append(
                f"Impostare un periodo minimo di {self.security_requirements['min_age_days']} giorni tra i cambi password"
            )

        # Controllo storia delle password
        history = policy.get("password_history", 0)
        if history < self.security_requirements["password_history"]:
            issues.append(f"Storia delle password insufficiente: {history}")
            recommendations.append(
                f"Mantenere almeno {self.security_requirements['password_history']} password precedenti non riutilizzabili"
            )

        # Controllo soglia di blocco
        lockout_threshold = policy.get("lockout_threshold")
        if lockout_threshold is None or lockout_threshold > self.security_requirements["lockout_threshold"]:
            issues.append(f"Soglia di blocco account troppo alta: {lockout_threshold} tentativi")
            recommendations.append(
                f"Impostare la soglia di blocco a massimo {self.security_requirements['lockout_threshold']} tentativi"
            )

        # Determina lo status
        if not issues:
            status = CheckStatus.PASS
            message = "Tutte le policy delle password soddisfano i requisiti minimi di sicurezza"
        elif len(issues) <= 2:
            status = CheckStatus.WARNING
            message = f"Trovati {len(issues)} problemi nelle policy delle password"
        else:
            status = CheckStatus.FAIL
            message = f"Trovati {len(issues)} problemi critici nelle policy delle password"

        return CheckResult(
            status=status,
            message=message,
            details={
                "source": policy.get("source", "unknown"),
                "policy_details": policy,
                "total_issues": len(issues)
            },
            issues=[{"description": issue} for issue in issues],
            recommendations=recommendations
        )

    def _analyze_password_complexity(self, password: str) -> Dict[str, bool]:
        """
        Analizza la complessità di una password di esempio.

        Args:
            password: Password da analizzare

        Returns:
            Dizionario con i criteri di complessità soddisfatti
        """
        complexity = {
            "min_length": len(password) >= self.security_requirements["min_length"],
            "uppercase": bool(re.search(r'[A-Z]', password)),
            "lowercase": bool(re.search(r'[a-z]', password)),
            "numbers": bool(re.search(r'\d', password)),
            "special_chars": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }

        return complexity

    def generate_password_example(self) -> str:
        """
        Genera un esempio di password conforme ai requisiti.

        Returns:
            Una password di esempio che soddisfa i requisiti di sicurezza
        """
        import random
        import string

        # Definisci set di caratteri
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        numbers = string.digits
        special_chars = "!@#$%^&*(),.?\":{}|<>"

        # Assicura almeno un carattere per categoria
        password_chars = [
            random.choice(uppercase),
            random.choice(lowercase),
            random.choice(numbers),
            random.choice(special_chars)
        ]

        # Aggiungi caratteri casuali per raggiungere la lunghezza minima
        remaining_length = self.security_requirements["min_length"] - len(password_chars)
        all_chars = uppercase + lowercase + numbers + special_chars
        password_chars.extend(
            random.choice(all_chars) for _ in range(remaining_length)
        )

        # Mescola i caratteri
        random.shuffle(password_chars)

        return ''.join(password_chars)

    def __str__(self) -> str:
        """
        Rappresentazione stringa del controllo.

        Returns:
            Stringa descrittiva del controllo
        """
        return (
            f"PasswordPolicyCheck(id='{self.id}', "
            f"severity='{self.severity}', "
            f"supported_os={self.supported_os})"
        )

    def get_requirements_summary(self) -> Dict[str, Any]:
        """
        Fornisce un riepilogo dei requisiti di sicurezza delle password.

        Returns:
            Dizionario con i requisiti di sicurezza
        """
        return {
            "minimum_length": self.security_requirements["min_length"],
            "maximum_length": self.security_requirements["max_length"],
            "complexity_requirements": self.security_requirements["min_complexity"],
            "max_password_age_days": self.security_requirements["max_age_days"],
            "min_password_age_days": self.security_requirements["min_age_days"],
            "password_history_length": self.security_requirements["password_history"],
            "account_lockout_threshold": self.security_requirements["lockout_threshold"],
            "account_lockout_duration_minutes": self.security_requirements["lockout_duration_minutes"]
        }

    def is_password_valid(self, password: str) -> bool:
        """
        Verifica se una password soddisfa tutti i requisiti di sicurezza.

        Args:
            password: Password da verificare

        Returns:
            True se la password è conforme ai requisiti, False altrimenti
        """
        complexity = self._analyze_password_complexity(password)

        # Controlla tutti i criteri di complessità
        return all([
            complexity["min_length"],
            complexity["uppercase"],
            complexity["lowercase"],
            complexity["numbers"],
            complexity["special_chars"]
        ])

    def calculate_password_strength(self, password: str) -> float:
        """
        Calcola un punteggio di forza della password.

        Args:
            password: Password da valutare

        Returns:
            Punteggio di forza (0-100)
        """
        # Parametri per il calcolo della forza
        strength_factors = {
            "length": 0.3,
            "uppercase": 0.15,
            "lowercase": 0.15,
            "numbers": 0.15,
            "special_chars": 0.25
        }

        # Analizza la complessità
        complexity = self._analyze_password_complexity(password)

        # Calcola il punteggio
        strength_score = sum(
            strength_factors[factor] * (1 if value else 0)
            for factor, value in complexity.items()
        ) * 100

        # Penalità per password troppo lunghe o troppo corte
        length_penalty = max(0, min(1, (len(password) - self.security_requirements["min_length"]) / 10))
        strength_score *= (1 + length_penalty)

        return min(max(strength_score, 0), 100)

    def generate_password_recommendations(self, policy_details: Dict[str, Any]) -> List[str]:
        """
        Genera raccomandazioni per le policy delle password.

        Args:
            policy_details: Dizionario con i dettagli delle policy

        Returns:
            Lista di raccomandazioni per migliorare le policy delle password
        """
        recommendations = []

        # Controllo lunghezza minima
        min_length = policy_details.get("min_password_length", 0)
        if min_length < self.security_requirements["min_length"]:
            recommendations.append(
                f"Aumentare la lunghezza minima delle password a {self.security_requirements['min_length']} caratteri"
            )

        # Controllo complessità
        if not policy_details.get("complexity_enabled", False):
            recommendations.append(
                "Abilitare requisiti di complessità delle password (maiuscole, minuscole, numeri, caratteri speciali)"
            )

        # Controllo scadenza password
        max_age = policy_details.get("max_password_age")
        if max_age is None or max_age > self.security_requirements["max_age_days"]:
            recommendations.append(
                f"Impostare la scadenza massima delle password a {self.security_requirements['max_age_days']} giorni"
            )

        # Controllo periodo minimo tra cambi password
        min_age = policy_details.get("min_password_age", 0)
        if min_age < self.security_requirements["min_age_days"]:
            recommendations.append(
                f"Impostare un periodo minimo di {self.security_requirements['min_age_days']} giorni tra i cambi password"
            )

        # Controllo storia delle password
        history = policy_details.get("password_history", 0)
        if history < self.security_requirements["password_history"]:
            recommendations.append(
                f"Mantenere almeno {self.security_requirements['password_history']} password precedenti non riutilizzabili"
            )

        # Controllo soglia di blocco
        lockout_threshold = policy_details.get("lockout_threshold")
        if lockout_threshold is None or lockout_threshold > self.security_requirements["lockout_threshold"]:
            recommendations.append(
                f"Impostare la soglia di blocco account a massimo {self.security_requirements['lockout_threshold']} tentativi"
            )

        return recommendations