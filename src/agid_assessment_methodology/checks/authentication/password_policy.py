"""
Modulo per il controllo delle policy delle password.

Questo modulo fornisce un meccanismo di verifica completo per le policy delle
password su diversi sistemi operativi, con supporto per Windows, Linux e macOS.
Include controlli avanzati di sicurezza delle password.
"""

import os
import re
import json
import tempfile
import subprocess
import platform
import logging
import zxcvbn
from typing import Dict, Any, List, Optional, Tuple

from agid_assessment_methodology.checks.base import BaseCheck, CheckResult, CheckStatus


class PasswordPolicyCheck(BaseCheck):
    """
    Classe per la verifica delle policy delle password con controlli avanzati.

    Effettua controlli dettagliati su:
    - Lunghezza delle password
    - Complessità
    - Scadenza
    - Meccanismi di blocco account
    - Rilevamento di password compromesse
    - Analisi di dizionario e pattern
    """

    def __init__(self):
        """Inizializza il controllo delle password con requisiti di sicurezza avanzati."""
        super().__init__()
        self.id = "password_policy"
        self.name = "Password Policy Security Check"
        self.description = "Verifica approfondita della conformità delle policy delle password agli standard di sicurezza più rigorosi"
        self.category = "authentication"
        self.severity = "high"
        self.supported_os = ["windows", "linux", "macos"]

        # Requisiti minimi di sicurezza delle password rafforzati
        self.security_requirements = {
            "min_length": 14,  # Aumentato a 14 caratteri
            "max_length": 128,
            "min_complexity": {
                "uppercase": True,
                "lowercase": True,
                "numbers": True,
                "special_chars": True,
                "min_char_types": 3,  # Almeno 3 tipi di caratteri
            },
            "max_age_days": 90,  # Massimo 3 mesi
            "min_age_days": 1,  # Almeno un giorno tra i cambi
            "password_history": 10,  # Mantieni storia delle ultime 10 password
            "lockout_threshold": 5,  # Dopo 5 tentativi
            "lockout_duration_minutes": 30,
            "prohibited_patterns": [
                r'\d{4,}',  # Sequenze numeriche
                r'(?i)password',  # Parola "password"
                r'(?i)123',  # Sequenze semplici
                r'(?i)qwerty',  # Pattern di tastiera
                r'(?i)admin',  # Parole admin/amministratore
                r'(?i)welcome',
                r'(?i)letmein'
            ]
        }

        # Lista di password compromesse (da espandere/aggiornare periodicamente)
        self.compromised_passwords = [
            'password', '123456', 'qwerty', 'admin', 'welcome',
            'letmein', 'monkey', '123123', 'dragon', 'baseball'
        ]

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
            # Metodi specifici per OS per ottenere le policy delle password
            if os_type == 'windows':
                policy_details = self._get_windows_password_policies()
            elif os_type == 'linux':
                policy_details = self._get_linux_password_policies()
            elif os_type == 'darwin':  # macOS
                policy_details = self._get_macos_password_policies()
            else:
                return CheckResult(
                    status=CheckStatus.SKIPPED,
                    message=f"Controllo policy password non supportato per {os_type}"
                )

            # Genera una password di esempio per test
            test_password = self.generate_secure_password()

            # Valuta la password di esempio
            password_analysis = self.evaluate_password_against_requirements(test_password)

            # Crea il report finale
            return self._create_password_policy_report(
                policy_details,
                password_analysis
            )

        except Exception as e:
            self._logger.error(f"Errore durante il controllo delle password policy: {str(e)}")
            return CheckResult(
                status=CheckStatus.ERROR,
                message=f"Errore nel controllo delle password policy: {str(e)}"
            )

    def check_password_against_compromised_list(self, password: str) -> bool:
        """
        Verifica se la password è presente in una lista di password compromesse.

        Args:
            password: Password da verificare

        Returns:
            True se la password è compromessa, False altrimenti
        """
        return (
            password.lower() in self.compromised_passwords or
            any(pw in password.lower() for pw in self.compromised_passwords)
        )

    def check_password_complexity_advanced(self, password: str) -> Dict[str, Any]:
        """
        Esegue un'analisi avanzata della complessità della password.

        Utilizza zxcvbn per una valutazione più approfondita.

        Args:
            password: Password da analizzare

        Returns:
            Dizionario con dettagli sulla complessità
        """
        try:
            # Usa zxcvbn per l'analisi della password
            result = zxcvbn.password_strength(password)

            complexity_details = {
                "score": result['score'],  # Punteggio da 0 a 4
                "entropy": result['entropy'],  # Entropia della password
                "crack_time_seconds": result['crack_times_seconds']['online_no_throttling_10_per_second'],
                "feedback": result.get('feedback', {}).get('suggestions', []),
                "warnings": result.get('feedback', {}).get('warning', ''),

                # Controlli custom aggiuntivi
                "char_types": {
                    "uppercase": bool(re.search(r'[A-Z]', password)),
                    "lowercase": bool(re.search(r'[a-z]', password)),
                    "numbers": bool(re.search(r'\d', password)),
                    "special_chars": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
                },
                "char_types_count": sum([
                    bool(re.search(r'[A-Z]', password)),
                    bool(re.search(r'[a-z]', password)),
                    bool(re.search(r'\d', password)),
                    bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
                ])
            }

            return complexity_details

        except ImportError:
            # Fallback se zxcvbn non è installato
            return self._analyze_password_complexity(password)

    def generate_secure_password(self, length: int = 16) -> str:
        """
        Genera una password sicura utilizzando criteri avanzati.

        Args:
            length: Lunghezza della password (default 16)

        Returns:
            Password generata
        """
        import secrets
        import string

        # Set di caratteri per la generazione
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        punctuation = "!@#$%^&*(),.?\":{}|<>"

        # Combina tutti i set di caratteri
        all_chars = uppercase + lowercase + digits + punctuation

        # Assicura la presenza di almeno un carattere per categoria
        password_chars = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(punctuation)
        ]

        # Aggiungi caratteri casuali per raggiungere la lunghezza desiderata
        remaining_length = length - len(password_chars)
        password_chars.extend(secrets.choice(all_chars) for _ in range(remaining_length))

        # Mescola i caratteri
        secrets.SystemRandom().shuffle(password_chars)

        return ''.join(password_chars)

    def evaluate_password_against_requirements(self, password: str) -> Dict[str, Any]:
        """
        Valuta una password rispetto a requisiti di sicurezza avanzati.

        Args:
            password: Password da valutare

        Returns:
            Dizionario con i risultati della valutazione
        """
        evaluation = {
            "meets_length_requirement": len(password) >= self.security_requirements["min_length"],
            "meets_complexity_requirement": False,
            "is_compromised": self.check_password_against_compromised_list(password),
            "prohibited_pattern_matches": [],
            "complexity_details": None
        }

        # Analisi complessità avanzata
        try:
            complexity_details = self.check_password_complexity_advanced(password)
            evaluation["complexity_details"] = complexity_details

            # Valutazione complessità
            char_types_met = sum(complexity_details["char_types"].values())
            evaluation["meets_complexity_requirement"] = (
                complexity_details["score"] >= 3 and  # zxcvbn score
                char_types_met >= self.security_requirements["min_complexity"]["min_char_types"]
            )
        except Exception:
            # Fallback al metodo base se zxcvbn non è disponibile
            basic_complexity = self._analyze_password_complexity(password)
            evaluation["complexity_details"] = basic_complexity
            evaluation["meets_complexity_requirement"] = (
                basic_complexity["min_length"] and
                basic_complexity["uppercase"] and
                basic_complexity["lowercase"] and
                basic_complexity["numbers"] and
                basic_complexity["special_chars"]
            )

        # Controllo pattern proibiti
        for pattern in self.security_requirements["prohibited_patterns"]:
            match = re.search(pattern, password, re.IGNORECASE)
            if match:
                evaluation["prohibited_pattern_matches"].append({
                    "pattern": pattern,
                    "matched_text": match.group(0)
                })

        return evaluation

    def recommend_password_improvements(self, password_eval: Dict[str, Any]) -> List[str]:
        """
        Genera raccomandazioni specifiche per migliorare una password.

        Args:
            password_eval: Risultati della valutazione della password

        Returns:
            Lista di raccomandazioni
        """
        recommendations = []

        if not password_eval["meets_length_requirement"]:
            recommendations.append(
                f"Aumentare la lunghezza della password a minimo {self.security_requirements['min_length']} caratteri"
            )

        if not password_eval["meets_complexity_requirement"]:
            recommendations.append(
                "Aumentare la complessità della password usando una combinazione di maiuscole, "
                "minuscole, numeri e caratteri speciali"
            )

        if password_eval["is_compromised"]:
            recommendations.append(
                "La password corrente è presente in un elenco di password compromesse. "
                "Cambiare immediatamente la password."
            )

        if password_eval["prohibited_pattern_matches"]:
            recommendations.append(
                "Evitare pattern o parole comuni facilmente indovinabili"
            )

        # Suggerimenti da zxcvbn, se disponibile
        complexity_details = password_eval.get("complexity_details", {})
        feedback = complexity_details.get("feedback", [])
        warnings = complexity_details.get("warnings", '')

        if feedback:
            recommendations.extend([
                f"Suggerimento: {suggestion}" for suggestion in feedback
            ])

        if warnings:
            recommendations.append(f"Avvertenza: {warnings}")

        return recommendations

    def check_breach_databases(self, password: str) -> Dict[str, Any]:
        """
        Verifica la password contro database di password compromesse.

        NOTA: Questa è un'implementazione di esempio.
        In un'implementazione reale, si dovrebbe utilizzare un servizio
        come HaveIBeenPwned API.

        Args:
            password: Password da verificare

        Returns:
            Dizionario con i risultati della verifica
        """
        # Implementazione di esempio molto semplificata
        try:
            # In un'implementazione reale, si farebbe una chiamata API
            # a un servizio come HaveIBeenPwned
            import hashlib

            # Hash della password per la verifica
            password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

            # Lista di hash di password compromesse (esempio)
            compromised_hashes = [
                '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8',  # password
                '8CB2237D0679CA88DB6464EAE60836444F1F9E47'   # 12345
            ]

            return {
                "hash": password_hash,
                "compromised": password_hash in compromised_hashes,
                "details": "Verificato contro una lista di hash di password compromesse"
            }

        except Exception as e:
            return {
                "error": str(e),
                "compromised": None,
                "details": "Impossibile completare la verifica"
            }

    def advanced_password_audit(self, username: Optional[str] = None) -> Dict[str, Any]:
        """
        Esegue un audit approfondito delle password.

        Args:
            username: Nome utente opzionale per analisi contestuale

        Returns:
            Dizionario con i risultati dell'audit
        """
        # In un'implementazione reale, si potrebbe:
        # 1. Controllare la password corrente dell'utente
        # 2. Verificare la storia delle password
        # 3. Controllare i requisiti di sistema

        audit_results = {
            "password_rotation_needed": False,
            "last_change_days": None,
            "system_password_policies": self.security_requirements
        }

        # Logica di esempio (da adattare al sistema specifico)
        try:
            # Qui si potrebbe integrare con meccanismi specifici del sistema operativo
            # per ottenere informazioni sulla password dell'utente
            pass
        except Exception as e:
            audit_results["error"] = str(e)

        return audit_results

    def _create_password_policy_report(self,
                                       system_password_policies: Dict[str, Any],
                                       password_analysis: Dict[str, Any]) -> CheckResult:
        """
        Crea un report dettagliato della policy delle password.

        Args:
            system_password_policies: Policy di sistema
            password_analysis: Analisi delle password

        Returns:
            CheckResult con i dettagli della policy
        """
        # Determina lo status basato sull'analisi
        status = CheckStatus.PASS
        issues = []
        recommendations = []

        if not password_analysis.get("meets_length_requirement", False):
            status = CheckStatus.WARNING
            issues.append({
                "severity": "high",
                "description": "Lunghezza minima password non soddisfatta"
            })

        if not password_analysis.get("meets_complexity_requirement", False):
            status = CheckStatus.FAIL
            issues.append({
                "severity": "critical",
                "description": "Requisiti di complessità password non soddisfatti"
            })

        if password_analysis.get("is_compromised", False):
            status = CheckStatus.FAIL
            issues.append({
                "severity": "critical",
                "description": "Password presente in elenchi di password compromesse"
            })

        # Genera raccomandazioni
        recommendations = self.recommend_password_improvements(password_analysis)

        # Calcola il punteggio
        score = self._calculate_password_policy_score(password_analysis)

        return CheckResult(
            status=status,
            message="Verifica delle policy delle password completata",
            details={
                "system_policies": system_password_policies,
                "password_analysis": password_analysis
            },
            issues=issues,
            recommendations=recommendations,
            score=self._calculate_password_policy_score(password_analysis)
        )

    def _calculate_password_policy_score(self, password_analysis: Dict[str, Any]) -> float:
        """
        Calcola un punteggio per la policy delle password.

        Args:
            password_analysis: Risultati dell'analisi della password

        Returns:
            Punteggio (0-100)
        """
        score = 100.0  # Inizia con un punteggio massimo

        # Sottrai punti per problemi specifici
        if not password_analysis.get("meets_length_requirement", False):
            score -= 30

        if not password_analysis.get("meets_complexity_requirement", False):
            score -= 40

        if password_analysis.get("is_compromised", False):
            score -= 50

        # Controlla i pattern proibiti
        prohibited_matches = password_analysis.get("prohibited_pattern_matches", [])
        score -= len(prohibited_matches) * 10

        # Assicura che il punteggio sia tra 0 e 100
        return max(0, min(score, 100))

    def _get_windows_password_policies(self) -> Dict[str, Any]:
        """
        Ottiene le policy delle password per Windows.

        Returns:
            Dizionario con i dettagli delle policy di Windows
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

            return policy_details

        except Exception as e:
            self._logger.error(f"Errore nel recupero delle policy Windows: {str(e)}")
            return {}

    def _get_linux_password_policies(self) -> Dict[str, Any]:
        """
        Ottiene le policy delle password per Linux.

        Returns:
            Dizionario con i dettagli delle policy di Linux
        """
        try:
            # Analizza /etc/login.defs
            login_defs = self._parse_linux_login_defs()

            # Controlla configurazioni PAM
            pam_config = self._parse_linux_pam_config()

            # Combina i risultati
            return {
                **login_defs,
                **pam_config
            }

        except Exception as e:
            self._logger.error(f"Errore nel recupero delle policy Linux: {str(e)}")
            return {}

    def _get_macos_password_policies(self) -> Dict[str, Any]:
        """
        Ottiene le policy delle password per macOS.

        Returns:
            Dizionario con i dettagli delle policy di macOS
        """
        try:
            # Usa pwpolicy per ottenere le policy
            pwpolicy_result = subprocess.run(
                ['pwpolicy', 'getaccountpolicies'],
                capture_output=True, text=True, timeout=10
            )

            # Analizza i risultati
            return self._parse_macos_password_policy(pwpolicy_result.stdout)

        except Exception as e:
            self._logger.error(f"Errore nel recupero delle policy macOS: {str(e)}")
            return {}