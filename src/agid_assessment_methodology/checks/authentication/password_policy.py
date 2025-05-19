"""Controllo per verificare le policy delle password."""

import subprocess
import re
from typing import Dict, Any
from ..base import BaseCheck, CheckResult, CheckStatus


class PasswordPolicyCheck(BaseCheck):
    """Controllo per verificare le policy di sicurezza delle password."""

    def __init__(self):
        super().__init__()
        self.id = "password_policy"
        self.name = "Password Policy Check"
        self.description = "Verifica le impostazioni della policy delle password del sistema"
        self.category = "authentication"
        self.severity = "high"
        self.supported_os = ["windows", "linux", "macos"]

    def execute(self, context: Dict[str, Any]) -> CheckResult:
        """
        Esegue la verifica delle policy delle password.

        Args:
            context: Contesto di esecuzione

        Returns:
            Risultato del controllo delle policy password
        """
        issues = []
        recommendations = []
        policy_checks = {}
        os_type = context.get("os_type", "unknown")

        try:
            if os_type == "windows":
                policy_checks = self._check_windows_password_policy()
            elif os_type == "linux":
                policy_checks = self._check_linux_password_policy()
            elif os_type == "macos":
                policy_checks = self._check_macos_password_policy()
            else:
                return CheckResult(
                    status=CheckStatus.SKIPPED,
                    message=f"Password policy check not supported for {os_type}"
                )

            # Analizza i risultati e genera issues/recommendations
            issues, recommendations = self._analyze_policy_results(policy_checks, os_type)

            # Calcola il punteggio
            score = self._calculate_policy_score(policy_checks)

            # Determina lo status
            if not policy_checks:
                status = CheckStatus.ERROR
            elif issues:
                critical_issues = [i for i in issues if i.get("severity") == "critical"]
                high_issues = [i for i in issues if i.get("severity") == "high"]
                if critical_issues:
                    status = CheckStatus.FAIL
                elif high_issues:
                    status = CheckStatus.WARNING
                else:
                    status = CheckStatus.WARNING
            else:
                status = CheckStatus.PASS

            return CheckResult(
                status=status,
                message=f"Password policy check completed with {len(issues)} issues found",
                details=policy_checks,
                issues=issues,
                recommendations=recommendations,
                score=score
            )

        except Exception as e:
            return CheckResult(
                status=CheckStatus.ERROR,
                message=f"Error during password policy check: {str(e)}",
                details={"error": str(e)}
            )

    def _check_windows_password_policy(self) -> Dict[str, Any]:
        """Controlla le policy delle password su Windows."""
        policy = {}

        try:
            # Usa net accounts per ottenere le policy
            result = subprocess.run(
                ['net', 'accounts'],
                capture_output=True, text=True
            )

            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    line = line.strip()
                    if 'Minimum password length' in line:
                        match = re.search(r'(\d+)', line)
                        policy['min_length'] = int(match.group(1)) if match else None
                    elif 'Maximum password age' in line:
                        if 'Never' in line:
                            policy['max_age_days'] = None
                        else:
                            match = re.search(r'(\d+)', line)
                            policy['max_age_days'] = int(match.group(1)) if match else None
                    elif 'Minimum password age' in line:
                        match = re.search(r'(\d+)', line)
                        policy['min_age_days'] = int(match.group(1)) if match else None
                    elif 'Password history length' in line:
                        match = re.search(r'(\d+)', line)
                        policy['history_length'] = int(match.group(1)) if match else None
                    elif 'Lockout threshold' in line:
                        if 'Never' in line:
                            policy['lockout_threshold'] = None
                        else:
                            match = re.search(r'(\d+)', line)
                            policy['lockout_threshold'] = int(match.group(1)) if match else None

            # Controlla la complexity policy usando secedit
            try:
                temp_file = "secedit_output.inf"
                subprocess.run(
                    ['secedit', '/export', '/cfg', temp_file],
                    capture_output=True
                )

                with open(temp_file, 'r') as f:
                    content = f.read()
                    if 'PasswordComplexity = 1' in content:
                        policy['complexity_enabled'] = True
                    elif 'PasswordComplexity = 0' in content:
                        policy['complexity_enabled'] = False

                import os
                if os.path.exists(temp_file):
                    os.remove(temp_file)

            except Exception:
                policy['complexity_enabled'] = None

        except Exception as e:
            self._logger.error(f"Error checking Windows password policy: {e}")
            policy['error'] = str(e)

        return policy

    def _check_linux_password_policy(self) -> Dict[str, Any]:
        """Controlla le policy delle password su Linux."""
        policy = {}

        try:
            # Controlla /etc/login.defs
            try:
                with open('/etc/login.defs', 'r') as f:
                    content = f.read()

                    # Estrae le configurazioni
                    patterns = {
                        'min_length': r'PASS_MIN_LEN\s+(\d+)',
                        'max_age_days': r'PASS_MAX_DAYS\s+(\d+)',
                        'min_age_days': r'PASS_MIN_DAYS\s+(\d+)',
                        'warn_days': r'PASS_WARN_AGE\s+(\d+)'
                    }

                    for key, pattern in patterns.items():
                        match = re.search(pattern, content)
                        if match:
                            policy[key] = int(match.group(1))

            except FileNotFoundError:
                policy['login_defs_error'] = "/etc/login.defs not found"

            # Controlla PAM per complexity
            try:
                pam_files = ['/etc/pam.d/common-password', '/etc/pam.d/system-auth']
                policy['pam_complexity'] = {}

                for pam_file in pam_files:
                    try:
                        with open(pam_file, 'r') as f:
                            content = f.read()

                            # Cerca pam_pwquality o pam_cracklib
                            if 'pam_pwquality' in content:
                                policy['pam_complexity']['module'] = 'pam_pwquality'
                                policy['pam_complexity']['enabled'] = True

                                # Estrae parametri comuni
                                minlen_match = re.search(r'minlen=(\d+)', content)
                                if minlen_match:
                                    policy['pam_complexity']['minlen'] = int(minlen_match.group(1))

                            elif 'pam_cracklib' in content:
                                policy['pam_complexity']['module'] = 'pam_cracklib'
                                policy['pam_complexity']['enabled'] = True
                            else:
                                policy['pam_complexity']['enabled'] = False

                    except FileNotFoundError:
                        continue

            except Exception as e:
                policy['pam_error'] = str(e)

            # Controlla /etc/security/pwquality.conf se esiste
            try:
                with open('/etc/security/pwquality.conf', 'r') as f:
                    content = f.read()
                    policy['pwquality_config'] = {}

                    patterns = {
                        'minlen': r'minlen\s*=\s*(\d+)',
                        'minclass': r'minclass\s*=\s*(\d+)',
                        'maxrepeat': r'maxrepeat\s*=\s*(\d+)',
                        'maxsequence': r'maxsequence\s*=\s*(\d+)'
                    }

                    for key, pattern in patterns.items():
                        match = re.search(pattern, content)
                        if match:
                            policy['pwquality_config'][key] = int(match.group(1))

            except FileNotFoundError:
                pass

        except Exception as e:
            self._logger.error(f"Error checking Linux password policy: {e}")
            policy['error'] = str(e)

        return policy

    def _check_macos_password_policy(self) -> Dict[str, Any]:
        """Controlla le policy delle password su macOS."""
        policy = {}

        try:
            # Usa pwpolicy per ottenere le policy
            result = subprocess.run(
                ['pwpolicy', '-getaccountpolicies'],
                capture_output=True, text=True
            )

            if result.returncode == 0:
                # Parse del XML output (semplificato)
                policy['raw_output'] = result.stdout

                # Estrae valori comuni
                if 'policyAttributeMaximumFailedAuthentications' in result.stdout:
                    policy['lockout_enabled'] = True
                else:
                    policy['lockout_enabled'] = False

                if 'policyAttributePasswordMinLength' in result.stdout:
                    match = re.search(r'<integer>(\d+)</integer>', result.stdout)
                    if match:
                        policy['min_length'] = int(match.group(1))

            # Controlla le impostazioni di sistema
            result = subprocess.run(
                ['defaults', 'read', '/Library/Preferences/com.apple.loginwindow', 'DisableFDEAutoLogin'],
                capture_output=True, text=True
            )

            if result.returncode == 0:
                policy['fde_autologin_disabled'] = '1' in result.stdout

        except Exception as e:
            self._logger.error(f"Error checking macOS password policy: {e}")
            policy['error'] = str(e)

        return policy

    def _analyze_policy_results(self, policy_checks: Dict[str, Any], os_type: str) -> tuple:
        """Analizza i risultati delle policy e genera issues/recommendations."""
        issues = []
        recommendations = []

        # Definisce i requisiti minimi per una policy sicura
        secure_requirements = {
            'min_length': 8,
            'max_age_days': 90,
            'min_age_days': 1,
            'history_length': 5,
            'lockout_threshold': 5,
            'complexity_enabled': True
        }

        # Controlla lunghezza minima
        min_length = policy_checks.get('min_length')
        if min_length is not None:
            if min_length < secure_requirements['min_length']:
                issues.append({
                    "severity": "high",
                    "description": f"Password minimum length too short: {min_length} (recommended: {secure_requirements['min_length']})",
                    "field": "min_length",
                    "current": min_length,
                    "recommended": secure_requirements['min_length']
                })
                recommendations.append(
                    f"Increase minimum password length to at least {secure_requirements['min_length']} characters")
        else:
            issues.append({
                "severity": "medium",
                "description": "Password minimum length not configured",
                "field": "min_length"
            })
            recommendations.append("Configure minimum password length")

        # Controlla età massima
        max_age = policy_checks.get('max_age_days')
        if max_age is None:
            issues.append({
                "severity": "medium",
                "description": "Password never expires",
                "field": "max_age_days"
            })
            recommendations.append("Configure password expiration policy")
        elif max_age > secure_requirements['max_age_days']:
            issues.append({
                "severity": "medium",
                "description": f"Password expiration too long: {max_age} days (recommended: {secure_requirements['max_age_days']})",
                "field": "max_age_days",
                "current": max_age,
                "recommended": secure_requirements['max_age_days']
            })
            recommendations.append(f"Reduce password expiration to {secure_requirements['max_age_days']} days or less")

        # Controlla complexity
        complexity = policy_checks.get('complexity_enabled')
        if complexity is False:
            issues.append({
                "severity": "critical",
                "description": "Password complexity requirements disabled",
                "field": "complexity"
            })
            recommendations.append("Enable password complexity requirements")
        elif complexity is None:
            issues.append({
                "severity": "medium",
                "description": "Password complexity requirements not configured",
                "field": "complexity"
            })
            recommendations.append("Configure password complexity requirements")

        # Controlla lockout threshold
        lockout_threshold = policy_checks.get('lockout_threshold')
        if lockout_threshold is None:
            issues.append({
                "severity": "high",
                "description": "Account lockout policy not configured",
                "field": "lockout_threshold"
            })
            recommendations.append("Configure account lockout policy")
        elif lockout_threshold > secure_requirements['lockout_threshold']:
            issues.append({
                "severity": "medium",
                "description": f"Account lockout threshold too high: {lockout_threshold} (recommended: {secure_requirements['lockout_threshold']})",
                "field": "lockout_threshold",
                "current": lockout_threshold,
                "recommended": secure_requirements['lockout_threshold']
            })
            recommendations.append(
                f"Reduce account lockout threshold to {secure_requirements['lockout_threshold']} attempts or less")

        # Controlli specifici per OS
        if os_type == "linux":
            # Verifica moduli PAM
            pam_complexity = policy_checks.get('pam_complexity', {})
            if not pam_complexity.get('enabled', False):
                issues.append({
                    "severity": "high",
                    "description": "PAM password complexity module not configured",
                    "field": "pam_complexity"
                })
                recommendations.append("Configure PAM password complexity module (pam_pwquality or pam_cracklib)")

        return issues, recommendations

    def _calculate_policy_score(self, policy_checks: Dict[str, Any]) -> float:
        """Calcola un punteggio per la policy delle password."""
        if 'error' in policy_checks:
            return 0.0

        score = 0.0
        max_score = 100.0

        # Punteggi per ogni criterio
        scoring = {
            'min_length': 20,  # 20 punti per lunghezza minima adeguata
            'max_age_days': 15,  # 15 punti per scadenza configurata
            'min_age_days': 10,  # 10 punti per età minima
            'complexity_enabled': 25,  # 25 punti per complessità
            'lockout_threshold': 20,  # 20 punti per lockout
            'history_length': 10  # 10 punti per storico
        }

        # Valuta lunghezza minima
        min_length = policy_checks.get('min_length')
        if min_length and min_length >= 8:
            score += scoring['min_length']
        elif min_length and min_length >= 6:
            score += scoring['min_length'] * 0.7  # Punteggio parziale

        # Valuta scadenza password
        max_age = policy_checks.get('max_age_days')
        if max_age and 30 <= max_age <= 90:
            score += scoring['max_age_days']
        elif max_age and max_age <= 180:
            score += scoring['max_age_days'] * 0.7

        # Valuta età minima
        min_age = policy_checks.get('min_age_days')
        if min_age and min_age >= 1:
            score += scoring['min_age_days']

        # Valuta complessità
        if policy_checks.get('complexity_enabled') is True:
            score += scoring['complexity_enabled']

        # Valuta lockout
        lockout = policy_checks.get('lockout_threshold')
        if lockout and 3 <= lockout <= 5:
            score += scoring['lockout_threshold']
        elif lockout and lockout <= 10:
            score += scoring['lockout_threshold'] * 0.7

        # Valuta storico
        history = policy_checks.get('history_length')
        if history and history >= 5:
            score += scoring['history_length']
        elif history and history >= 3:
            score += scoring['history_length'] * 0.7

        return min(score, max_score)