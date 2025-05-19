"""Controllo per verifiche di sicurezza di base."""

import os
import subprocess
from typing import Dict, Any, List
from ..base import BaseCheck, CheckResult, CheckStatus


class BasicSecurityCheck(BaseCheck):
    """Controllo per verifiche di sicurezza di base del sistema."""
    
    def __init__(self):
        super().__init__()
        self.id = "basic_security"
        self.name = "Basic Security Check"
        self.description = "Verifica impostazioni di sicurezza di base del sistema"
        self.category = "system"
        self.severity = "medium"
        self.supported_os = ["windows", "linux", "macos"]
    
    def execute(self, context: Dict[str, Any]) -> CheckResult:
        """
        Esegue le verifiche di sicurezza di base.
        
        Args:
            context: Contesto di esecuzione
            
        Returns:
            Risultato del controllo con verifiche di sicurezza
        """
        issues = []
        recommendations = []
        security_checks = {}
        os_type = context.get("os_type", "unknown")
        
        try:
            # Verifica permessi della directory corrente
            current_dir_check = self._check_current_directory_permissions()
            security_checks["directory_permissions"] = current_dir_check
            if not current_dir_check["secure"]:
                issues.append({
                    "severity": "medium",
                    "description": "Directory corrente potrebbe avere permessi non sicuri",
                    "details": current_dir_check
                })
                recommendations.append("Verificare i permessi della directory di esecuzione")
            
            # Controlli specifici per OS
            if os_type == "windows":
                windows_checks = self._check_windows_security()
                security_checks.update(windows_checks)
            elif os_type == "linux":
                linux_checks = self._check_linux_security()
                security_checks.update(linux_checks)
            elif os_type == "macos":
                macos_checks = self._check_macos_security()
                security_checks.update(macos_checks)
            
            # Verifica processi di sistema critici
            critical_processes_check = self._check_critical_processes(os_type)
            security_checks["critical_processes"] = critical_processes_check
            
            # Calcola il punteggio
            total_checks = len(security_checks)
            passed_checks = sum(1 for check in security_checks.values() 
                              if isinstance(check, dict) and check.get("status") == "pass")
            score = (passed_checks / total_checks * 100) if total_checks > 0 else 0
            
            # Determina lo status generale
            if issues:
                if any(issue["severity"] == "high" for issue in issues):
                    status = CheckStatus.FAIL
                else:
                    status = CheckStatus.WARNING
            else:
                status = CheckStatus.PASS
            
            return CheckResult(
                status=status,
                message=f"Basic security check completed with {len(issues)} issues found",
                details=security_checks,
                issues=issues,
                recommendations=recommendations,
                score=score
            )
            
        except Exception as e:
            return CheckResult(
                status=CheckStatus.ERROR,
                message=f"Error during basic security check: {str(e)}",
                details={"error": str(e)}
            )
    
    def _check_current_directory_permissions(self) -> Dict[str, Any]:
        """Verifica i permessi della directory corrente."""
        try:
            current_dir = os.getcwd()
            stat_info = os.stat(current_dir)
            
            # Controllo base - la directory non dovrebbe essere world-writable
            mode = stat_info.st_mode
            world_writable = bool(mode & 0o002)
            
            return {
                "path": current_dir,
                "mode": oct(mode),
                "world_writable": world_writable,
                "secure": not world_writable,
                "status": "fail" if world_writable else "pass"
            }
        except Exception as e:
            return {
                "error": str(e),
                "secure": False,
                "status": "error"
            }
    
    def _check_windows_security(self) -> Dict[str, Any]:
        """Controlli di sicurezza specifici per Windows."""
        checks = {}
        
        try:
            # Verifica se UAC è abilitato
            checks["uac_enabled"] = self._check_windows_uac()
            
            # Verifica Windows Defender
            checks["defender_status"] = self._check_windows_defender()
            
        except Exception as e:
            self._logger.error(f"Error in Windows security checks: {e}")
            checks["error"] = str(e)
        
        return checks
    
    def _check_linux_security(self) -> Dict[str, Any]:
        """Controlli di sicurezza specifici per Linux."""
        checks = {}
        
        try:
            # Verifica se root può loggarsi direttamente
            checks["root_login"] = self._check_linux_root_login()
            
            # Verifica se ci sono pacchetti aggiornabili
            checks["package_updates"] = self._check_linux_updates()
            
        except Exception as e:
            self._logger.error(f"Error in Linux security checks: {e}")
            checks["error"] = str(e)
        
        return checks
    
    def _check_macos_security(self) -> Dict[str, Any]:
        """Controlli di sicurezza specifici per macOS."""
        checks = {}
        
        try:
            # Verifica Gatekeeper
            checks["gatekeeper"] = self._check_macos_gatekeeper()
            
            # Verifica SIP (System Integrity Protection)
            checks["sip_status"] = self._check_macos_sip()
            
        except Exception as e:
            self._logger.error(f"Error in macOS security checks: {e}")
            checks["error"] = str(e)
        
        return checks
    
    def _check_critical_processes(self, os_type: str) -> Dict[str, Any]:
        """Verifica che i processi critici siano in esecuzione."""
        try:
            import psutil
            
            # Processi critici per OS
            critical_processes = {
                "windows": ["winlogon.exe", "csrss.exe", "lsass.exe"],
                "linux": ["init", "systemd", "kthreadd"],
                "macos": ["launchd", "kernel_task"]
            }
            
            expected_processes = critical_processes.get(os_type, [])
            running_processes = [p.name() for p in psutil.process_iter(['name'])]
            
            found_processes = [p for p in expected_processes if p in running_processes]
            missing_processes = [p for p in expected_processes if p not in running_processes]
            
            return {
                "expected": expected_processes,
                "found": found_processes,
                "missing": missing_processes,
                "status": "pass" if not missing_processes else "warning"
            }
            
        except ImportError:
            return {
                "error": "psutil not available",
                "status": "skipped"
            }
        except Exception as e:
            return {
                "error": str(e),
                "status": "error"
            }
    
    def _check_windows_uac(self) -> Dict[str, Any]:
        """Verifica se UAC è abilitato su Windows."""
        try:
            result = subprocess.run(
                ['reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 
                 '/v', 'EnableLUA'],
                capture_output=True, text=True
            )
            
            uac_enabled = "0x1" in result.stdout
            
            return {
                "enabled": uac_enabled,
                "status": "pass" if uac_enabled else "fail"
            }
        except Exception as e:
            return {
                "error": str(e),
                "status": "error"
            }
    
    def _check_windows_defender(self) -> Dict[str, Any]:
        """Verifica lo stato di Windows Defender."""
        try:
            result = subprocess.run(
                ['powershell', '-Command', 'Get-MpComputerStatus | Select-Object AntivirusEnabled'],
                capture_output=True, text=True
            )
            
            defender_enabled = "True" in result.stdout
            
            return {
                "enabled": defender_enabled,
                "status": "pass" if defender_enabled else "warning"
            }
        except Exception as e:
            return {
                "error": str(e),
                "status": "error"
            }
    
    def _check_linux_root_login(self) -> Dict[str, Any]:
        """Verifica se il login root è disabilitato."""
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    if line.startswith('root:'):
                        parts = line.split(':')
                        shell = parts[6].strip()
                        root_login_disabled = shell in ['/bin/false', '/usr/sbin/nologin']
                        
                        return {
                            "root_shell": shell,
                            "login_disabled": root_login_disabled,
                            "status": "pass" if root_login_disabled else "warning"
                        }
        except Exception as e:
            return {
                "error": str(e),
                "status": "error"
            }
        
        return {"status": "error", "error": "Could not check root login status"}
    
    def _check_linux_updates(self) -> Dict[str, Any]:
        """Verifica la disponibilità di aggiornamenti."""
        try:
            # Prova apt-get (Debian/Ubuntu)
            result = subprocess.run(
                ['apt', 'list', '--upgradable'],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                upgradable_count = len([l for l in lines if '/' in l and 'upgradable' in l])
                
                return {
                    "package_manager": "apt",
                    "upgradable_packages": upgradable_count,
                    "status": "warning" if upgradable_count > 0 else "pass"
                }
            
        except FileNotFoundError:
            pass
        
        try:
            # Prova yum/dnf (Red Hat/CentOS/Fedora)
            result = subprocess.run(
                ['dnf', 'check-update'],
                capture_output=True, text=True
            )
            
            # dnf check-update restituisce 100 se ci sono aggiornamenti
            if result.returncode == 100:
                updates_available = True
            elif result.returncode == 0:
                updates_available = False
            else:
                updates_available = None
            
            return {
                "package_manager": "dnf",
                "updates_available": updates_available,
                "status": "warning" if updates_available else "pass"
            }
            
        except FileNotFoundError:
            pass
        
        return {
            "error": "No supported package manager found",
            "status": "skipped"
        }
    
    def _check_macos_gatekeeper(self) -> Dict[str, Any]:
        """Verifica lo stato di Gatekeeper su macOS."""
        try:
            result = subprocess.run(
                ['spctl', '--status'],
                capture_output=True, text=True
            )
            
            gatekeeper_enabled = "assessments enabled" in result.stdout
            
            return {
                "enabled": gatekeeper_enabled,
                "status": "pass" if gatekeeper_enabled else "warning"
            }
        except Exception as e:
            return {
                "error": str(e),
                "status": "error"
            }
    
    def _check_macos_sip(self) -> Dict[str, Any]:
        """Verifica lo stato di System Integrity Protection su macOS."""
        try:
            result = subprocess.run(
                ['csrutil', 'status'],
                capture_output=True, text=True
            )
            
            sip_enabled = "enabled" in result.stdout
            
            return {
                "enabled": sip_enabled,
                "status": "pass" if sip_enabled else "warning"
            }
        except Exception as e:
            return {
                "error": str(e),
                "status": "error"
            }