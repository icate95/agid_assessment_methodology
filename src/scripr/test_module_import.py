import importlib

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
        print(f"Successfully imported: {module_name}")
    except ImportError as e:
        print(f"Failed to import {module_name}")
        print(f"Error: {e}")