import logging
logging.basicConfig(level=logging.DEBUG)

import agid_assessment_methodology
from agid_assessment_methodology.checks import registry

print("Checks in registry:", len(registry._checks))
for check_id, check in registry._checks.items():
    print(f"Check: {check_id}")
    print(f"  Name: {check.name}")
    print(f"  Category: {check.category}")
    print(f"  Severity: {check.severity}")
    print(f"  Supported OS: {check.supported_os}")
    print()