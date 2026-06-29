"""
Custom recognizer example: extend detection with YAML-defined patterns.
"""

import tempfile
from pathlib import Path

import yaml

from pii_redactor import PrivacyRedactor
from pii_redactor.config import Settings, load_yaml_config
from pii_redactor.detection.detector import PIIDetector
from pii_redactor.redaction.redactor import PIIRedactor

# ── Inline custom patterns (Python dict) ──────────────────────────────────────

custom_patterns = [
    {
        "name": "CUSTOMER_ID",
        "pattern": r"\bCUS-[0-9]{6}\b",
        "confidence": 0.95,
    },
    {
        "name": "PROJECT_CODE",
        "pattern": r"\bPRJ-[A-Z]{3}-[0-9]{4}\b",
        "confidence": 0.90,
    },
]

settings = Settings(enable_presidio=False, enable_spacy=False)
redactor = PrivacyRedactor(config=settings, custom_patterns=custom_patterns)

text = "Customer CUS-123456 is working on project PRJ-ABC-1234."
result = redactor.redact(text)

print("Original:", text)
print("Redacted:", result.redacted_text)
print()
for ph, original in result.mapping.items():
    print(f"  {ph} → {original!r}")

print()

# ── From YAML config file ──────────────────────────────────────────────────────

yaml_config = {
    "custom_recognizers": [
        {
            "name": "EMPLOYEE_ID",
            "pattern": r"\bEMP-[0-9]{5}\b",
            "confidence": 0.92,
        },
        {
            "name": "INVOICE_NUMBER",
            "pattern": r"\bINV-[0-9]{8}\b",
            "confidence": 0.95,
        },
    ]
}

with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
    yaml.dump(yaml_config, f)
    config_path = f.name

cfg = load_yaml_config(config_path)
redactor2 = PrivacyRedactor(config=settings, custom_patterns=cfg["custom_recognizers"])

text2 = "Employee EMP-12345 submitted invoice INV-20240001."
result2 = redactor2.redact(text2)

print("Original:", text2)
print("Redacted:", result2.redacted_text)
