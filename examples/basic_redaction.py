"""
Basic redaction example: detect and redact PII from text using the Python library.
"""

from pii_redactor import PrivacyRedactor
from pii_redactor.config import Settings

# ── Example 1: Simple redaction (regex-only, no ML deps) ──────────────────────

settings = Settings(enable_presidio=False, enable_spacy=False)
redactor = PrivacyRedactor(config=settings)

text = "Contact John Smith at john.smith@example.com or call +1-555-123-4567."
result = redactor.redact(text)

print("Original :", text)
print("Redacted :", result.redacted_text)
print("Entities :", len(result.entities))
print()

# ── Example 2: Store mapping and restore later ────────────────────────────────

result_with_id = redactor.redact(text, store_mapping=True)

print("Mapping ID:", result_with_id.mapping_id)
print("Redacted  :", result_with_id.redacted_text)

# Simulate sending redacted text to an LLM and getting a response back
llm_response = f"{result_with_id.redacted_text} — we'll follow up shortly."

# Restore the original values in the LLM response
restored = redactor.restore(llm_response, result_with_id.mapping)
print("Restored  :", restored.restored_text)
print("Replaced  :", restored.placeholders_replaced, "placeholders")
print()

# ── Example 3: Detection-only (no redaction) ──────────────────────────────────

entities = redactor.detect(text)
for e in entities:
    print(f"  [{e.entity_type}] {text[e.start:e.end]!r}  (confidence={e.confidence:.2f})")
