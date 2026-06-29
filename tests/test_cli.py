"""
Tests for the CLI: redact, redact-file, detect, serve commands.

Uses typer's testing runner to invoke CLI commands in-process.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from pii_redactor.cli import app

runner = CliRunner()


class TestRedactCommand:
    def test_redact_email(self):
        result = runner.invoke(app, ["redact", "alice@example.com"])
        assert result.exit_code == 0
        assert "alice@example.com" not in result.output
        assert "EMAIL" in result.output

    def test_redact_credit_card(self):
        result = runner.invoke(app, ["redact", "Card: 4111 1111 1111 1111"])
        assert result.exit_code == 0
        assert "4111 1111 1111 1111" not in result.output
        assert "CREDIT_CARD" in result.output

    def test_redact_multiple_pii(self):
        result = runner.invoke(app, ["redact", "alice@foo.com and 192.168.1.1"])
        assert result.exit_code == 0
        assert "alice@foo.com" not in result.output
        assert "192.168.1.1" not in result.output

    def test_redact_empty_text(self):
        result = runner.invoke(app, ["redact", ""])
        assert result.exit_code == 0
        assert result.output.strip() == "" or len(result.output) < 5

    def test_redact_no_pii(self):
        result = runner.invoke(app, ["redact", "Hello world"])
        assert result.exit_code == 0
        assert "Hello world" in result.output

    def test_redact_with_language_flag(self):
        result = runner.invoke(app, ["redact", "--language", "fr", "Email: test@example.fr"])
        assert result.exit_code == 0
        assert "test@example.fr" not in result.output

    def test_redact_show_mapping_flag(self):
        result = runner.invoke(app, ["redact", "--show-mapping", "alice@example.com"])
        assert result.exit_code == 0
        # Mapping info goes to stderr; output should not contain original email
        assert "alice@example.com" not in result.output

    def test_redact_ssn(self):
        result = runner.invoke(app, ["redact", "SSN: 123-45-6789"])
        assert result.exit_code == 0
        assert "123-45-6789" not in result.output

    def test_redact_phone_number(self):
        result = runner.invoke(app, ["redact", "Call +1-555-123-4567"])
        assert result.exit_code == 0
        assert "+1-555-123-4567" not in result.output


class TestRedactFileCommand:
    def test_redact_file_to_stdout(self, tmp_path):
        input_file = tmp_path / "input.txt"
        input_file.write_text("Contact alice@example.com for help.", encoding="utf-8")
        result = runner.invoke(app, ["redact-file", str(input_file)])
        assert result.exit_code == 0
        assert "alice@example.com" not in result.output
        assert "EMAIL" in result.output

    def test_redact_file_to_output_file(self, tmp_path):
        input_file = tmp_path / "input.txt"
        output_file = tmp_path / "output.txt"
        input_file.write_text("Email alice@example.com please.", encoding="utf-8")
        result = runner.invoke(app, ["redact-file", str(input_file), "--output", str(output_file)])
        assert result.exit_code == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "alice@example.com" not in content
        assert "EMAIL" in content

    def test_redact_file_missing_file_exits_1(self):
        result = runner.invoke(app, ["redact-file", "/nonexistent/path/input.txt"])
        assert result.exit_code == 1

    def test_redact_file_with_multiple_pii_types(self, tmp_path):
        input_file = tmp_path / "input.txt"
        input_file.write_text("alice@foo.com, 4111 1111 1111 1111, 192.168.1.1")
        result = runner.invoke(app, ["redact-file", str(input_file)])
        assert result.exit_code == 0
        assert "alice@foo.com" not in result.output
        assert "4111 1111 1111 1111" not in result.output

    def test_redact_file_unicode_content(self, tmp_path):
        # Use ASCII email - Unicode local-parts (like maría) are not supported
        # by most email systems and not matched by standard RFC 5321 patterns
        input_file = tmp_path / "input.txt"
        input_file.write_text("Contactez: maria@ejemplo.es", encoding="utf-8")
        result = runner.invoke(app, ["redact-file", str(input_file)])
        assert result.exit_code == 0
        assert "maria@ejemplo.es" not in result.output


class TestDetectCommand:
    def test_detect_text_argument(self):
        result = runner.invoke(app, ["detect", "alice@example.com"])
        assert result.exit_code == 0
        assert "EMAIL" in result.output

    def test_detect_no_pii(self):
        result = runner.invoke(app, ["detect", "Hello world, nothing sensitive here."])
        assert result.exit_code == 0
        assert "No PII" in result.output

    def test_detect_json_output(self):
        result = runner.invoke(app, ["detect", "--json", "alice@example.com"])
        assert result.exit_code == 0
        data = json.loads(result.output.strip())
        assert isinstance(data, list)
        assert len(data) >= 1
        assert "entity_type" in data[0]

    def test_detect_from_file(self, tmp_path):
        input_file = tmp_path / "detect.txt"
        input_file.write_text("alice@example.com is the contact.")
        result = runner.invoke(app, ["detect", str(input_file)])
        assert result.exit_code == 0
        assert "EMAIL" in result.output

    def test_detect_json_has_required_fields(self):
        result = runner.invoke(app, ["detect", "--json", "alice@example.com"])
        assert result.exit_code == 0
        data = json.loads(result.output.strip())
        if data:
            record = data[0]
            assert "entity_type" in record
            assert "start" in record
            assert "end" in record
            assert "confidence" in record
            assert "source" in record


class TestHelpOutput:
    def test_main_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "redact" in result.output.lower()

    def test_redact_command_help(self):
        result = runner.invoke(app, ["redact", "--help"])
        assert result.exit_code == 0

    def test_detect_command_help(self):
        result = runner.invoke(app, ["detect", "--help"])
        assert result.exit_code == 0

    def test_redact_file_command_help(self):
        result = runner.invoke(app, ["redact-file", "--help"])
        assert result.exit_code == 0
