"""Exact public command-envelope selection shared by CLI and application."""
from jsonschema import Draft202012Validator, FormatChecker
from .errors import PhaseError


def validate_command_result(value, registry):
    resources = {
        '1.0': 'stage3-command-result.schema.json',
        '1.1': 'stage3-command-result-1.1.schema.json',
    }
    version = value.get('stage3_command_result_version') if isinstance(value, dict) else None
    if version not in resources:
        raise PhaseError('application.command_result_version_unsupported')
    schema = registry.schema_document('https://phase-tool.local/schemas/'+resources[version])
    Draft202012Validator(schema, format_checker=FormatChecker(),
                        registry=registry.schema_registry()).validate(value)
