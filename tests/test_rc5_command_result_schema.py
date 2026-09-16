"""R1: public 1.1 schemas require already-verified original identifiers."""
import copy
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from phase_tool.application import PhaseApplication
from .test_rc01_correction import crash_prepared_bundle

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='qualified Linux mutation')
ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOTS = [ROOT / 'schemas', ROOT / 'src/phase_tool/data/schemas']
IDENTIFIERS = ['run_id', 'intent_digest', 'effect_plan_digest']


@pytest.fixture(scope='module', params=['recovered_verified', 'indeterminate'])
def inspected_result(request, tmp_path_factory):
    root = tmp_path_factory.mktemp('rc5-schema')
    args, run, query = crash_prepared_bundle(root, version='2.0')
    app = PhaseApplication()
    if request.param == 'recovered_verified':
        assert app.recover_publication(**query, mode='commit_prepared').payload['success']
    result = app.inspect(evidence_root=args['evidence_root'], run_id=args['run_id'],
        root_bindings={'phase_result_root': args['target_root']}).payload
    assert result['stage3_command_result_version'] == '1.1'
    assert result['inspection_status'] == request.param
    assert all(result[key] is not None for key in IDENTIFIERS)
    assert not (run / 'receipt.json').exists()
    return result


def schema_validator(root, version='1.1'):
    name = 'stage3-command-result-1.1' if version == '1.1' else 'stage3-command-result'
    schema = json.loads((root / (name + '.schema.json')).read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=PhaseApplication().registry.schema_registry())


@pytest.mark.parametrize('schema_root', SCHEMA_ROOTS, ids=['public', 'packaged'])
def test_known_identifiers_and_unknown_original_facts_are_valid(inspected_result, schema_root):
    # Real runtime envelopes, not a fabricated success fixture.
    for key in ('receipt_digest', 'terminal_status', 'execution_disposition', 'mutation_attempted'):
        assert inspected_result[key] is None
    schema_validator(schema_root).validate(inspected_result)


@pytest.mark.parametrize('schema_root', SCHEMA_ROOTS, ids=['public', 'packaged'])
@pytest.mark.parametrize('key', IDENTIFIERS)
@pytest.mark.parametrize('invalid', ['null', 'missing'])
def test_schema_rejects_unknown_verified_identifiers(inspected_result, schema_root, key, invalid):
    validator = schema_validator(schema_root)
    validator.validate(inspected_result)
    broken = copy.deepcopy(inspected_result)
    if invalid == 'null':
        broken[key] = None
    else:
        del broken[key]
    with pytest.raises(ValidationError) as caught:
        validator.validate(broken)
    # Ensure failure is caused by this identifier, not a broken nested recovery record.
    if invalid == 'null':
        assert list(caught.value.path) == [key]
        assert caught.value.validator == 'type'
    else:
        assert caught.value.validator == 'required'
        assert key in caught.value.message


@pytest.mark.parametrize('schema_root', SCHEMA_ROOTS, ids=['public', 'packaged'])
def test_early_inspect_failure_keeps_historical_10_null_identifiers(tmp_path, schema_root):
    result = PhaseApplication().inspect(evidence_root=tmp_path, run_id='unavailable',
        root_bindings={}).payload
    assert result['stage3_command_result_version'] == '1.0'
    assert not result['success'] and result['exit_code'] == 10
    assert all(result[key] is None for key in IDENTIFIERS)
    schema_validator(schema_root, version='1.0').validate(result)
