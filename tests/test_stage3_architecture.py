from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "phase_tool"
CORE = PACKAGE / "core.py"


def _tree(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _call_name(call: ast.Call) -> str:
    function = call.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        parts = [function.attr]
        value = function.value
        while isinstance(value, ast.Attribute):
            parts.append(value.attr)
            value = value.value
        if isinstance(value, ast.Name):
            parts.append(value.id)
        return ".".join(reversed(parts))
    return ""


def _string_values(tree: ast.AST) -> set[str]:
    values: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            values.add(node.value)
        elif isinstance(node, ast.Subscript):
            slice_node = node.slice
            if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, str):
                values.add(slice_node.value)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            for arg in node.args[:1]:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    values.add(arg.value)
    return values


def test_core_has_no_contract_or_effect_specific_control_flow() -> None:
    source = CORE.read_text(encoding="utf-8")
    exact_forbidden = {
        "fixture_create.v1",
        "fixture_append.v1",
        "fixture_copy.v1",
        "exclusive_create",
        "append_record",
        "copy_blob",
    }
    assert exact_forbidden.isdisjoint(set(source.replace('"', " ").replace("'", " ").split()))
    tree = _tree(CORE)
    comparisons = [node for node in ast.walk(tree) if isinstance(node, ast.Compare)]
    branch_literals = {
        constant.value
        for comparison in comparisons
        for constant in ast.walk(comparison)
        if isinstance(constant, ast.Constant) and isinstance(constant.value, str)
    }
    assert exact_forbidden.isdisjoint(branch_literals)


def test_only_mechanism_boundary_owns_target_write_primitives() -> None:
    allowed_write_modules = {
        "mutation/expected_head_append.py",
        "mutation/exclusive_create.py",
        "mutation/content_addressed_copy.py",
        "mutation/archive_then_publish.py",
        "mutation/object_store_publish.py",
        "mutation/target_authority.py",
        "mutation/posix/authority.py",
        "evidence/__init__.py",
        "freeze/__init__.py",
    }
    forbidden_calls = {"os.open", "os.replace", "shutil.move", "write_bytes", "write_text", "unlink", "rename"}
    hits: list[tuple[str, int, str]] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        relative = path.relative_to(PACKAGE).as_posix()
        for node in ast.walk(_tree(path)):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            terminal = name.rsplit(".", 1)[-1]
            if name == "os.open" or terminal in forbidden_calls:
                if relative not in allowed_write_modules:
                    hits.append((relative, node.lineno, name))
            if terminal == "open" and relative not in allowed_write_modules:
                modes = [arg.value for arg in node.args[1:2] if isinstance(arg, ast.Constant) and isinstance(arg.value, str)]
                modes += [
                    keyword.value.value
                    for keyword in node.keywords
                    if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str)
                ]
                if any(set(mode) & set("wax+") for mode in modes):
                    hits.append((relative, node.lineno, f"open:{modes[0]}"))
    assert hits == []


def test_no_shell_exec_subprocess_or_dynamic_module_loading() -> None:
    forbidden_imports = {"subprocess", "runpy"}
    forbidden_calls = {"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile", "__import__", "builtins.__import__", "importlib.import_module", "subprocess.Popen", "subprocess.run", "os.system"}
    hits: list[tuple[str, int, str]] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        relative = path.relative_to(PACKAGE).as_posix()
        for node in ast.walk(_tree(path)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".", 1)[0] in forbidden_imports:
                        hits.append((relative, node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".", 1)[0] in forbidden_imports:
                hits.append((relative, node.lineno, node.module or ""))
            elif isinstance(node, ast.Call):
                name = _call_name(node)
                if name in forbidden_calls:
                    hits.append((relative, node.lineno, name))
    assert hits == []


def test_phase_core_exposes_one_top_level_lifecycle() -> None:
    tree = _tree(CORE)
    classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef) and node.name == "PhaseCore"]
    assert len(classes) == 1
    public_runs = [node for node in classes[0].body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run"]
    assert len(public_runs) == 1


def test_stage4_shared_core_broker_and_mechanisms_do_not_interpret_task_contracts() -> None:
    scanned = [
        PACKAGE / "core.py",
        PACKAGE / "planning" / "__init__.py",
        PACKAGE / "mutation" / "broker.py",
        PACKAGE / "mutation" / "expected_head_append.py",
        PACKAGE / "mutation" / "exclusive_create.py",
    ]
    forbidden = {
        "task_journal.v1",
        "task_open",
        "task_event",
        "task_close",
        "task_correction",
        "record_type",
        "verify_record",
        "original_instruction",
        "event_payload",
        "task_status",
        "task_id",
        "target_sequence",
        "target_event_hash",
    }
    hits: list[tuple[str, str]] = []
    for path in scanned:
        values = _string_values(_tree(path))
        for token in sorted(forbidden.intersection(values)):
            hits.append((path.relative_to(PACKAGE).as_posix(), token))
    assert hits == []


def test_stage4_cli_acceptance_keeps_subprocess_pythonpath_absent() -> None:
    script = (ROOT / "scripts" / "stage4_cli_acceptance.py").read_text(encoding="utf-8")
    assert 'env.pop("PYTHONPATH", None)' in script
    assert 'env["PYTHONPATH"]' not in script


def test_stage4_task_adapter_and_contract_data_are_declarative_only() -> None:
    adapter = PACKAGE / "contracts" / "task_journal_v1.py"
    write_calls = {"write_bytes", "write_text", "open", "os.open", "os.replace", "unlink", "rename"}
    hits: list[tuple[str, int, str]] = []
    for node in ast.walk(_tree(adapter)):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in write_calls or name.rsplit(".", 1)[-1] in write_calls:
                hits.append((adapter.relative_to(PACKAGE).as_posix(), node.lineno, name))
    assert hits == []

    forbidden_keys = {"command", "commands", "shell", "subprocess", "argv", "executable"}
    data_hits: list[tuple[str, str]] = []
    for path in sorted((PACKAGE / "data" / "contracts").glob("*.json")):
        source = path.read_text(encoding="utf-8")
        for key in forbidden_keys:
            if f'"{key}"' in source:
                data_hits.append((path.name, key))
    assert data_hits == []


def test_stage4_append_has_no_hidden_create_boundary() -> None:
    broker = _tree(PACKAGE / "mutation" / "broker.py")
    calls = [(node.lineno, _call_name(node)) for node in ast.walk(broker) if isinstance(node, ast.Call)]
    exclusive_lines = [line for line, name in calls if name == "execute_exclusive_create"]
    append_lines = [line for line, name in calls if name == "execute_append_record"]
    assert len(exclusive_lines) == 1
    assert len(append_lines) == 1

    planner_source = (PACKAGE / "planning" / "__init__.py").read_text(encoding="utf-8")
    assert '"exclusive_create" if expected_head is None' not in planner_source
