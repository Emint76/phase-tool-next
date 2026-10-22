from __future__ import annotations

import ast
from pathlib import Path

import pytest

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


def _windows_control_pipe_write(relative: str, tree: ast.AST, node: ast.Call) -> bool:
    """Inventory one reviewed transport call, never a whole module or generic fd."""
    if relative != "mutation/ntfs/windows_pipe.py" or ast.unparse(node) != "os.write(fd, data[offset:offset + 65536])":
        return False
    owners = [function for cls in ast.walk(tree) if isinstance(cls, ast.ClassDef)
              and cls.name == "WindowsPipeFrames" for function in cls.body
              if isinstance(function, ast.FunctionDef) and function.name == "_write"
              and node in ast.walk(function)]
    if len(owners) != 1 or [arg.arg for arg in owners[0].args.args] != ["self", "data", "deadline_ns", "progress"]:
        return False
    # No nested lexical scope or second write can inherit this one call site's
    # inventory exception. This is not a general static data-flow verifier.
    if any(isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda))
           for item in ast.walk(owners[0]) if item is not owners[0]):
        return False
    writes = [item for item in ast.walk(owners[0]) if isinstance(item, ast.Call) and _call_name(item) == "os.write"]
    if len(writes) != 1:
        return False
    stores = [item for item in ast.walk(owners[0]) if isinstance(item, ast.Name)
              and item.id == "fd" and isinstance(item.ctx, ast.Store)]
    assignments = [item for item in ast.walk(owners[0]) if isinstance(item, ast.Assign)
                   and len(item.targets) == 1 and isinstance(item.targets[0], ast.Name)
                   and item.targets[0].id == "fd"]
    return (len(stores) == len(assignments) == 1
            and ast.unparse(assignments[0].value) == "self._identity(1)")


def _readonly_process_class_import(relative: str, tree: ast.AST, node: ast.Import) -> bool:
    """Inventory four reviewed class-identity references; never permit a spawn.

    This is an architecture inventory for trusted source, not a Python security
    analyser. No module-wide exemption or executable subprocess call is granted.
    """
    if relative != "mutation/ntfs/process_witness.py" or node not in tree.body:
        return False
    if len(node.names) != 1 or node.names[0].name != "subprocess" or node.names[0].asname is not None:
        return False
    imports = [item for item in ast.walk(tree) if isinstance(item, (ast.Import, ast.ImportFrom))
               and (any(alias.name.split(".", 1)[0] == "subprocess" or alias.asname == "subprocess"
                        for alias in item.names)
                    or isinstance(item, ast.ImportFrom) and (item.module or "").split(".", 1)[0] == "subprocess")]
    if imports != [node]:
        return False
    owners = [item for item in ast.walk(tree) if isinstance(item, ast.ClassDef)
              and item.name == "WindowsProcessWitness"]
    if len(owners) != 1 or owners[0] not in tree.body:
        return False
    constructors = [item for item in owners[0].body if isinstance(item, ast.FunctionDef)
                    and item.name == "__init__"]
    if len(constructors) != 1:
        return False
    constructor = constructors[0]
    if any(isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda))
           for item in ast.walk(constructor) if item is not constructor):
        return False
    # Name Store is not every Python binding form: also inventory arguments,
    # definition names, imports, exception aliases, scope and pattern bindings.
    for item in ast.walk(tree):
        if isinstance(item, ast.arg) and item.arg == "subprocess":
            return False
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and item.name == "subprocess":
            return False
        if isinstance(item, ast.ExceptHandler) and item.name == "subprocess":
            return False
        if isinstance(item, (ast.Global, ast.Nonlocal)) and "subprocess" in item.names:
            return False
        if isinstance(item, (ast.MatchAs, ast.MatchStar)) and item.name == "subprocess":
            return False
        if isinstance(item, ast.MatchMapping) and item.rest == "subprocess":
            return False
    expected = {
        "SpawnProcess | subprocess.Popen",
        "type(process) in (SpawnProcess, subprocess.Popen)",
        "type(process) is subprocess.Popen",
        "type(handle) is subprocess.Handle",
    }
    expressions = [item for item in ast.walk(constructor)
                   if isinstance(item, (ast.BinOp, ast.Compare)) and ast.unparse(item) in expected]
    if len(expressions) != 4 or {ast.unparse(item) for item in expressions} != expected:
        return False
    process_args = [arg for arg in constructor.args.args if arg.arg == "process"]
    if len(process_args) != 1 or process_args[0].annotation not in expressions:
        return False
    assignments = [item for item in ast.walk(constructor) if isinstance(item, ast.Assign)
                   and len(item.targets) == 1 and ast.unparse(item.targets[0]) == "self._popen"
                   and ast.unparse(item.value) == "type(process) is subprocess.Popen"]
    if len(assignments) != 1:
        return False
    permitted = {id(item) for expression in expressions for item in ast.walk(expression)
                 if isinstance(item, ast.Name) and item.id == "subprocess"}
    references = [item for item in ast.walk(tree) if isinstance(item, ast.Name) and item.id == "subprocess"]
    return (len(references) == len(permitted) == 4
            and all(isinstance(item.ctx, ast.Load) and id(item) in permitted for item in references))


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
        # Exact added IO boundaries for file_create.v2; no generic module glob.
        "mutation/stream_create.py",
        "mutation/bundle_create.py",
        "streaming.py",
        "mutation/content_addressed_copy.py",
        "mutation/archive_then_publish.py",
        "mutation/object_store_publish.py",
        "mutation/target_authority.py",
        "mutation/posix/authority.py",
        # Reviewed native physical IO boundary; no directory or module glob.
        "mutation/ntfs/mutating.py",
        "evidence/__init__.py",
        "freeze/__init__.py",
    }
    forbidden_calls = {"os.open", "os.write", "os.link", "os.replace", "shutil.move", "write_bytes", "write_text", "unlink", "rename"}
    native_calls_by_module = {
        "mutation/ntfs/native.py": {"NtSetInformationFile", "NtFlushBuffersFileEx"},
        "mutation/ntfs/mutating.py": {
            "NtCreateFile", "NtSetInformationFile", "WriteFile", "SetEndOfFile", "NtFlushBuffersFileEx",
        },
    }
    native_write_calls = set().union(*native_calls_by_module.values())
    hits: list[tuple[str, int, str]] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        relative = path.relative_to(PACKAGE).as_posix()
        tree = _tree(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            terminal = name.rsplit(".", 1)[-1]
            if terminal in native_write_calls and terminal not in native_calls_by_module.get(relative, set()):
                hits.append((relative, node.lineno, name))
            if name in forbidden_calls or terminal in forbidden_calls:
                # This exact transport call writes only borrowed stdout after
                # the channel's identity/access/nonblocking check. It is not a
                # target-filesystem writer; all other calls stay inventoried.
                stdout_channel_write = (
                    relative == "mutation/ntfs/channel.py" and name == "os.write"
                    and len(node.args) == 2 and not node.keywords
                    and isinstance(node.args[0], ast.Call)
                    and _call_name(node.args[0]) == "self._identity"
                    and len(node.args[0].args) == 1 and not node.args[0].keywords
                    and isinstance(node.args[0].args[0], ast.Constant)
                    and type(node.args[0].args[0].value) is int
                    and node.args[0].args[0].value == 1
                )
                windows_pipe_write = _windows_control_pipe_write(relative, tree, node)
                if relative not in allowed_write_modules and not stdout_channel_write and not windows_pipe_write:
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


@pytest.mark.parametrize("relative,binding,extra,argument,owner,expected", [
    ("mutation/ntfs/windows_pipe.py", "self._identity(1)", "", "fd", "WindowsPipeFrames", True),
    ("mutation/ntfs/other.py", "self._identity(1)", "", "fd", "WindowsPipeFrames", False),
    ("mutation/ntfs/windows_pipe.py", "caller_fd", "", "fd", "WindowsPipeFrames", False),
    ("mutation/ntfs/windows_pipe.py", "self._identity(1)", "fd = 42", "fd", "WindowsPipeFrames", False),
    ("mutation/ntfs/windows_pipe.py", "self._identity(1)", "", "caller_fd", "WindowsPipeFrames", False),
    ("mutation/ntfs/windows_pipe.py", "self._identity(1)", "", "fd", "Other", False),
])
def test_windows_pipe_inventory_rejects_generic_write(relative, binding, extra, argument, owner, expected):
    # Parse synthetic source only: these strings never execute or acquire a fd.
    tree = ast.parse(f"class {owner}:\n def _write(self, data, deadline_ns, progress):\n"
                     f"  fd = {binding}\n  {extra}\n  os.write({argument}, data[offset:offset + 65536])\n")
    node = next(item for item in ast.walk(tree) if isinstance(item, ast.Call) and _call_name(item) == "os.write")
    assert _windows_control_pipe_write(relative, tree, node) is expected


@pytest.mark.parametrize("body", [
    "  def hidden(fd):\n   os.write(fd, data[offset:offset + 65536])\n",
    "  os.write(fd, data[offset:offset + 65536])\n  os.write(fd, data[offset:offset + 65536])\n",
])
def test_windows_pipe_inventory_rejects_nested_or_duplicate_write(body):
    tree = ast.parse("class WindowsPipeFrames:\n def _write(self, data, deadline_ns, progress):\n"
                     "  fd = self._identity(1)\n" + body)
    writes = [item for item in ast.walk(tree) if isinstance(item, ast.Call) and _call_name(item) == "os.write"]
    assert writes and all(not _windows_control_pipe_write("mutation/ntfs/windows_pipe.py", tree, node) for node in writes)


def test_no_shell_exec_subprocess_or_dynamic_module_loading() -> None:
    forbidden_imports = {"subprocess", "runpy"}
    forbidden_calls = {"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile", "__import__", "builtins.__import__", "importlib.import_module", "subprocess.Popen", "subprocess.run", "os.system"}
    hits: list[tuple[str, int, str]] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        relative = path.relative_to(PACKAGE).as_posix()
        tree = _tree(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".", 1)[0] in forbidden_imports and not _readonly_process_class_import(relative, tree, node):
                        hits.append((relative, node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".", 1)[0] in forbidden_imports:
                hits.append((relative, node.lineno, node.module or ""))
            elif isinstance(node, ast.Call):
                name = _call_name(node)
                if name in forbidden_calls:
                    hits.append((relative, node.lineno, name))
    assert hits == []


_CLASS_IDENTITY_SOURCE = """import subprocess
class WindowsProcessWitness:
 def __init__(self, process: SpawnProcess | subprocess.Popen):
  require(type(process) in (SpawnProcess, subprocess.Popen))
  self._popen = type(process) is subprocess.Popen
  require(type(handle) is subprocess.Handle)
"""


@pytest.mark.parametrize("relative,source,expected", [
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE, True),
    ("mutation/ntfs/other.py", _CLASS_IDENTITY_SOURCE, False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE.replace("WindowsProcessWitness", "Other"), False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE.replace("__init__", "other"), False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE.replace("import subprocess", "import subprocess as subprocess"), False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE.replace("import subprocess", "from subprocess import Popen"), False),
    ("mutation/ntfs/process_witness.py", "import subprocess\n" + _CLASS_IDENTITY_SOURCE, False),
    ("mutation/ntfs/process_witness.py", "import os as subprocess\n" + _CLASS_IDENTITY_SOURCE, False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "from os import path as subprocess\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "subprocess.Popen([])\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "subprocess.run([])\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "subprocess.Handle(1)\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "alias = subprocess.Popen\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "getattr(subprocess, 'Popen')\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "subprocess = other\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "def other(subprocess): pass\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "def subprocess(): pass\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "class subprocess: pass\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "try: pass\nexcept Exception as subprocess: pass\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "global subprocess\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "match value:\n case subprocess: pass\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "match value:\n case [*subprocess]: pass\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "match value:\n case {**subprocess}: pass\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "[x for subprocess in values]\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "  def hidden(): return subprocess.Popen\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE + "  def hidden(): pass\n", False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE.replace("SpawnProcess | subprocess.Popen", "SpawnProcess"), False),
    ("mutation/ntfs/process_witness.py", _CLASS_IDENTITY_SOURCE.replace("  self._popen =", "  other ="), False),
])
def test_readonly_process_import_inventory(relative, source, expected):
    # Parse synthetic source only; never import subprocess or execute these calls.
    tree = ast.parse(source)
    node = next(item for item in ast.walk(tree) if isinstance(item, ast.Import)
                and any(alias.name == "subprocess" for alias in item.names)) if "import subprocess" in source else ast.Import(names=[])
    assert _readonly_process_class_import(relative, tree, node) is expected


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
