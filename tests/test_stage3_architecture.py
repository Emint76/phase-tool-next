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



def _native_terminal_stdout_write(relative: str,tree: ast.AST,node: ast.Call) -> bool:
    """One fixed owned stdio delivery site, never a path/generic fd writer."""
    if relative!='mutation/ntfs/entrypoint.py' or ast.unparse(node)!='os.write(1, wire[offset:offset + 65536])':return False
    owners=[f for f in tree.body if isinstance(f,ast.FunctionDef)
        and f.name=='_deliver_linux_frame' and node in ast.walk(f)]
    if len(owners)!=1:return False
    function=owners[0]
    if [arg.arg for arg in function.args.args]!=['value','identities']:return False
    if function.args.posonlyargs or function.args.defaults or function.args.vararg or function.args.kwarg:return False
    keyword_names=[arg.arg for arg in function.args.kwonlyargs]
    if keyword_names not in ([],['_deadline']):return False
    if keyword_names and (len(function.args.kw_defaults)!=1
        or not isinstance(function.args.kw_defaults[0],ast.Constant)
        or function.args.kw_defaults[0].value is not None):return False
    if any(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda))
        for n in ast.walk(function) if n is not function):return False
    writes=[n for n in ast.walk(function) if isinstance(n,ast.Call) and _call_name(n)=='os.write']
    if writes!=[node]:return False
    # Literal 1 cannot become a caller-selected descriptor. Code review and
    # actual pipe fault tests separately establish ownership/identity checks.
    return type(node.args[0].value) is int and node.args[0].value==1


def _native_terminal_pipe_write(relative: str,tree: ast.AST,node: ast.Call) -> bool:
    """One terminal-only owned-pipe site; no module or caller-fd exemption.

    This inventories reviewed source structure, not arbitrary Python data flow
    or Windows quiescence. Runtime pipe/frame fault models are separate.
    """
    if relative!='mutation/ntfs/bundle_recovery_terminal.py':return False
    if ast.unparse(node)!="os.write(descriptor(1), framed[progress['wire_bytes']:progress['wire_bytes'] + 65536])":return False
    owners=[f for f in tree.body if isinstance(f,ast.FunctionDef)
        and f.name=='_frame_io' and node in ast.walk(f)]
    if len(owners)!=1:return False
    function=owners[0];args=function.args
    if ([a.arg for a in args.args]!=['owner'] or args.posonlyargs or args.defaults
            or args.vararg or args.kwarg or [a.arg for a in args.kwonlyargs]!=
            ['sending','raw','deadline_ns','maximum_bytes','windows']
            or any(value is not None for value in args.kw_defaults)):return False
    nested=[n for n in ast.walk(function) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda))
        and n is not function]
    if (len(nested)!=3 or any(not isinstance(n,ast.FunctionDef)for n in nested)
            or {n.name for n in nested}!={'descriptor','remaining','read_exact'}):return False
    descriptor=next(n for n in nested if n.name=='descriptor')
    expected=ast.parse('''def descriptor(side):
    _require(owner._owner == (os.getpid(), threading.get_ident()) and not owner._sealed,
             'ntfs.terminal_owner_changed')
    if windows:
        value = owner._pipe(side)
        _require(value == owner._identities[side], 'ntfs.pipe_identity_changed')
        return value[0]
    _require(owner._pipe(side) == owner._pipes[side], 'ntfs.channel_descriptor_changed')
    return side
''').body[0]
    if ast.dump(descriptor)!=ast.dump(expected):return False
    if any(isinstance(n,ast.Name) and n.id=='descriptor' and not isinstance(n.ctx,ast.Load)
        for n in ast.walk(function)):return False
    if any(isinstance(n,ast.arg) and n.arg=='descriptor' for n in ast.walk(function)):return False
    writes=[n for n in ast.walk(function) if isinstance(n,ast.Call) and _call_name(n)=='os.write']
    if len(writes)!=1 or writes[0] is not node or any(node in ast.walk(n)for n in nested):return False
    parents={id(child):n for n in ast.walk(tree)for child in ast.iter_child_nodes(n)}
    references=[n for n in ast.walk(tree)if isinstance(n,ast.Name)and n.id=='_frame_io']
    calls=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and _call_name(n)=='_frame_io']
    if len(calls)!=2 or len(references)!=2 or any(parents.get(id(n)) not in calls for n in references):return False
    expected_calls={
        "_frame_io(pipe, sending=sending, raw=raw, deadline_ns=deadline_ns, maximum_bytes=maximum_bytes, windows=True)":
            ('windows_terminal',"_require(type(pipe) is WindowsPipeFrames, 'ntfs.windows_worker_pipe_required')"),
        "_frame_io(channel, sending=False, raw=None, deadline_ns=deadline_ns, maximum_bytes=maximum_bytes, windows=False)":
            ('linux_terminal',"_require(type(channel) is LinuxNativeBundleRecoveryChannel and channel._gate.locked(), 'ntfs.closed_terminal_exchange_required')")}
    if {ast.unparse(n)for n in calls}!=set(expected_calls):return False
    for call in calls:
        name,guard=expected_calls[ast.unparse(call)]
        wrappers=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name and call in ast.walk(n)]
        if len(wrappers)!=1 or not any(isinstance(n,ast.Call)and ast.unparse(n)==guard
            for n in ast.walk(wrappers[0])):return False
    return True


def _native_launch_process_inventory(relative: str,tree: ast.AST) -> bool:
    """Closed trusted-launcher spawn/inspect shapes, no whole-module exemption.

    This trusted-source architecture inventory is not a Python security sandbox
    or runtime/qualification verifier. Commands/targets never come from operation
    data; real accepted launcher, qualified profile and process tests are separate.
    """
    if relative!='mutation/ntfs/bootstrap.py':return False
    imports=[n for n in ast.walk(tree) if isinstance(n,(ast.Import,ast.ImportFrom))
        and ((isinstance(n,ast.ImportFrom) and (n.module or '').split('.')[0]=='subprocess')
            or any(a.name.split('.')[0]=='subprocess' or a.asname=='subprocess' for a in n.names))]
    if len(imports)!=1 or imports[0] not in tree.body or not isinstance(imports[0],ast.Import):return False
    if [(a.name,a.asname) for a in imports[0].names]!=[('subprocess',None)]:return False
    owners=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='_NativeAcceptedLaunch']
    if len(owners)!=1:return False
    owner=owners[0]
    methods={}
    signatures={'_spawn':['self','args'],'_pipe':['self','process'],
        '_finalize_exited':['self','process','pipe'],'_check_linux_contours':['self'],
        '_linux_command':['self','role'],'spawn_core':['self'],'spawn_worker':['self'],
        'spawn_inspection':['self'],
        '_query_original':['self','action','digest']}
    for name,args in signatures.items():
        found=[n for n in owner.body if isinstance(n,ast.FunctionDef) and n.name==name]
        if len(found)!=1:return False
        f=found[0]
        if ([n.arg for n in f.args.args]!=args or f.args.posonlyargs or f.args.defaults
                or f.args.vararg or f.args.kwarg):return False
        if f.args.kwonlyargs:
            if (name!='_query_original' or [n.arg for n in f.args.kwonlyargs]!=['_original_nonce']
                    or len(f.args.kw_defaults)!=1 or not isinstance(f.args.kw_defaults[0],ast.Constant)
                    or f.args.kw_defaults[0].value is not None):return False
        if any(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda))
            for n in ast.walk(f) if n is not f):return False
        methods[name]=f
    # Reject every binding/alias escape of the imported module, including pattern
    # variables and exception aliases. Only reviewed attribute Load uses remain.
    for n in ast.walk(tree):
        if isinstance(n,ast.Name) and n.id=='subprocess' and not isinstance(n.ctx,ast.Load):return False
        if isinstance(n,ast.arg) and n.arg=='subprocess':return False
        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and n.name=='subprocess':return False
        if isinstance(n,ast.ExceptHandler) and n.name=='subprocess':return False
        if isinstance(n,(ast.Global,ast.Nonlocal)) and 'subprocess' in n.names:return False
        if isinstance(n,(ast.MatchAs,ast.MatchStar)) and n.name=='subprocess':return False
        if isinstance(n,ast.MatchMapping) and n.rest=='subprocess':return False
    parents={id(child):n for n in ast.walk(tree) for child in ast.iter_child_nodes(n)}
    allowed_refs={'_spawn':{'Popen','PIPE','CREATE_NO_WINDOW'},'_pipe':{'Popen'},
        '_finalize_exited':{'Handle'},'_check_linux_contours':{'run','DEVNULL','PIPE','CREATE_NO_WINDOW'}}
    for n in [n for n in ast.walk(tree) if isinstance(n,ast.Name) and n.id=='subprocess']:
        parent=parents.get(id(n))
        if not isinstance(parent,ast.Attribute):return False
        containing=[name for name,f in methods.items() if n in ast.walk(f)]
        if len(containing)!=1 or parent.attr not in allowed_refs.get(containing[0],set()):return False
    calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and _call_name(n).startswith('subprocess.')]
    expected={
      'subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, close_fds=True, creationflags=subprocess.CREATE_NO_WINDOW)':methods['_spawn'],
      "subprocess.run([config['docker_executable'], 'inspect', '--format', template, config[field]], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=True, creationflags=subprocess.CREATE_NO_WINDOW)":methods['_check_linux_contours']}
    if len(calls)!=2 or {ast.unparse(n) for n in calls}!=set(expected):return False
    if any(n not in ast.walk(expected[ast.unparse(n)]) for n in calls):return False
    # Every module reference must belong to its single reviewed call or exact
    # class-identity comparison. An alias inside an otherwise allowed method
    # cannot escape Popen/Handle or inherit this inventory exception.
    for n in [n for n in ast.walk(tree) if isinstance(n,ast.Name) and n.id=='subprocess']:
        containing=next(name for name,f in methods.items() if n in ast.walk(f))
        attribute=parents[id(n)]
        if containing in {'_spawn','_check_linux_contours'}:
            call=next(c for c in calls if c in ast.walk(methods[containing]))
            if n not in ast.walk(call):return False
        else:
            comparison=parents.get(id(attribute))
            exact=("type(process) is subprocess.Popen" if containing=='_pipe'
                else "type(handle) is subprocess.Handle")
            if not isinstance(comparison,ast.Compare) or ast.unparse(comparison)!=exact:return False
    refs=[n for n in ast.walk(methods['_spawn']) if isinstance(n,ast.Name) and n.id=='args']
    if len(refs)!=1 or not isinstance(refs[0].ctx,ast.Load):return False
    spawn_expected={
      "self._spawn(self._linux_command('core'))":methods['spawn_core'],
      "self._spawn(self._linux_command('inspect'))":methods['spawn_inspection'],
      "self._spawn([sys.executable, '-I', '-S', '-B', '-u', launcher, 'worker'])":methods['spawn_worker'],
      "self._spawn(self._linux_command('original'))":methods['_query_original']}
    refs=[n for n in ast.walk(tree) if isinstance(n,ast.Attribute) and isinstance(n.value,ast.Name)
        and n.value.id=='self' and n.attr=='_spawn']
    if len(refs)!=4:return False
    for n in refs:
        call=parents.get(id(n))
        if not isinstance(call,ast.Call) or call.func is not n or ast.unparse(call) not in spawn_expected:return False
        if n not in ast.walk(spawn_expected[ast.unparse(call)]):return False
    launcher=[n for n in ast.walk(methods['spawn_worker']) if isinstance(n,ast.Assign)
        and len(n.targets)==1 and ast.unparse(n.targets[0])=='launcher']
    if len(launcher)!=1 or ast.unparse(launcher[0].value)!="self._config['windows_launcher']":return False
    returns=[n for n in ast.walk(methods['_linux_command']) if isinstance(n,ast.Return)]
    if len(returns)!=1 or ast.unparse(returns[0].value)!="[config['docker_executable'], 'exec', '-i', container, config['linux_python'], '-I', '-S', '-B', '-u', config['linux_launcher'], role]":return False
    projection=[n for n in ast.walk(methods['_check_linux_contours']) if isinstance(n,ast.Assign)
        and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='template']
    if len(projection)!=1 or not isinstance(projection[0].value,ast.Constant):return False
    if projection[0].value.value!='{"id":{{json .Id}},"image":{{json .Image}},"user":{{json .Config.User}},"readonly_rootfs":{{json .HostConfig.ReadonlyRootfs}},"cap_drop":{{json .HostConfig.CapDrop}},"security_options":{{json .HostConfig.SecurityOpt}},"network_mode":{{json .HostConfig.NetworkMode}},"mounts":{{json .Mounts}},"pids_limit":{{json .HostConfig.PidsLimit}},"memory":{{json .HostConfig.Memory}},"nano_cpus":{{json .HostConfig.NanoCpus}},"running":{{json .State.Running}}}':return False
    return True


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
                if (relative not in allowed_write_modules and not stdout_channel_write and not windows_pipe_write
                        and not _native_terminal_stdout_write(relative,tree,node)
                        and not _native_terminal_pipe_write(relative,tree,node)):
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
    forbidden_calls = {"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile", "__import__", "builtins.__import__", "importlib.import_module", "subprocess.Popen", "subprocess.run", "runpy.run_path", "runpy.run_module", "os.system"}
    hits: list[tuple[str, int, str]] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        relative = path.relative_to(PACKAGE).as_posix()
        tree = _tree(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".", 1)[0] in forbidden_imports and not _readonly_process_class_import(relative, tree, node) and not (alias.name == 'subprocess' and _native_launch_process_inventory(relative,tree)):
                        hits.append((relative, node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".", 1)[0] in forbidden_imports:
                hits.append((relative, node.lineno, node.module or ""))
            elif isinstance(node, ast.Call):
                name = _call_name(node)
                if name in forbidden_calls and not (name in {'subprocess.Popen','subprocess.run'}
                    and _native_launch_process_inventory(relative,tree)):
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


@pytest.mark.parametrize('module,fd,extra,expected',[
 ('mutation/ntfs/entrypoint.py','1','',True),
 ('mutation/ntfs/other.py','1','',False),
 ('mutation/ntfs/entrypoint.py','True','',False),
 ('mutation/ntfs/entrypoint.py','caller_fd','',False),
 ('mutation/ntfs/entrypoint.py','2','',False),
 ('mutation/ntfs/entrypoint.py','1',' os.write(1, wire[offset:offset + 65536])',False),
])
def test_native_terminal_inventory_is_stdio_only(module,fd,extra,expected):
    tree=ast.parse(f'def _deliver_linux_frame(value,identities):\n os.write({fd}, wire[offset:offset + 65536])\n{extra}\n')
    calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and _call_name(n)=='os.write']
    assert calls and all(_native_terminal_stdout_write(module,tree,n) is expected for n in calls)


@pytest.mark.parametrize('mutation',[
 "subprocess.Popen(args, shell=True)","subprocess.run(args)",
 "getattr(subprocess, 'Popen')",'alias = subprocess.Popen',
 'subprocess = other','def other(subprocess): pass',
 'from subprocess import Popen','import subprocess as subprocess',
])
def test_native_process_inventory_rejects_extra_process_authority(mutation):
    source=(PACKAGE/'mutation/ntfs/bootstrap.py').read_text('utf-8')
    assert _native_launch_process_inventory('mutation/ntfs/bootstrap.py',ast.parse(source))
    assert not _native_launch_process_inventory('mutation/ntfs/bootstrap.py',ast.parse(source+'\n'+mutation+'\n'))


@pytest.mark.parametrize('old,new',[
 ('close_fds=True','close_fds=False'),('bufsize=0','bufsize=1'),
 ('creationflags=subprocess.CREATE_NO_WINDOW','creationflags=0'),
 ("self._spawn(self._linux_command('core'))","self._spawn(request_command)"),
 ("self._config['windows_launcher']","request['command']"),
 ("'exec', '-i'","'run', '-i'"),
])
def test_native_process_inventory_rejects_changed_spawn_shape(old,new):
    # Normalize ONLY synthetic mutation input; keep historical parameter IDs.
    # No source is executed and the inventory still evaluates the mutated AST.
    source=ast.unparse(ast.parse((PACKAGE/'mutation/ntfs/bootstrap.py').read_text('utf-8')))
    assert _native_launch_process_inventory('mutation/ntfs/bootstrap.py',ast.parse(source))
    assert old in source
    assert not _native_launch_process_inventory('mutation/ntfs/bootstrap.py',ast.parse(source.replace(old,new)))


def test_native_process_inventory_accepts_only_fixed_module():
    tree=_tree(PACKAGE/'mutation/ntfs/bootstrap.py')
    assert _native_launch_process_inventory('mutation/ntfs/bootstrap.py',tree)
    assert not _native_launch_process_inventory('mutation/ntfs/other.py',tree)


@pytest.mark.parametrize('replacement',[
    '*, foreign_nonce=None','*, _original_nonce=True',
    '*, _original_nonce=None, caller_command=None','*, _original_nonce=None, **kwargs',
])
def test_native_process_inventory_rejects_nonclosed_original_query_keywords(replacement):
    source=ast.unparse(ast.parse((PACKAGE/'mutation/ntfs/bootstrap.py').read_text('utf-8')))
    assert _native_launch_process_inventory('mutation/ntfs/bootstrap.py',ast.parse(source))
    old='*, _original_nonce=None'
    assert source.count(old)==1
    assert not _native_launch_process_inventory('mutation/ntfs/bootstrap.py',ast.parse(source.replace(old,replacement)))


@pytest.mark.parametrize('old,new',[
    ('os.write(descriptor(1),', 'os.write(descriptor(0),'),
    ('return value[0]', 'return 99'),
    ('return side', 'return caller_fd'),
    ('*, sending, raw, deadline_ns, maximum_bytes, windows):',
        '*, sending, raw, deadline_ns, maximum_bytes, windows, caller_fd=None):'),
    ('count = os.write(descriptor(1),', 'descriptor = replacement\n                    count = os.write(descriptor(1),'),
    ('count = os.write(descriptor(1), framed[progress[\'wire_bytes\']:progress[\'wire_bytes\']+65536])',
        'count = (lambda: os.write(descriptor(1), framed[progress[\'wire_bytes\']:progress[\'wire_bytes\']+65536]))()'),
    ('count = os.write(descriptor(1), framed[progress[\'wire_bytes\']:progress[\'wire_bytes\']+65536])',
        'count = os.write(descriptor(1), framed[progress[\'wire_bytes\']:progress[\'wire_bytes\']+65536])\n'
        '                    count = os.write(descriptor(1), framed[progress[\'wire_bytes\']:progress[\'wire_bytes\']+65536])'),
    ('windows=True)', 'windows=False)'),
])
def test_native_terminal_pipe_inventory_rejects_descriptor_or_owner_escape(old,new):
    relative='mutation/ntfs/bundle_recovery_terminal.py'
    source=(PACKAGE/relative).read_text('utf-8');tree=ast.parse(source)
    writes=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and _call_name(n)=='os.write']
    assert len(writes)==1 and _native_terminal_pipe_write(relative,tree,writes[0])
    assert not _native_terminal_pipe_write('mutation/ntfs/other.py',tree,writes[0])
    assert source.count(old)==1
    changed=ast.parse(source.replace(old,new))
    writes=[n for n in ast.walk(changed)if isinstance(n,ast.Call)and _call_name(n)=='os.write']
    assert writes and all(not _native_terminal_pipe_write(relative,changed,n)for n in writes)


def test_native_terminal_pipe_inventory_refuses_an_extra_frame_caller():
    relative='mutation/ntfs/bundle_recovery_terminal.py'
    source=(PACKAGE/relative).read_text('utf-8');tree=ast.parse(source)
    write=next(n for n in ast.walk(tree)if isinstance(n,ast.Call)and _call_name(n)=='os.write')
    assert _native_terminal_pipe_write(relative,tree,write)
    changed=ast.parse(source+'\ndef unrelated(owner):\n return _frame_io(owner, sending=True, raw=b"x", deadline_ns=1, maximum_bytes=1, windows=True)\n')
    write=next(n for n in ast.walk(changed)if isinstance(n,ast.Call)and _call_name(n)=='os.write')
    assert not _native_terminal_pipe_write(relative,changed,write)


@pytest.mark.parametrize('old,new',[
 ("        from .windows_pipe import WindowsPipeFrames\n", "        from .windows_pipe import WindowsPipeFrames\n        alias = subprocess.Popen\n"),
 ("            handle=process._handle\n", "            handle=process._handle\n            alias = subprocess.Handle\n"),
 ("{{json .Id}}", "{{json .Config.Env}}"),
])
def test_native_process_inventory_rejects_inner_alias_and_sensitive_projection(old,new):
    source=(PACKAGE/'mutation/ntfs/bootstrap.py').read_text('utf-8')
    assert _native_launch_process_inventory('mutation/ntfs/bootstrap.py',ast.parse(source))
    assert old in source
    assert not _native_launch_process_inventory('mutation/ntfs/bootstrap.py',ast.parse(source.replace(old,new)))


def test_bootstrap_subprocess_exception_never_exempts_runpy(tmp_path, monkeypatch):
    source=(PACKAGE/'mutation/ntfs/bootstrap.py').read_text('utf-8')
    changed=source+'\nimport runpy\nrunpy.run_path("synthetic-only")\n'
    tree=ast.parse(changed)
    assert _native_launch_process_inventory('mutation/ntfs/bootstrap.py',tree)
    path=tmp_path/'mutation/ntfs/bootstrap.py'
    path.parent.mkdir(parents=True)
    path.write_text(changed,encoding='utf-8')
    monkeypatch.setitem(globals(),'PACKAGE',tmp_path)
    with pytest.raises(AssertionError):test_no_shell_exec_subprocess_or_dynamic_module_loading()


@pytest.mark.parametrize('replacement',[
    "self._spawn(request_command)",
    "self._spawn(self._linux_command('core'))",
    "self._spawn(self._linux_command(request_role))",
])
def test_native_inspection_spawn_inventory_rejects_nonliteral_or_wrong_role(replacement):
    source=(PACKAGE/'mutation/ntfs/bootstrap.py').read_text('utf-8')
    assert _native_launch_process_inventory('mutation/ntfs/bootstrap.py',ast.parse(source))
    old="self._spawn(self._linux_command('inspect'))"
    assert source.count(old)==1
    assert not _native_launch_process_inventory('mutation/ntfs/bootstrap.py',ast.parse(source.replace(old,replacement)))


@pytest.mark.parametrize('signature,expected',[
 ('value,identities,*,_deadline=None',True),
 ('value,identities,*,caller_fd=None',False),
 ('caller_fd,/,value,identities',False),
 ('value=None,identities=None',False),
 ('value,identities,*,_deadline=30',False),
 ('value,identities,*,_deadline',False),
 ('value,identities,**options',False),
 ('value,identities,*options',False),
])
def test_native_terminal_inventory_rejects_new_caller_authority(signature,expected):
    tree=ast.parse(f'def _deliver_linux_frame({signature}):\n os.write(1, wire[offset:offset + 65536])\n')
    calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and _call_name(n)=='os.write']
    assert len(calls)==1
    assert _native_terminal_stdout_write('mutation/ntfs/entrypoint.py',tree,calls[0]) is expected
