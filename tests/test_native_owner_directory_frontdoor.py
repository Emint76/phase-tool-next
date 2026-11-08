"""Actual pure decoders only: no Native/Phase dispatch, filesystem writes or catalogue activation."""
from pathlib import Path
import ast, base64, hashlib, importlib.util, json, sys, unittest
from importlib.resources import files
from phase_tool.canonical import canonical_bytes,digest_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import owner_directory_launch as launch
source=files('phase_tool').joinpath('data/native/native_phase_candidate_launcher_v1.py.in').read_bytes()
nodes=[n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name in {'need','fixed_startup_version'}]
assert len(nodes)==2
g={}
exec(compile(ast.Module(body=nodes,type_ignores=[]),'packaged-native-candidate-template','exec'),g)
def config():
    raw=canonical_bytes({'component_test_data_only':True})
    value={key:None for key in launch._FIELDS}
    value.update(native_launch_version='4.0',owner_directory_configuration_base64=base64.b64encode(raw).decode(),owner_directory_configuration_digest=digest_bytes(raw))
    return value,raw
def outer(version):
    value=dict(native_fixed_startup_version=version,config_base64='x',config_digest='x',manifest_base64='x',manifest_digest='x',dependency_roots=[])
    if version=='1.1':value['experimental_admission_base64']='x'
    if version in {'2.0','3.0'}:value['owner_directory_fixture_base64']='x'
    return value
class Decoders(unittest.TestCase):
    def test_exact_decoder_returns_unchanged_binary_binding(self):
        value,raw=config()
        self.assertEqual(launch._owner_configuration_from_launch_config(value),(raw,digest_bytes(raw)))
    def test_extra_target_or_authority_selector_rejected(self):
        for key in ('target_locator','candidate_digest','profile','provider','experimental_admission_base64','history_manifest_set_base64'):
            value,_=config();value[key]='x'
            with self.subTest(key=key),self.assertRaises(PhaseError):launch._owner_configuration_from_launch_config(value)
    def test_missing_fields_rejected(self):
        for key in launch._FIELDS:
            value,_=config();del value[key]
            with self.subTest(key=key),self.assertRaises(PhaseError):launch._owner_configuration_from_launch_config(value)
    def test_foreign_or_untyped_version_rejected(self):
        for version in ('3.0','4.1',4.0,True,None):
            value,_=config();value['native_launch_version']=version
            with self.subTest(version=version),self.assertRaises(PhaseError):launch._owner_configuration_from_launch_config(value)
    def test_base64_trailing_newline_and_whitespace_rejected(self):
        for suffix in ('\n',' ','=','\t'):
            value,_=config();value['owner_directory_configuration_base64']+=suffix
            with self.subTest(suffix=suffix),self.assertRaises(PhaseError):launch._owner_configuration_from_launch_config(value)
    def test_base64_nonascii_or_nontext_rejected(self):
        for encoded in ('РЇ','!','',None,False,b'eA=='):
            value,_=config();value['owner_directory_configuration_base64']=encoded
            with self.subTest(encoded=repr(encoded)),self.assertRaises(PhaseError):launch._owner_configuration_from_launch_config(value)
    def test_digest_shape_and_binding_rejected(self):
        for digest in ('sha256:'+'0'*64,'sha256:'+'A'*64,'0'*64,None,True):
            value,_=config();value['owner_directory_configuration_digest']=digest
            with self.subTest(digest=digest),self.assertRaises(PhaseError):launch._owner_configuration_from_launch_config(value)
    def test_whole_launch_envelope_bound_includes_graph(self):
        value,_=config();value['artifact_graph']='x'*(2*1024**2)
        with self.assertRaises(PhaseError):launch._owner_configuration_from_launch_config(value)
    def test_all_historical_startup_shapes_retained(self):
        for version in ('1.1','1.2','2.0','3.0'):
            with self.subTest(version=version):self.assertEqual(g['fixed_startup_version'](outer(version)),version)
    def test_ordinary4_common_shape_has_no_duplicate_owner_bytes(self):
        value=outer('4.0')
        self.assertEqual(g['fixed_startup_version'](value),'4.0')
        for key in ('experimental_admission_base64','owner_directory_fixture_base64','owner_directory_configuration_base64','profile','provider'):
            wrong=dict(value);wrong[key]='x'
            with self.subTest(key=key),self.assertRaises(RuntimeError):g['fixed_startup_version'](wrong)
    def test_ordinary4_missing_outer_field_rejected(self):
        for key in outer('4.0'):
            value=outer('4.0');del value[key]
            with self.subTest(key=key),self.assertRaises(RuntimeError):g['fixed_startup_version'](value)
    def test_unknown_outer_versions_rejected(self):
        for version in ('4.1',4.0,True,None):
            with self.subTest(version=version),self.assertRaises(RuntimeError):g['fixed_startup_version'](outer(version))

if __name__=='__main__':unittest.main()
