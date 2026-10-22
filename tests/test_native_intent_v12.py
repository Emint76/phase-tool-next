"""Schema/data-only original-intent controls, never native admission or I/O."""
from copy import deepcopy
import unittest
from jsonschema.exceptions import ValidationError
from phase_tool.canonical import canonical_bytes, digest_bytes, profile_digest
from phase_tool.errors import PhaseError
from phase_tool.evidence import validate_intent
from phase_tool.preconditions import verify_pre_validator_binding
from phase_tool.registry import BundledRegistry, RegistrySnapshot

OLD_PACKAGE='sha256:e3231b5f97bb49c499a82fd1d003ddde081c9cbe31b7b10b87435526c1e15870'
SCHEMA='schemas/phase-intent-1.2.schema.json'
D='sha256:'+'0'*64


def fixture(registry):
    # Synthetic structural claims only. No installation/profile is qualified by
    # this data; these values must never be passed to an executor or Core route.
    entries=[entry for entry in registry.to_document()['entries'] if entry.get('kind')=='contract'
        and entry.get('id')=='file_create.v1' and any(a['resource']==SCHEMA for a in entry.get('package_artifacts',[]))]
    assert len(entries)==1 and entries[0]['current'] is False
    binding={key:entries[0][key] for key in ('id','version','package_digest')}
    contract=registry.resolve_contract(**dict(identifier=binding['id'],version=binding['version'],
        package_digest=binding['package_digest'],core_version='1.2.0-rc.1'))
    mechanism={key:contract.document['operation']['mechanism'][key] for key in ('id','version','package_digest')}
    roots=[{'root_binding':'phase_result_root','device':r'\Device\HarddiskVolume17',
        'volume_guid':'\\\\?\\volume{11111111-2222-3333-4444-555555555555}\\',
        'volume_serial32':17,'components':['Qualification','Synthetic'],
        'native_identity':{'volume_serial':(1<<48)+17,'file_id':'0123456789abcdef'+'fedcba9876543210'}}]
    return {'phase_intent_version':'1.2','run_id':'synthetic-schema-only','created_at':'2026-10-22T00:00:00Z',
        'core':{'id':'phase.core','version':'1.2.0-rc.1','package_digest':D},'registry_snapshot_digest':registry.digest,
        'contract':binding,'candidate':{'input_mode':'structured_json','digest':D,'length':2,
            'storage':{'mode':'inline','value':{},'attachment_digest':None}},'inputs':[],
        'write_scope_digest':D,'operation':{'intent':'create','mechanism':mechanism},
        'idempotency':{'key':'schema-only','scope_digest':D,'request_digest':D,
            'root_identity_digest':profile_digest('native-root-identity-v1',roots),'root_identities':roots},
        'effect_plan_digest':D,'implementation_binding':{'authority':{'usage':'provider_backed',
            'profile':{'id':'synthetic.unqualified','version':'1.0.0','descriptor_digest':D},
            'provider':{'id':'synthetic.uninstalled','version':'1.0.0','artifact_digest':D}},
            'mechanism':mechanism,'effect_plan_digest':D},'execution_requested':True,
        'evidence':{'effect_plan_attachment_digest':D,'content_blob_digests':[],
            'pre_validator_results_digest':digest_bytes(b'[]')},'status':'intent_recorded',
        'native_binding':{'native_binding_version':'1.0','installation':{'id':'synthetic.uninstalled','descriptor_digest':D},
            'composition':{'id':'synthetic.unselected','version':'1.0.0','artifact_graph_digest':D},
            'evidence_identity':{'stable_id':'synthetic.ext4','device':1,'inode':2},'operation_nonce':'a'*32}}


class NativeIntentSchemaTests(unittest.TestCase):
    def setUp(self):
        self.registry=BundledRegistry.load()
        self.intent=fixture(self.registry)

    def test_full_native_identity_has_a_package_bound_schema(self):
        validate_intent(self.intent,self.registry)
        identity=self.intent['idempotency']['root_identities'][0]['native_identity']
        self.assertGreater(identity['volume_serial'],2**32)
        self.assertEqual(len(identity['file_id']),32)
        self.assertTrue(verify_pre_validator_binding(self.intent,digest_bytes(b'[]')))

    def test_default_selection_and_descriptors_are_unchanged(self):
        uri='https://phase-tool.local/'+SCHEMA
        entries=[entry for entry in self.registry.to_document()['entries']
            if entry.get('kind')=='schema' and entry.get('schema_ref')==uri]
        self.assertEqual(len(entries),1)
        self.assertIs(entries[0]['current'],True)
        raw=BundledRegistry.resources()[SCHEMA]
        self.assertEqual(digest_bytes(raw),'sha256:af15652c8073fb546b4b7b0496a1a40b6da4a97f822444102e49bcca1e8c647d')
        self.assertEqual(self.registry.schema_document(uri),self.registry.schema_document(uri,digest_bytes(raw)))
        self.assertEqual(self.registry.contract_bindings()['file_create.v1@1.0.0']['package_digest'],OLD_PACKAGE)
        old=self.registry.resolve_contract('file_create.v1','1.0.0',OLD_PACKAGE,core_version='1.2.0-rc.1')
        new=self.registry.resolve_contract(**dict(identifier=self.intent['contract']['id'],version='1.0.0',
            package_digest=self.intent['contract']['package_digest'],core_version='1.2.0-rc.1'))
        self.assertEqual(old.document,new.document)
        self.assertEqual(old.entry['artifact_digest'],new.entry['artifact_digest'])
        self.assertFalse(new.entry['current'])

    def test_historical_schema_bytes_unchanged(self):
        expected={'schemas/phase-intent.schema.json':'sha256:b511a3cf311554daabff7555a1b407ad3deb581efea5d53d82657a5991270040',
            'schemas/phase-intent-1.1.schema.json':'sha256:1cec2a5728209bd130cd7d44d3a6ca3e00e7ed3805ac599bc02233e5515c5904'}
        resources=BundledRegistry.resources()
        for name,digest in expected.items():self.assertEqual(digest_bytes(resources[name]),digest)

    def test_native_schema_has_no_unpinned_external_reference(self):
        schema=self.registry.schema_document('https://phase-tool.local/'+SCHEMA,
            next(a['digest'] for e in self.registry.to_document()['entries'] if e.get('kind')=='contract'
                and e.get('package_digest')==self.intent['contract']['package_digest']
                for a in e['package_artifacts'] if a['resource']==SCHEMA))
        def check(value):
            if isinstance(value,dict):
                for key,item in value.items():
                    if key=='$ref':self.assertTrue(item.startswith('#/'),item)
                    else:check(item)
            elif isinstance(value,list):
                for item in value:check(item)
        check(schema)

    def test_new_native_nested_shape_ignores_replacement_current_schema(self):
        document=self.registry.to_document();resources=BundledRegistry.resources()
        uri='https://phase-tool.local/schemas/mutation-implementation-binding.schema.json'
        old=next(e for e in document['entries'] if e.get('kind')=='schema' and e.get('schema_ref')==uri
            and e.get('current',True))
        old['current']=False
        raw=canonical_bytes({'$schema':'https://json-schema.org/draft/2020-12/schema','$id':uri,'not':{}})
        replacement=deepcopy(old);replacement.update(artifact='test-only/replacement-current.json',
            artifact_digest=digest_bytes(raw),package_digest=digest_bytes(raw),current=True)
        document['entries'].append(replacement);resources[replacement['artifact']]=raw
        registry=RegistrySnapshot.from_document(document,resources)
        # Only synthetic in-memory schema resolution. No trust/provider guard is
        # disabled; the original immutable77db nested shape is local to1.2.
        validate_intent(self.intent,registry)
        intent=deepcopy(self.intent);intent['implementation_binding']['authority']['extra']=True
        with self.assertRaises(ValidationError):validate_intent(intent,registry)

    def test_old_package_cannot_accept_new_intent(self):
        self.intent['contract']['package_digest']=OLD_PACKAGE
        with self.assertRaisesRegex(PhaseError,'intent.schema_unbound'):validate_intent(self.intent,self.registry)

    def test_native_binding_required(self):
        del self.intent['native_binding']
        with self.assertRaises(ValidationError):validate_intent(self.intent,self.registry)

    def test_single_root_table_cannot_be_posix(self):
        self.intent['idempotency']['root_identities']=[{'binding_id':'phase_result_root',
            'resolved_path':'/synthetic','device':1,'inode':2}]
        with self.assertRaises(ValidationError):validate_intent(self.intent,self.registry)

    def test_identity_truncation_bool_and_ranges_rejected(self):
        for field,value in [('volume_serial',True),('volume_serial',-1),('volume_serial',2**64),
                            ('file_id','f'*16),('file_id','f'*33),('file_id','G'*32)]:
            with self.subTest(field=field,value=value):
                intent=deepcopy(self.intent);intent['idempotency']['root_identities'][0]['native_identity'][field]=value
                with self.assertRaises(ValidationError):validate_intent(intent,self.registry)

    def test_native_namespace_shape_rejected(self):
        for field,value in [('volume_serial32',True),('volume_serial32',2**32),('device','S:'),
                            ('volume_guid','S:'),('components',[]),('components',['..']),('components',['CON']),
                            ('components',['parent/child']),('components',['trailing.'])]:
            with self.subTest(field=field,value=value):
                intent=deepcopy(self.intent);intent['idempotency']['root_identities'][0][field]=value
                with self.assertRaises(ValidationError):validate_intent(intent,self.registry)

    def test_closed_shapes_do_not_accept_qualification_or_command_fields(self):
        paths=[(),('native_binding',),('native_binding','installation'),('native_binding','composition'),
               ('native_binding','evidence_identity'),('idempotency',),('idempotency','root_identities',0),
               ('idempotency','root_identities',0,'native_identity')]
        for path in paths:
            with self.subTest(path=path):
                intent=deepcopy(self.intent);node=intent
                for key in path:node=node[key]
                node['qualified']=True
                with self.assertRaises(ValidationError):validate_intent(intent,self.registry)

    def test_root_table_mandatory_nonempty_and_unique(self):
        for roots in (None,[],self.intent['idempotency']['root_identities']*2):
            with self.subTest(roots=roots):
                intent=deepcopy(self.intent)
                if roots is None:del intent['idempotency']['root_identities']
                else:intent['idempotency']['root_identities']=roots
                with self.assertRaises(ValidationError):validate_intent(intent,self.registry)

    def test_prevalidation_digest_is_not_a_historical_exemption(self):
        with self.assertRaisesRegex(PhaseError,'preconditions.digest_mismatch'):
            verify_pre_validator_binding(self.intent,digest_bytes(b'[1]'))
        del self.intent['evidence']['pre_validator_results_digest']
        with self.assertRaises(ValidationError):validate_intent(self.intent,self.registry)
        with self.assertRaisesRegex(PhaseError,'preconditions.digest_mismatch'):
            verify_pre_validator_binding(self.intent,digest_bytes(b'[]'))

    def test_unknown_version_still_rejects(self):
        for version in (None,'','1.3','2.0'):
            with self.subTest(version=version):
                with self.assertRaisesRegex(PhaseError,'preconditions.unsupported_intent_version'):
                    verify_pre_validator_binding({'phase_intent_version':version},D)


if __name__=='__main__':unittest.main()
