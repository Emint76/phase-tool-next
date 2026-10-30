"""Real Core metadata scanners with explicit synthetic native records.

No native authority/worker/GO or complete native original is produced. Portable
tests exercise static idempotency refusal; Linux tests exercise real ext4 locks
and evidence refusal. Neither is native execution or qualification evidence.
"""
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory,gettempdir
from types import SimpleNamespace
import stat
import sys
import uuid
import unittest
from unittest.mock import patch

from phase_tool import core,installation
from phase_tool.canonical import canonical_bytes,canonical_digest,digest_bytes,parse_json_bytes,profile_digest
from phase_tool.evidence import validate_intent
from phase_tool.errors import PhaseError
from phase_tool.registry import BundledRegistry
from .test_native_intent_v12 import fixture as schema_claims
from .test_native_experiment_history import history_fixture,history_bytes


def synthetic_intent(row,index):
    """Valid schema/static bindings only, never an executed original/proof."""
    manifest=parse_json_bytes(row.manifest_bytes);doc=row.experimental_admission.document()
    value=schema_claims(BundledRegistry.load())
    payloads=(b'history zero\n',b'history one\n',b'history two\n')
    candidate={'operation_id':doc['run_id'],'idempotency_key':doc['request_id'],
        'target_locator':doc['target_locator'],'input_binding':'payload'}
    if index:candidate['expected_current_digest']=digest_bytes(payloads[index-1])
    assert digest_bytes(canonical_bytes(candidate))==doc['candidate_digest']
    value.update(run_id=doc['run_id'],core=deepcopy(manifest['core']),
        contract=deepcopy(manifest['contract']),registry_snapshot_digest=row.registry.digest,
        operation={'intent':'publish_new_version' if index else 'create',
            'mechanism':deepcopy(manifest['mechanism'])})
    contract=row.registry.resolve_contract(manifest['contract']['id'],manifest['contract']['version'],
        manifest['contract']['package_digest'],core_version=manifest['core']['version'])
    value['write_scope_digest']=canonical_digest(contract.document['write_scope'])
    value['candidate'].update(digest=profile_digest('candidate',candidate),
        length=len(canonical_bytes(candidate)),storage={'mode':'inline','value':candidate,'attachment_digest':None})
    value['inputs']=[{'binding_id':'payload','freeze_strategy':'copy_and_hash',
        'digest':doc['payload_digest'],'blob_digest':doc['payload_digest'],'manifest_digest':None,
        'provenance_ref':None,'frozen_at':value['created_at'],'revalidation_token':None}]
    root=profile_digest('native-root-identity-v1',manifest['root_grants'])
    scope={'contract':value['contract'],'result_locator':doc['target_locator'],
        'root_identity_digest':root,'operation_intent':value['operation']['intent']}
    value['idempotency'].update(key=doc['request_id'],root_identities=deepcopy(manifest['root_grants']),
        root_identity_digest=root,scope_digest=profile_digest('idempotency-scope',scope),
        request_digest=profile_digest('request',{'scope':scope,
            'candidate_digest':value['candidate']['digest'],'inputs':value['inputs']}))
    value['native_binding'].update(installation={'id':manifest['installation_id'],
        'descriptor_digest':row.manifest_digest},composition=deepcopy(manifest['composition']),
        evidence_identity=deepcopy(manifest['evidence_identity']))
    value['implementation_binding'].update(authority=deepcopy(manifest['authority']),
        mechanism=deepcopy(manifest['mechanism']))
    value['evidence']['content_blob_digests']=[doc['payload_digest']]
    validate_intent(value,row.registry)
    return value


class HistoryMetadataScanTests(unittest.TestCase):
    def setUp(self):
        # Prior TemporaryDirectory roots were inaccessible; exact cause unknown.
        # Use inherited security, without permission resets or temp fallback.
        parent=(Path(__file__).resolve().parents[1] if sys.platform=='win32'
            else Path(gettempdir()).resolve())
        info=parent.lstat()
        self.assertTrue(stat.S_ISDIR(info.st_mode))
        self.assertFalse(stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400)
        self.root=parent/('phase-history-metadata-'+uuid.uuid4().hex)
        self._fixture_dirs=[];self._fixture_files=[]
        self.root.mkdir()
        self._remember_fixture(self.root,directory=True)
        self.addCleanup(self._cleanup_fixture)
        self.assertEqual(self.root.parent,parent)
        phase=self.root/'.phase';self._mkdir_fixture(phase)
        self.runs=phase/'runs';self._mkdir_fixture(self.runs)
        self.rows=history_fixture()
        self.store=SimpleNamespace(evidence_root=self.root,run_root=self.runs/'history-version-b')
        # Data-only argument to a static scanner, NOT an admitted authority.
        self.authority=SimpleNamespace(read_binding=self.rows[2])

    def _fixture_identity(self,path,*,directory):
        self.assertTrue(path==self.root or path.is_relative_to(self.root))
        info=path.lstat()
        self.assertFalse(stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400)
        self.assertTrue(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        if not directory:self.assertEqual(info.st_nlink,1)
        self.assertNotEqual(info.st_ino,0)
        return info.st_dev,info.st_ino

    def _remember_fixture(self,path,*,directory):
        identity=self._fixture_identity(path,directory=directory)
        entries=self._fixture_dirs if directory else self._fixture_files
        self.assertFalse(any(old==path for old,_ in entries))
        entries.append((path,identity))

    def _mkdir_fixture(self,path):
        self.assertTrue(any(old==path.parent for old,_ in self._fixture_dirs))
        path.mkdir()
        self._remember_fixture(path,directory=True)

    def _cleanup_fixture(self):
        # Preflight the complete known inventory before any deletion. Unknown
        # children, access refusal or identity drift leaves the fixture intact.
        all_entries=self._fixture_dirs+self._fixture_files
        for path,identity in self._fixture_dirs:
            self.assertEqual(self._fixture_identity(path,directory=True),identity)
            self.assertEqual(set(path.iterdir()),{p for p,_ in all_entries if p.parent==path})
        for path,identity in self._fixture_files:
            self.assertEqual(self._fixture_identity(path,directory=False),identity)
        for path,identity in reversed(self._fixture_files):
            self.assertEqual(self._fixture_identity(path,directory=False),identity);path.unlink()
        for path,identity in reversed(self._fixture_dirs):
            self.assertEqual(self._fixture_identity(path,directory=True),identity);path.rmdir()

    def put(self,index,name=None):
        value=synthetic_intent(self.rows[index],index)
        run=self.runs/(name or value['run_id']);self._mkdir_fixture(run)
        path=run/'intent.json'
        with path.open('xb') as stream:stream.write(canonical_bytes(value))
        self._remember_fixture(path,directory=False)
        return path,value

    def scan(self,*,key='unrelated-key',scope='sha256:'+'e'*64,request='sha256:'+'f'*64):
        return core.PhaseCore._check_idempotency(self.store,None,self.rows[2].registry,
            key,scope,request,{},execute=True,_native_authority=self.authority,
            _native_history_bindings=self.rows)

    def test_all_different_keys_use_own_static_registry_and_bindings(self):
        self.put(0);self.put(1)
        with patch.object(core,'validate_intent',wraps=core.validate_intent) as validate:
            self.assertIsNone(self.scan())
        self.assertEqual([call.args[1] for call in validate.call_args_list],
            [self.rows[0].registry,self.rows[1].registry])

    def test_unknown_run_blocks_even_when_its_key_differs(self):
        self.put(0,'unknown-other-key')
        with self.assertRaisesRegex(PhaseError,'idempotency.prior_inspection_required'):
            self.scan()

    def test_wrong_registry_or_installation_never_passes_on_a_different_key(self):
        path,value=self.put(1)
        for field in ('registry','installation'):
            changed=deepcopy(value)
            if field=='registry':changed['registry_snapshot_digest']='sha256:'+'f'*64
            else:changed['native_binding']['installation']['descriptor_digest']=self.rows[2].manifest_digest
            path.write_bytes(canonical_bytes(changed))
            with self.subTest(field=field),self.assertRaisesRegex(PhaseError,'idempotency.prior_inspection_required'):
                self.scan()

    def test_changed_same_key_reaches_core_conflict_without_historical_inspect(self):
        _,value=self.put(1);prior=value['idempotency']
        with patch.object(core,'inspect_run',side_effect=AssertionError('inspect reached')) as inspect:
            with self.assertRaisesRegex(PhaseError,'idempotency.same_key_conflict'):
                self.scan(key=prior['key'],scope=prior['scope_digest'],request='sha256:'+'f'*64)
            inspect.assert_not_called()

    def test_equal_request_never_reuses_active_authority_for_historical_observation(self):
        _,value=self.put(1);prior=value['idempotency']
        with patch.object(core,'inspect_run',side_effect=AssertionError('active observation reached')) as inspect:
            with self.assertRaisesRegex(PhaseError,'idempotency.prior_inspection_required'):
                self.scan(key=prior['key'],scope=prior['scope_digest'],request=prior['request_digest'])
            inspect.assert_not_called()


@unittest.skipUnless(sys.platform.startswith('linux'),'real qualified Linux/ext4 guard components required')
class HistoryOriginalGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=TemporaryDirectory(prefix='phase-history-guard-')
        self.root=Path(self.tmp.name).resolve()
        self.assertEqual(self.root.parent,Path(gettempdir()).resolve())
        self.assertTrue(self.root.name.startswith('phase-history-guard-'))
        self.addCleanup(self.tmp.cleanup)
        evidence=self.root/'evidence';preparation=self.root/'preparation';opaque=self.root/'opaque'
        for path in (evidence,preparation,opaque):path.mkdir(mode=0o700)
        installation.qualify_host_authority_roots({'evidence':evidence,'preparation':preparation})
        if installation._linux_filesystem_type(evidence)!='ext4':self.skipTest('actual ext4 required')
        def identity(path):
            info=path.stat()
            return {'stable_id':'synthetic.history.'+path.name,'device':info.st_dev,'inode':info.st_ino}
        rows=[]
        for old in history_fixture():
            manifest=parse_json_bytes(old.manifest_bytes);doc=old.experimental_admission.document()
            doc.update(evidence_identity=identity(evidence),preparation_identity=identity(preparation))
            cap=type(old.experimental_admission)(canonical_bytes(doc))
            manifest.update(evidence_root=str(evidence),evidence_identity=doc['evidence_identity'],
                preparation_root=str(preparation),preparation_identity=doc['preparation_identity'],
                installation_id=cap._installation_prefix+cap.digest[7:],
                root_projections={manifest['root_grants'][0]['root_binding']:str(opaque)})
            raw=canonical_bytes(manifest)
            rows.append(installation._native_experimental_read_binding(manifest_bytes=raw,
                expected_manifest_digest=digest_bytes(raw),admission=cap))
        self.rows=tuple(rows);raw=history_bytes(self.rows)
        self.history=installation._resolve_native_history_bindings(self.rows[0],raw,digest_bytes(raw))
        self.evidence=evidence;self.runs=evidence/'.phase'/'runs'
        self.runs.mkdir(parents=True,mode=0o700);(evidence/'.phase'/'locks').mkdir(mode=0o700)

    def guard(self,index=2):
        return core._guard_native_original_intents(self.rows[index],history_bindings=self.history)

    def test_three_rejections_use_one_lock_and_own_per_run_cap(self):
        for row in self.rows:
            doc=row.experimental_admission.document();exact=doc['contract'];name=doc['run_id']
            request=core.PhaseRequest(exact['id'],exact['version'],exact['package_digest'],
                self.root/'unused.json',self.evidence,name,{}, {},timestamp='2026-10-28T00:00:00Z')
            receipt=core.PhaseCore(row.registry)._rejection_receipt(request,[],request.timestamp,
                'synthetic.rejected',attachment_digests=[row.experimental_admission.digest])
            run=self.runs/name;run.mkdir(mode=0o700);(run/'attachments').mkdir(mode=0o700)
            (run/'receipt.json').write_bytes(canonical_bytes(receipt))
            (run/'attachments'/'experimental-admission.json').write_bytes(row.experimental_admission.raw)
        before={p:p.read_bytes() for p in self.runs.rglob('*') if p.is_file()}
        locks=None
        for index in range(3):
            with self.guard(index):pass
            actual={p.name:(p.stat().st_dev,p.stat().st_ino) for p in (self.evidence/'.phase'/'locks').iterdir()}
            self.assertEqual(len(actual),1)
            if locks is not None:self.assertEqual(locks,actual)
            locks=actual
        self.assertEqual(before,{p:p.read_bytes() for p in self.runs.rglob('*') if p.is_file()})

    def test_orphan_proofless_and_unclosed_metadata_never_yield(self):
        for mode in ('orphan','proofless','unclosed'):
            row=self.rows[1];run=self.runs/row.experimental_admission.document()['run_id'];run.mkdir(mode=0o700)
            if mode!='orphan':
                (run/'intent.json').write_bytes(canonical_bytes(synthetic_intent(row,1)))
            if mode=='unclosed':
                (run/'attachments').mkdir(mode=0o700)
                (run/'attachments'/'native-terminal-proof.json').write_bytes(b'{}')
            with self.subTest(mode=mode),self.assertRaisesRegex(PhaseError,'ntfs.original_history_unresolved'):
                with self.guard():self.fail('unclosed original yielded')
            # Only explicitly created own test entries, no recursive removal.
            if mode=='unclosed':
                (run/'attachments'/'native-terminal-proof.json').unlink();(run/'attachments').rmdir()
            if mode!='orphan':(run/'intent.json').unlink()
            run.rmdir()

    def test_unknown_run_and_other_known_installation_cannot_close_an_original(self):
        for mode in ('unknown-run','other-installation'):
            row=self.rows[1];value=synthetic_intent(row,1)
            if mode=='unknown-run':
                value['run_id']='unknown-other-key';value['idempotency']['key']='unrelated-key'
            else:
                manifest=parse_json_bytes(self.rows[2].manifest_bytes)
                value['native_binding']['installation']={'id':manifest['installation_id'],
                    'descriptor_digest':self.rows[2].manifest_digest}
            run=self.runs/value['run_id'];run.mkdir(mode=0o700)
            (run/'intent.json').write_bytes(canonical_bytes(value))
            with self.subTest(mode=mode),self.assertRaisesRegex(PhaseError,'ntfs.original_history_binding_mismatch'):
                with self.guard():self.fail('foreign original yielded')
            (run/'intent.json').unlink();run.rmdir()


if __name__=='__main__':unittest.main()
