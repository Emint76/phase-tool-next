"""Real disposable Linux/ext4 Original files; synthetic native claim metadata.

No accepted runtime, authority, Core operation, worker, native target or GO.
Only check_runtime is an explicit metadata-model boundary; real constructor
validation, real admission/history, real filesystem reader and parsers run.
"""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import base64,os,subprocess
from phase_tool.canonical import canonical_bytes,canonical_digest,digest_bytes,parse_json_bytes
from phase_tool.installation import _linux_filesystem_type,qualify_host_authority_roots
from phase_tool.mutation.ntfs import owner_directory_fixture as owner,input_stage,native,bootstrap,original_endpoint
from .native_staged_original14_data import builders
from .native_staged_original14_records import record_for

class RuntimeBoundary(RuntimeError):pass

class Original14Storage:
    def __init__(self,root,version='3.0'):
        self.root=Path(root);self.version=version;self.env=builders();self.evidence=self.root/'evidence';self.preparation=self.root/'preparation'
        for p in(self.evidence,self.preparation):p.mkdir(mode=0o700,parents=True)
        qualify_host_authority_roots({'phase_evidence_root':self.evidence,'phase_preparation_root':self.preparation})
        if _linux_filesystem_type(self.evidence)!='ext4':raise RuntimeError('NOT_VERIFIED: genuine ext4 required')
        self.doc=self.env['fixture'](version)
        for name,path in(('evidence',self.evidence),('preparation',self.preparation)):
            st=path.stat();self.doc[name+'_root']=str(path);self.doc[name+'_identity']={'stable_id':'original14.'+name,'device':st.st_dev,'inode':st.st_ino}
        self.raw=canonical_bytes(self.doc);self.graph=self.env['prepared'](version)[3];self.manifests={};self.scopes={};deps={}
        for role,kind in owner._kinds().items():
            row=next(r for r in self.doc['roles']if r['role']==role);m=deepcopy(self.env['ACTUAL'][role]['manifest'])
            m.update(core=deepcopy(self.doc['core']),contract=deepcopy(row['contract']),registry_snapshot_digest=row['registry_snapshot_digest'],
                authority=deepcopy(row['authority']),installation_id=owner.installation_id(kind,self.raw))
            for key in('evidence_root','evidence_identity','preparation_root','preparation_identity'):m[key]=deepcopy(self.doc[key])
            view=owner.role_projection(kind,self.raw);m['root_grants']=view.get('root_grants',[view.get('root_grant')])
            m['root_projections']=deepcopy(self.doc['root_projections'])if role=='Version2'else{row['root_binding']:'/ntfs-result'}
            path=self.root/'installation'/role/'native-input-scope.json'
            scope={'native_input_scope_version':'1.0','scope_id':'original14-'+role.lower(),
                'owner_scope_id':self.doc['owner_scope_id'],'fixture_digest':digest_bytes(self.raw),'installation_id':m['installation_id'],
                'contract':m['contract'],'windows_root':r'C:\Original14-Model-Input',
                'volume':{'device':r'\Device\HarddiskVolume6','volume_guid':'\\\\?\\volume{ba5c2916-eefe-46a6-aabc-b23fe12c95b4}\\',
                    'volume_serial32':714582050,'filesystem':'NTFS','flags':0},
                'root_identity':{'volume_serial':m['root_grants'][0]['native_identity']['volume_serial'],'file_id':'f'*32},
                'preparation_root':str(self.preparation),'preparation_identity':self.doc['preparation_identity']}
            scope_raw=canonical_bytes(scope);self.write(path,scope_raw);deps[str(path)]=digest_bytes(scope_raw)
            self.scopes[role]=(scope,path,scope_raw);self.manifests[role]=m
        self.graph['linux']['dependency_file_digests']=deepcopy(deps)
        for m in self.manifests.values():m['composition']['artifact_graph_digest']=canonical_digest(self.graph)
        self.data=(self.doc,self.raw,self.manifests,self.graph);self.records={};self.files={};self.stage_files={}
        for role in owner._ROLES:
            record=record_for(role,self.data);self.records[role]=record;self.files[role]=self.original_files(record)
            self.stage_files[role]=self.marker_files(record)if version=='3.0'else{}
            self.restore(role)
        history={'history_manifest_set_version':version,'fixture_base64':base64.b64encode(self.raw).decode(),'fixture_digest':digest_bytes(self.raw),
            'manifests':[{'role':role,'manifest_base64':base64.b64encode(canonical_bytes(self.manifests[role])).decode(),
                'manifest_digest':digest_bytes(canonical_bytes(self.manifests[role]))}for role in owner._ROLES]}
        if version=='3.0':history['predecessors']=[]
        self.history=history;self.configs={role:self.config(role)for role in owner._ROLES}
        self.runtime_boundaries=0;self.runtime_model_calls=0;self.native_calls=0;self.process_calls=0

    @staticmethod
    def write(path,raw):
        path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        path.write_bytes(raw);path.chmod(0o600)

    def original_files(self,record):
        run=self.evidence/'.phase'/'runs'/record['intent']['run_id']
        attempt=owner.original_attempt_document(type(record['admission']),record['admission'].raw,record['binding'].manifest_digest,
            intent=record['intent'],plan=record['plan'])
        result={run/'intent.json':canonical_bytes(record['intent']),run/'attachments'/'effect-plan.json':canonical_bytes(record['plan']),
            run/'attachments'/'pre-validator-results.json':canonical_bytes(record['pre']),
            run/'attachments'/'experimental-admission.json':record['admission'].raw,
            run/'attachments'/'experimental-attempt.json':canonical_bytes(attempt)}
        result.update({run/'blobs'/digest[7:]:body for digest,body in record['blobs'].items()})
        return result

    def marker_files(self,record):
        role=record['role'];scope,_path,scope_raw=self.scopes[role];members=record['request_literals']['members'];rows=[]
        logical=record['contract'].document['identity']['id']
        body=b'complete-original14-fixture\n'
        paths=members or['payload']
        for index,name in enumerate(paths):
            content=b''if name=='empty.bin'else(record['content']if not members else body)
            identity={'volume_serial':scope['root_identity']['volume_serial'],'file_id':format(0x100+index,'032x')}
            rows.append({'path':name,'length':len(content),'native_identity':identity,'state':{'native_identity':identity,
                'length':len(content),'attributes':32,'links':1,'creation_time':100,'write_time':101,'change_time':102}})
        context=SimpleNamespace(run_id=record['intent']['run_id'],installation_digest=record['binding'].manifest_digest,
            channel_id='1'*32,operation_nonce='2'*32)
        raw=input_stage._header(context,scope,role,digest_bytes(scope_raw),input_stage._stage_request(scope['scope_id'],'fixed-source',members),rows)
        digest=digest_bytes(raw);name='phase-native-input-'+digest[7:39];source=name+'/payload'+('/payload'if not members else'')
        marker_rows=[]
        if members:
            manifest=parse_json_bytes(record['content']);marker_rows=manifest['members']
        else:marker_rows=[{'path':'payload','length':len(record['content']),'digest':digest_bytes(record['content'])}]
        marker={'native_prepared_input_version':'1.0','header_digest':digest,'payload_kind':'bundle'if members else'file',
            'source_locator':source,'expected_digest':record['request_literals']['source_digest'],'expected_length':record['request_literals']['source_length'],
            'member_count':len(marker_rows),'total_length':sum(r['length']for r in marker_rows),'members':marker_rows,
            'source_header':parse_json_bytes(raw),'telemetry_stage':'PRE_RETURN_PREPARATION_DATA','final_acceptance':None}
        request=input_stage._staged_publication_request(role=role,prepared={'source_locator':source,'header_digest':digest,
            'expected_digest':marker['expected_digest'],'expected_length':marker['expected_length']},input_scope=scope['scope_id'],
            request_id=record['request_literals']['request_id'],target_locator=record['request_literals']['target_locator'],
            members=members,expected_current_digest=record['request_literals']['expected_current_digest'],content_utf8=record['request_literals']['content_utf8'])
        record['staged_request']=request;record['marker']=marker;record['marker_path']=self.preparation/name/'input-stage.json'
        # The marker is read by the genuine helper; consumed bytes are read
        # separately from the actual Original blobs. No producer is simulated.
        return {record['marker_path']:canonical_bytes(marker)}

    def restore(self,role):
        for path,raw in{**self.files[role],**self.stage_files[role]}.items():self.write(path,raw)
        scope,path,raw=self.scopes[role];self.write(path,raw)

    def config(self,role):
        hraw=canonical_bytes(self.history);launcher=self.scopes[role][1].parent/'launcher.py'
        return {'native_launch_version':self.version,'phase_wheel':'C:/source-model-never-opened/candidate.whl','phase_wheel_digest':self.doc['wheel_digest'],
            'dependency_file_digests':deepcopy(self.graph['linux']['dependency_file_digests']),
            'windows_launcher':'C:/source-model-never-opened/launcher.py','linux_launcher':str(launcher),
            'docker_executable':'C:/source-model-never-opened/docker.exe','core_container_id':'a'*64,'reader_container_id':'b'*64,
            'image_digest':'sha256:'+'c'*64,'linux_python':'/opt/phase/bin/python','expected_linux_contours':{},'artifact_graph':self.graph,
            'history_manifest_set_base64':base64.b64encode(hraw).decode(),'history_manifest_set_digest':digest_bytes(hraw)}

    def launch(self,role,request=None,config=None):
        record=self.records[role];config=self.configs[role]if config is None else config
        request=(record['staged_request']if self.version=='3.0'else{'operation':'execute'})if request is None else request
        invocation={'run_id':record['intent']['run_id'],'channel_id':'1'*32,'operation_nonce':'2'*32,'request':request}
        raw=canonical_bytes(config);obj=object.__new__(bootstrap._NativeAcceptedLaunch)
        def barrier(_self):self.runtime_boundaries+=1;raise RuntimeBoundary('NO_RUNTIME_ACCEPTANCE')
        with patch.object(bootstrap._NativeAcceptedLaunch,'check_runtime',barrier):
            try:bootstrap._NativeAcceptedLaunch.__init__(obj,config_bytes=raw,expected_config_digest=digest_bytes(raw),
                manifest_bytes=record['binding'].manifest_bytes,expected_manifest_digest=record['binding'].manifest_digest,
                invocation_bytes=canonical_bytes(invocation),_inspection_only=False,_experimental_admission_context=record['admission'])
            except RuntimeBoundary:pass
            else:raise AssertionError('Test must never return an actually accepted runtime')
        return obj

    def query(self,role,*,request=None):
        launch=self.launch(role,request=request);record=self.records[role]
        def runtime(_self):self.runtime_model_calls+=1
        def no_native(*a,**k):self.native_calls+=1;raise AssertionError('NativeIO forbidden')
        def no_process(*a,**k):self.process_calls+=1;raise AssertionError('Process/GO forbidden')
        with patch.object(bootstrap._NativeAcceptedLaunch,'check_runtime',runtime),patch.object(native.NativeIO,'__init__',no_native),\
            patch.object(subprocess,'run',no_process),patch.object(subprocess,'Popen',no_process):
            # SAME declared runtime-metadata model covers query composition
            # and endpoint; genuine cold-runtime enforcement stays unchanged.
            query=bootstrap._original_query_request(launch,'read_executing',record['intent_digest'])
            result=original_endpoint.native_original_query(launch,query)
        return result,query
