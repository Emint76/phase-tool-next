"""Real SDK metadata/argument invocation and six typed staging wire vectors.

Server.run and native staging/transport are modeled boundaries. No accepted
launch, worker, Native call or Phase execution is created by these tests.
"""
import asyncio,hashlib,os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.command_result import validate_command_result
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import bundle_recovery_mcp,input_stage,inspection_mcp
from phase_tool.mutation.ntfs.owner_semantic_contracts import semantic_owner_contract

ROLES=('File1','File2','Version1','Version2','Bundle1','Bundle2')
HEADER='sha256:'+'a'*64

def binary(role):
    word=hashlib.sha256(('phase-ntfs-qual-v1|110022|wire.'+role+'|0').encode()).digest()
    return word*2048

def vector(role):
    members=['empty.bin',*[('member-%02d.bin'%i if i%3==0 else'd/member-%02d.bin'%i if i%3==1 else'd/e/member-%02d.bin'%i)for i in range(16)]]if role.startswith('Bundle')else None
    if members:members=sorted(members,key=lambda v:v.encode())
    expected=digest_bytes(binary('File1'))if role=='Version1'else digest_bytes(binary('Version1'))if role=='Version2'else None
    content='A'*4096+'\n'if role=='Version2'else None
    if members:
        rows=[{'path':name,'length':0 if name=='empty.bin'else 65536,
            'digest':digest_bytes(b''if name=='empty.bin'else binary(role+name))}for name in members]
        payload=canonical_bytes({'bundle_version':'1.0','members':rows,'total_length':16*65536})
    else:payload=content.encode()if content is not None else binary(role)
    arguments={'run_id':'wire-'+role.lower(),'input_scope':'inputs.'+role.lower(),'source_locator':role.lower(),
        'target_locator':'current.bin'if role.startswith('Version')or role=='File1'else role.lower(),
        'request_id':'request-'+role.lower(),'members':members,'expected_current_digest':expected}
    return arguments,payload,content

class NativeInputMCPClosedSchemaTests(unittest.TestCase):
    def server(self,role='File1'):
        manifest=canonical_bytes({'contract':semantic_owner_contract(role)})
        with patch.object(inspection_mcp.FastMCP,'run',autospec=True)as run:
            inspection_mcp.run_native_input_mcp(config_bytes=b'',expected_config_digest=None,
                manifest_bytes=manifest,expected_manifest_digest=digest_bytes(manifest))
        run.assert_called_once();return run.call_args.args[0]

    def test_all_six_fixed_input_servers_have_exact_closed_tools(self):
        for role in ROLES:
            with self.subTest(role=role):
                tools=self.server(role)._tool_manager._tools
                expected={'phase_publish_input','phase_inspect'}
                if role in {'File1','File2'}:
                    expected.add('phase_publish_file')
                self.assertEqual(set(tools),expected)
                for tool in tools.values():
                    self.assertIs(tool.parameters['additionalProperties'],False)
                    self.assertEqual(tool.fn_metadata.arg_model.model_config['extra'],'forbid')
                self.assertEqual(set(tools['phase_publish_input'].parameters['properties']),
                    {'run_id','input_scope','source_locator','target_locator','request_id','members','expected_current_digest'})
                inspect_fields={'run_id','root_binding'} if role in {'File1','File2'} else {'run_id'}
                self.assertEqual(set(tools['phase_inspect'].parameters['properties']),inspect_fields)
                self.assertEqual(tools['phase_inspect'].parameters['required'],['run_id'])

    def test_actual_SDK_tool_invocation_preserves_six_typed_argument_sets(self):
        for role in ROLES:
            arguments,payload,content=vector(role);tool=self.server(role)._tool_manager._tools['phase_publish_input']
            with self.subTest(role=role),patch.object(inspection_mcp._InputScopeSession,'_invoke',return_value={'role':role})as invoke:
                actual=asyncio.run(tool.run(arguments))
                self.assertEqual(actual,{'role':role});invoke.assert_called_once_with('publish_input',arguments)

    def test_extra_selectors_fail_real_SDK_validation_before_owner_on_both_tools(self):
        for role in ROLES:
            tools=self.server(role)._tool_manager._tools;arguments,_,_=vector(role)
            for name in('registry','profile','contract','root_grants','provider','candidate','owner_directory_configuration','operation'):
                for tool_name,base in(('phase_publish_input',arguments),('phase_inspect',{'run_id':arguments['run_id']})):
                    with self.subTest(role=role,name=name,tool=tool_name),patch.object(inspection_mcp._InputScopeSession,'_invoke')as invoke:
                        with self.assertRaises(Exception):asyncio.run(tools[tool_name].run(dict(base,**{name:'foreign'})))
                        invoke.assert_not_called()

    def test_strict_types_and_unknown_run_selector_never_reach_owner(self):
        tools=self.server()._tool_manager._tools;arguments,_,_=vector('File1')
        for name,value in(('run_id',True),('input_scope',None),('source_locator',42),('target_locator',False),
                ('request_id',[]),('members','not-a-list'),('members',[1]),('expected_current_digest',10)):
            with self.subTest(field=name),patch.object(inspection_mcp._InputScopeSession,'_invoke')as invoke:
                with self.assertRaises(Exception):asyncio.run(tools['phase_publish_input'].run(dict(arguments,**{name:value})))
                invoke.assert_not_called()
        with patch.object(inspection_mcp._InputScopeSession,'_invoke')as invoke:
            with self.assertRaises(Exception):asyncio.run(tools['phase_inspect'].run({'run_id':1}))
            invoke.assert_not_called()

    def test_six_CLI_and_MCP_wires_share_genuine_candidate_and_staged_request(self):
        for role in ROLES:
            arguments,payload,content=vector(role)
            request={'operation':'publish_input',**{k:v for k,v in arguments.items()if k!='run_id'}}
            envelope={'run_id':arguments['run_id'],'request':request}
            with self.subTest(role=role):
                checked=inspection_mcp._native_input_cli_request(envelope);self.assertEqual(checked,arguments)
                candidate,raw=input_stage._publication_candidate(role,arguments['request_id'],arguments['target_locator'],
                    arguments['members'],arguments['expected_current_digest'],content)
                self.assertEqual(parse_json_bytes(raw),candidate)
                prepared={'header_digest':HEADER,'source_locator':'phase-native-input-'+HEADER[7:39]+'/payload'+(''if role.startswith('Bundle')else'/payload'),
                    'expected_digest':digest_bytes(payload),'expected_length':len(payload)}
                staged=input_stage._staged_publication_request(role=role,prepared=prepared,input_scope=arguments['input_scope'],
                    request_id=arguments['request_id'],target_locator=arguments['target_locator'],members=arguments['members'],
                    expected_current_digest=arguments['expected_current_digest'],content_utf8=content)
                self.assertEqual(staged['source_digest'],digest_bytes(payload));self.assertEqual(staged['source_length'],len(payload))
                self.assertEqual(staged['members'],arguments['members'])
                self.assertEqual(staged['expected_current_digest'],arguments['expected_current_digest'])
                for selector in('registry','profile','contract','root_grants','provider','candidate'):
                    bad={'run_id':arguments['run_id'],'request':dict(request,**{selector:'foreign'})}
                    with self.assertRaises(PhaseError):inspection_mcp._native_input_cli_request(bad)

    def test_six_genuine_v10_ACK_inspect_pairs_survive_shared_publication_owner(self):
        app=PhaseApplication()
        for role in ROLES:
            arguments,payload,content=vector(role);run=arguments['run_id']
            owner=inspection_mcp._InspectionMCPCallOwner(config_bytes=b'',expected_config_digest=None,
                manifest_bytes=canonical_bytes({'contract':semantic_owner_contract(role)}),expected_manifest_digest=None)
            prepared={'header_digest':HEADER,'source_locator':'phase-native-input-'+HEADER[7:39]+'/payload'+(''if role.startswith('Bundle')else'/payload'),
                'expected_digest':digest_bytes(payload),'expected_length':len(payload)}
            def command(operation):
                return PhaseApplication._command_payload(operation,success=True,run_id=run,terminal_status='succeeded_verified',
                    execution_disposition='executed',mutation_attempted=True,effect_plan_digest='sha256:'+'1'*64,
                    intent_digest='sha256:'+'2'*64,receipt_digest='sha256:'+'3'*64,target_verified=True if operation=='inspect'else None,
                    blockers=[],error=None,exit_code=0)
            ack,inspect=command('execute'),command('inspect')
            validate_command_result(ack,app.registry);validate_command_result(inspect,app.registry)
            with self.subTest(role=role),patch.object(input_stage,'os',SimpleNamespace(name='nt',getpid=os.getpid)),\
                    patch.object(input_stage,'run_windows_input_stage',return_value=(prepared,role,{},content)),\
                    patch.object(owner,'_call_locked',side_effect=[ack,inspect])as call:
                result=owner.publish_input(**arguments)
                self.assertIs(result['command_ack'],ack);self.assertIs(result['independent_inspection'],inspect)
                self.assertEqual(result['role'],role);self.assertEqual(result['source_digest'],digest_bytes(payload))
                self.assertEqual(call.call_count,2);self.assertFalse(owner._unavailable)
                self.assertEqual(call.call_args_list[0].args[1]['source_length'],len(payload))
                self.assertEqual(call.call_args_list[1].args[1],{'operation':'inspect'})

    def test_real_sdk_delivers_closed_file_refusals_and_retains_session(self):
        registry=PhaseApplication().registry
        for role,maximum in (('File1',1024**2),('File2',2*1024**3)):
            tool=self.server(role)._tool_manager._tools['phase_publish_input']
            arguments,_,_=vector(role)
            staged=input_stage._ClosedInputFileRefusal(role,maximum+1,maximum,registry)
            with self.subTest(role=role),patch.object(input_stage,'os',SimpleNamespace(name='nt',getpid=os.getpid)),\
                    patch.object(input_stage,'run_windows_input_stage',return_value=staged)as stage,\
                    patch.object(inspection_mcp._InspectionMCPCallOwner,'_call_locked')as dispatch:
                result=asyncio.run(tool.run(arguments))
                for key in ('run_id','input_scope','source_locator','target_locator','request_id'):
                    self.assertEqual(result[key],arguments[key])
                self.assertEqual(result['role'],role)
                self.assertEqual(result['source_length'],maximum+1)
                self.assertEqual(result['maximum_source_length'],maximum)
                self.assertEqual(result['exit_code'],10)
                self.assertIs(result['source_handles_closed'],True)
                self.assertIs(result['preparation_started'],False)
                self.assertIs(result['retry_authorized'],False)
                self.assertNotIn('command_ack',result)
                refusal=result['refusal']
                validate_command_result(refusal,registry)
                self.assertEqual(refusal['error'],'input_stage.member_bound')
                self.assertIsNone(refusal['run_id'])
                self.assertIsNone(refusal['receipt_digest'])
                self.assertIs(refusal['mutation_attempted'],False)
                dispatch.assert_not_called();stage.assert_called_once()
                self.assertFalse(tool.fn.__self__.unknown)
                self.assertEqual(tool.fn.__self__.held,[])

    def test_bare_member_bound_and_pending_execute_errors_keep_session_unknown(self):
        arguments,payload,_=vector('File2')
        staged={'header_digest':HEADER,'source_locator':'phase-native-input-'+HEADER[7:39]+'/payload/payload',
            'expected_digest':digest_bytes(payload),'expected_length':len(payload)}
        for stage_result in (PhaseError('input_stage.member_bound'),(staged,'File2',{},None)):
            startup=dict(config_bytes=b'',expected_config_digest=None,manifest_bytes=b'',expected_manifest_digest=None)
            session=inspection_mcp._InputScopeSession(**startup)
            if isinstance(stage_result,Exception):
                stage=patch.object(input_stage,'run_windows_input_stage',side_effect=stage_result)
            else:
                stage=patch.object(input_stage,'run_windows_input_stage',return_value=stage_result)
            with stage,patch.object(input_stage,'os',SimpleNamespace(name='nt',getpid=os.getpid)),\
                    patch.object(inspection_mcp._InspectionMCPCallOwner,'_call_locked',
                        side_effect=PhaseError('input_stage.member_bound'))as dispatch:
                with self.assertRaisesRegex(PhaseError,'input_stage.member_bound'):
                    session.publish_input(**arguments)
                self.assertEqual(dispatch.call_count,0 if isinstance(stage_result,Exception)else 1)
                self.assertTrue(session.unknown)
                self.assertEqual(len(session.held),1)
                with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_unavailable'):
                    session.inspect(arguments['run_id'])

    def test_other_existing_finite_servers_keep_closed_arguments(self):
        startup={'config_bytes':b'','expected_config_digest':None,'manifest_bytes':b'','expected_manifest_digest':None}
        for entry in(inspection_mcp.run_native_inspection_mcp,inspection_mcp.run_native_prepared_mcp,bundle_recovery_mcp.run_native_recovery_mcp):
            with self.subTest(entry=entry.__name__),patch.object(inspection_mcp.FastMCP,'run',autospec=True)as run:
                entry(**startup)
                server=run.call_args.args[0]
                for tool in server._tool_manager._tools.values():
                    self.assertIs(tool.parameters['additionalProperties'],False)
                    self.assertEqual(tool.fn_metadata.arg_model.model_config['extra'],'forbid')


if __name__=='__main__':unittest.main()
