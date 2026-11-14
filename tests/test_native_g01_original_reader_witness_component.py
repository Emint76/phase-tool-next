"""Pure coverage of the G01-only forwarding of actual Original closure fields."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch
import os
import threading

from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import g01_creation_handle_test as g01


class TestG01OriginalReaderWitness(TestCase):
    def owners(self):
        own=(os.getpid(),threading.get_ident())
        run="od2-a2c7cf61-4832-5958-9af4-e08d6593c679-g01-file1-00"
        case=run[4:40]
        installation="sha256:"+"a"*64
        token=g01._G01CreationHandleTest.__new__(g01._G01CreationHandleTest)
        launch=SimpleNamespace(run_id=run,operation_nonce="b"*32,installation_digest=installation,
            _config={"reader_container_id":"c"*64,"windows_launcher":str(Path.cwd()/"launcher.py")},
            _g01_original_reader=token)
        token._launch,token._owner,token._consumed=launch,own,False
        token._original_reader_attempted=False
        token._original_reader_intent=None
        token._deadline=10_000
        token._binding={"fixture_uuid":case,"role":"File1","repeat":0,"nonce":"d"*64,"case_started_ns":100}
        stream=SimpleNamespace(closed=True)
        process=SimpleNamespace(pid=37,returncode=0,_handle=SimpleNamespace(closed=True),
                                stdin=stream,stdout=stream,stderr=stream)
        witness=g01.WindowsProcessWitness.__new__(g01.WindowsProcessWitness)
        witness.process=process
        witness._owner=own
        witness._popen=True
        witness._handle_object=process._handle
        witness.pid,witness.creation_filetime=37,456
        methods=("GetProcessId","GetProcessTimes","WaitForSingleObject","GetExitCodeProcess","GetProcessId","GetProcessTimes")
        def fact(start):
            events=[{"api":api,"outcome":"returned","started_ns":start+2*i,"returned_ns":start+2*i+1,
                     "result":result,"winerror":0}
                    for i,(api,result) in enumerate(zip(methods,(37,1,0,1,37,1),strict=True))]
            return {"process_witness_version":"1.0","pid":37,"creation_filetime":456,"wait_result":0,
                "worker_exit_established":True,"exit_code":0,"scope":"this retained creation process handle only; not descendants or effect success",
                "events":events}
        first,closed=fact(150),fact(200)
        witness.events=first["events"]
        request={"native_original_query_version":"1.0","action":"read_executing","run_id":run,
                 "installation_digest":installation,"operation_nonce":launch.operation_nonce,"channel_id":"e"*32,
                 "intent_digest":"sha256:"+"f"*64}
        return token,launch,process,witness,request,first,closed

    def test_retains_two_complete_waits_after_exact_closure_once(self):
        token,launch,process,witness,request,first,closed=self.owners()
        with patch.object(g01.time,"perf_counter_ns",return_value=500),patch.object(g01,"_write_raw") as write:
            token._record_original_reader(launch,process,witness,request,first,closed)
            with self.assertRaises(PhaseError):
                token._record_original_reader(launch,process,witness,request,first,closed)
        path,record=write.call_args.args
        self.assertEqual(write.call_count,1)
        self.assertEqual(path.name,"g01-before-original-query-close.json")
        self.assertEqual(record["first_wait"],first)
        self.assertEqual(record["close_wait"],closed)
        self.assertEqual(record["request"],request)
        self.assertEqual(record["reader_container_id"],"c"*64)
        self.assertTrue(record["all_streams_closed"] and record["creation_handle_closed"])
        self.assertIsNone(record["final_acceptance"])
        self.assertEqual(record["qualification_credit"],0)
        self.assertEqual(token._original_reader_intent,request["intent_digest"])

    def test_refuses_wrong_process_open_handle_stream_and_failed_wait(self):
        for mode in ("foreign_process","open_handle","open_stream","pending_wait","foreign_pid","wrong_query",
                     "event_order","unattached","closed_late"):
            with self.subTest(mode=mode):
                token,launch,process,witness,request,first,closed=self.owners()
                now=500
                if mode=="foreign_process":
                    witness.process=SimpleNamespace()
                elif mode=="open_handle":
                    process._handle.closed=False
                elif mode=="open_stream":
                    process.stderr=SimpleNamespace(closed=False)
                elif mode=="pending_wait":
                    closed["wait_result"]=258
                elif mode=="foreign_pid":
                    first["pid"]=38
                elif mode=="wrong_query":
                    request["action"]="verify_no_dispatch"
                elif mode=="event_order":
                    closed=deepcopy(closed)
                    closed["events"][0]["started_ns"]=10
                elif mode=="unattached":
                    launch._g01_original_reader=None
                else:
                    now=token._deadline
                with patch.object(g01.time,"perf_counter_ns",return_value=now),patch.object(g01,"_write_raw") as write:
                    with self.assertRaises(PhaseError):
                        token._record_original_reader(launch,process,witness,request,first,closed)
                    write.assert_not_called()
                self.assertIsNone(token._original_reader_intent)

    def test_uncertain_first_write_does_not_authorize_a_second_write(self):
        token,launch,process,witness,request,first,closed=self.owners()
        with patch.object(g01.time,"perf_counter_ns",return_value=500),patch.object(g01,"_write_raw",side_effect=OSError) as write:
            with self.assertRaises(OSError):
                token._record_original_reader(launch,process,witness,request,first,closed)
            with self.assertRaises(PhaseError):
                token._record_original_reader(launch,process,witness,request,first,closed)
        self.assertEqual(write.call_count,1)
        self.assertIsNone(token._original_reader_intent)

    def test_a_write_that_finishes_after_case_budget_does_not_admit_worker(self):
        token,launch,process,witness,request,first,closed=self.owners()
        with patch.object(g01.time,"perf_counter_ns",side_effect=(500,token._deadline)),patch.object(g01,"_write_raw") as write:
            with self.assertRaises(PhaseError):
                token._record_original_reader(launch,process,witness,request,first,closed)
        self.assertEqual(write.call_count,1)
        self.assertIsNone(token._original_reader_intent)

    def test_exact_query_forwards_only_the_selected_successful_read_executing(self):
        from phase_tool.canonical import canonical_bytes
        from phase_tool.mutation.ntfs import bootstrap, process_witness, staged_dynamic_a05

        for mode in ("ordinary","g01","no_dispatch","failed_close","a05","both"):
            with self.subTest(mode=mode):
                token,launch,process,witness,request,first,closed=self.owners()
                stage=staged_dynamic_a05._StagedDynamicA05Test.__new__(staged_dynamic_a05._StagedDynamicA05Test)
                launch._g01_original_reader=token if mode in {"g01","no_dispatch","failed_close","both"} else None
                launch._staged_a05_reader=stage if mode in {"a05","both"} else None
                launch._inspection_only=False
                launch._original_query_attempted=False
                launch._version1=False
                launch._version2=False
                launch._windows_required=lambda:None
                launch._linux_command=lambda role:("fixed",role)
                launch._spawn=lambda _args:process
                launch.check_runtime=lambda:None
                calls=[]
                def finish(process_ref,pipe):
                    self.assertIs(process_ref,process)
                    self.assertIs(pipe,launch._pipe(process))
                    calls.append("closed")
                    if mode=="failed_close":
                        raise RuntimeError("unclosed")
                    return closed
                launch._finalize_exited=finish
                action="verify_no_dispatch" if mode=="no_dispatch" else "read_executing"
                selected=request|{"action":action}
                frame=canonical_bytes({"query":selected,"value":{"model":True},"required_evidence_reads_finalized":True})
                pipe=SimpleNamespace(send_frame=lambda *_args:None,receive_frame=lambda *_args:(frame,0))
                launch._pipe=lambda _process:pipe
                witness.wait_for_exit=lambda _ms:first
                with (patch.object(bootstrap,"_original_query_request",return_value=selected),
                      patch.object(process_witness,"WindowsProcessWitness",return_value=witness),
                      patch.object(g01._G01CreationHandleTest,"_record_original_reader") as g01_emit,
                      patch.object(staged_dynamic_a05._StagedDynamicA05Test,"_record_original_reader") as a05_emit):
                    if mode in {"failed_close","both"}:
                        with self.assertRaises((PhaseError,RuntimeError)):
                            bootstrap._NativeAcceptedLaunch._query_original(launch,action,request["intent_digest"])
                    else:
                        self.assertEqual(bootstrap._NativeAcceptedLaunch._query_original(launch,action,request["intent_digest"]),
                                         {"model":True})
                    if mode=="g01":
                        g01_emit.assert_called_once_with(launch,process,witness,selected,first,closed)
                        self.assertEqual(calls,["closed"])
                    else:
                        g01_emit.assert_not_called()
                    if mode=="a05":
                        a05_emit.assert_called_once_with(launch,selected,first)
                    else:
                        a05_emit.assert_not_called()
