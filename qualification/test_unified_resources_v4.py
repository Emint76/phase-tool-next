"""Small pure numeric/clock/binding models. No workload or system calls."""
import json,sys,time,unittest
from pathlib import Path
from dataclasses import replace
sys.path.insert(0,str(Path(__file__).absolute().parent))
import unified_resources_v4 as r
from resource_review_binding_v3 import load_reviewed_matrix,canonical,OWNER
from b08_resources import BUDGETS,CONTROL_BYTES

GRAPH='sha256:'+'3'*64
def plan(scenario='B01',bytes=1024,store='S',control=1):
    return r.Plan(scenario,'MIX','MIX_PREPARED','sha256:'+'a'*64,'sha256:'+'b'*64,1,1,
        (r.Charge('payload',store,bytes,bytes,bytes if store=='ext4'else 0,'EXPLICIT_MODEL_NOT_ACTUAL_FIXTURE'),),
        control,control_stores=(store,))
def matrix(*plans,mutate=None):
    rows=[]
    for p in plans:
        value={k:getattr(p,k)for k in('scenario','lane','frontend','manifest_digest','source_digest','attempts','max_writers','control_cap')}
        value.update(content_digest=p.binding,review_evidence_digests=['sha256:'+'1'*64,'sha256:'+'2'*64]);rows.append(value)
    doc=dict(resource_review_version='1.0',owner_instruction_digest=OWNER,source_graph_digest=GRAPH,plans=rows)
    if mutate:mutate(doc)
    raw=canonical(doc)
    return load_reviewed_matrix(raw,expected_digest=r.digest(doc),expected_source_graph=GRAPH)
def obs(seq=1,*,c=100*r.GIB,e=100*r.GIB,s=100*r.GIB,shared=False):
    now=time.monotonic_ns()
    return r.Observation(r.Sample(c,e,s,50*r.GIB),'C-vol','C-vol'if shared else'S-vol','E-fs','VHDX-file','C-vol',30*r.GIB,now-1_000_100,now-1_000_000,seq)
def fresh(old,**changes):
    # Explicit ordered model samples avoid dependence on Windows clock tick
    # granularity. All model times stay within the real two-second age bound.
    start=old.capture_end_ns+100
    assert start+100<=time.monotonic_ns()
    return replace(old,sequence=old.sequence+1,capture_start_ns=start,capture_end_ns=start+100,**changes)

class Policy(unittest.TestCase):
    def test_b08_formula_floors_exact(self):
        for lane,b in BUDGETS.items():
            p=r.Plan('B08',lane,'B08_LEGACY','sha256:'+'a'*64,'sha256:'+'b'*64,4,1,
                (r.Charge('guest','ext4',b.ext4_peak,b.ext4_peak,b.guest_allocations,'pinnedB08legacy'),
                 r.Charge('originals','S',b.s_peak,b.s_peak,0,'pinnedB08legacy')),CONTROL_BYTES)
            self.assertEqual(tuple(r.requirements(p,obs()).values()),tuple(x*r.GIB for x in b.floors))
    def test_coupling_and_alias_min_no_sum(self):
        p=replace(plan(bytes=2*r.GIB,store='ext4'),charges=(r.Charge('E','ext4',2*r.GIB,2*r.GIB,2*r.GIB,'model'),r.Charge('C','C',r.GIB,r.GIB,0,'model'),r.Charge('S','S',3*r.GIB,3*r.GIB,0,'model')),control_stores=r.STORES)
        floors=r.requirements(p,obs(shared=True));self.assertEqual(floors['C'],12*r.GIB)
        with self.assertRaises(r.ResourceStop):r.admit(p,replace(obs(shared=True),sample=r.Sample(50*r.GIB,50*r.GIB,11*r.GIB,50*r.GIB)),0,matrix=matrix(p))
    def test_same_pool_min_for_single_active_host_alias(self):
        for store in ('C','S'):
            p=plan(store=store);o=obs(shared=True)
            for sample in (replace(o.sample,c_free=0),replace(o.sample,s_free=0)):
                with self.assertRaises(r.ResourceStop):r.admit(p,replace(o,sample=sample),0,matrix=matrix(p))
            c=r.Controller(p,o,0,matrix=matrix(p))
            other='s_free' if store=='C' else 'c_free'
            with self.assertRaises(r.ResourceStop):c.observe(fresh(o,sample=replace(o.sample,**{other:0})))
    def test_no_unpriced_control_slack_on_data_store(self):
        p=replace(plan(bytes=r.MIB,control=10*r.MIB),control_stores=('C',));o=obs()
        c=r.Controller(p,o,0,matrix=matrix(p))
        with self.assertRaises(r.ResourceStop):c.observe(fresh(o,sample=replace(o.sample,s_free=o.sample.s_free-r.MIB-1)))
    def test_strict_campaign_cap_boundary(self):
        p=plan();m=matrix(p);left=r.CAMPAIGN_CAP-p.campaign_peak
        r.admit(p,obs(),left-1,matrix=m)
        with self.assertRaises(r.ResourceStop):r.admit(p,obs(),left,matrix=m)
    def test_no_guest_undercharge(self):
        p=replace(plan(),charges=(r.Charge('bad','ext4',10*r.GIB,0,0,'no justification'),))
        with self.assertRaises(r.ResourceStop):r.requirements(p,obs())
    def test_review_flags_do_not_change_content_or_admit(self):
        p=plan();q=replace(p,reviewed=True,review_digest='sha256:'+'z'*64)
        self.assertEqual(p.binding,q.binding)
        with self.assertRaises(r.ResourceStop):r.admit(q,obs(),0,matrix=None)
        r.admit(q,obs(),0,matrix=matrix(q))
    def test_matrix_bool_count_and_unknown_scenario(self):
        p=plan()
        with self.assertRaises(ValueError):matrix(p,mutate=lambda d:d['plans'][0].update(attempts=True))
        p=replace(p,scenario='UNKNOWN')
        with self.assertRaises(r.ResourceStop):r.admit(p,obs(),0,matrix=matrix(p))
    def test_sample_stale_future_duration_and_replay(self):
        p=plan();m=matrix(p);o=obs();now=time.monotonic_ns()
        for bad in(replace(o,capture_end_ns=now-3_000_000_000,capture_start_ns=now-3_000_000_001),replace(o,capture_end_ns=now+1_000_000_000),replace(o,capture_start_ns=now-6_000_000_001,capture_end_ns=now)):
            with self.assertRaises(r.ResourceStop):r.admit(p,bad,0,matrix=m)
        c=r.Controller(p,o,0,matrix=m)
        with self.assertRaises(r.ResourceStop):c.observe(o)
        self.assertTrue(c.stopped)
    def test_vhdx_physical_sparse_and_identity(self):
        p=plan(store='ext4');m=matrix(p);o=obs();c=r.Controller(p,o,0,matrix=m)
        with self.assertRaises(r.ResourceStop):c.observe(fresh(o,vhdx_allocated=o.vhdx_allocated+p.vhdx_growth+1))
        self.assertTrue(c.stopped)
        c=r.Controller(p,o,0,matrix=m)
        with self.assertRaises(r.ResourceStop):c.observe(fresh(o,vhdx_identity='different-file'))
    def test_epoch_unused_old_draw_cannot_finance_new_work(self):
        a=plan(bytes=20*r.MIB);b=plan('B02',bytes=1);m=matrix(a,b);o=obs();c=r.Controller(a,o,0,matrix=m)
        n=fresh(o);closed=r.Closure(a.binding,'sha256:'+'f'*64,n.capture_start_ns,True,True,True)
        c.next_work(b,n,retained_floor=0,metadata_bytes=0,closure=closed,matrix=m)
        with self.assertRaises(r.ResourceStop):c.observe(fresh(n,sample=replace(n.sample,s_free=n.sample.s_free-10*r.MIB)))
        self.assertTrue(c.stopped)
    def test_closure_cannot_predate_old_case(self):
        a=plan();b=plan('B02');m=matrix(a,b);o=obs();c=r.Controller(a,o,0,matrix=m);n=fresh(o)
        bad=r.Closure(a.binding,'sha256:'+'f'*64,o.capture_start_ns-1,True,True,True)
        with self.assertRaises(r.ResourceStop):c.next_work(b,n,retained_floor=0,metadata_bytes=0,closure=bad,matrix=m)
    def test_control_bound_and_unknown_always_latch(self):
        p=plan();o=obs();c=r.Controller(p,o,0,matrix=matrix(p))
        with self.assertRaises(r.ResourceStop):c.observe(fresh(o),metadata_bytes=2)
        self.assertTrue(c.unknown)
        c=r.Controller(p,o,0,matrix=matrix(p));c.unknown_outcome('actual driver unknown')
        with self.assertRaises(r.ResourceStop):c.observe(fresh(o))
    def test_retained_and_consumption_highwater_never_reset(self):
        p=plan(bytes=20*r.MIB);o=obs();c=r.Controller(p,o,10,matrix=matrix(p));n=fresh(o,sample=replace(o.sample,s_free=o.sample.s_free-r.MIB))
        c.observe(n,retained_floor=30);c.observe(fresh(n),retained_floor=12)
        self.assertEqual(c.retained_floor,30);self.assertEqual(c.draw_high[2],r.MIB)
    def test_optional_counter_is_not_complete_census(self):
        p=plan();o=obs();c=r.Controller(p,o,0,matrix=matrix(p))
        self.assertEqual(c.observe(fresh(o))['resource_observation'],'CAPACITY_SAMPLE_ONLY')
    def test_unused_store_needs_no_unrelated_reserve(self):
        p=replace(plan(store='C'),lane='REF',frontend='SOURCE_ONLY')
        o=obs(e=0,s=0);o=replace(o,ext4_identity='UNUSED',s_volume='UNUSED',vhdx_identity='UNUSED',vhdx_volume='UNUSED',vhdx_allocated=0,sample=replace(o.sample,vhdx_bytes=0))
        floors=r.requirements(p,o);self.assertEqual(floors['ext4'],0);self.assertEqual(floors['S'],0)
        r.admit(p,o,0,matrix=matrix(p))

if __name__=='__main__':unittest.main(verbosity=2)
