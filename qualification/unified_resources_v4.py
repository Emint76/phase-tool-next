"""One qualification storage gate; never a Phase operation/receipt authority.

Success means resource admission only. No process, deletion, Docker command,
runtime setting, retry, namespace or storage implementation exists here.
Plans must bind reviewed scenario/source/manifest/count facts outside opJSON.
"""
from dataclasses import dataclass,asdict
import hashlib,json,time
from resource_review_binding_v3 import ReviewedMatrix,hash_value
from b08_resources import Sample,_free,GIB,MIB,CAMPAIGN_CAP,RESERVE,VHDX_HEADROOM

STORES=('C','ext4','S')
PROGRAM_CASES=frozenset(prefix+str(i).zfill(2)for prefix,count in(('A',7),('B',8),('C',6),('D',9),('E',8),('F',9),('G',6),('R',12))for i in range(1,count+1))
LATER_CASES=frozenset({'SDK','INSTALL','ROLLBACK','ARCHIVE','SOURCE_PREPARATION','SOURCE_REVIEW','CI'})
FRONTENDS=frozenset({'REF_HOST','MIX_PREPARED','MIX_WINDOWS_INPUT','B08_LEGACY','SDK_ONLY','ARCHIVE_F4','ROLLBACK_INSTALLED','SOURCE_ONLY','CI_RESOURCE'})

class ResourceStop(ValueError):
    def __init__(self,code,details=None):
        super().__init__(code);self.code=code;self.details=details or {}

def need(value,code):
    if not value:raise ResourceStop(code)

def amount(value):
    need(type(value)is int and 0<=value<2**63,'resource.invalid_byte_bound');return value

def digest(value):
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    return 'sha256:'+hashlib.sha256(raw).hexdigest()

def ceil_gib(value):return ((amount(value)+GIB-1)//GIB)*GIB

@dataclass(frozen=True)
class Charge:
    """A distinct representation; stage-to-target rename is one charge.

    live_peak: maximum simultaneously present logical bytes of this object set.
    retained: upper retained bytes after this scenario, without cleanup credit.
    guest_writes: cumulative guest allocations, including successful temporary
    copies even when their existing context closes/unlinks them afterwards.
    Fault-only slack belongs to the bounded active failure set, not every
    successful operation. Exact immutable input reuse must be represented as
    already charged in the retained ledger, never a negative charge.
    """
    key:str
    store:str
    live_peak:int
    retained:int
    guest_writes:int
    basis:str
    def validate(self):
        need(type(self.key)is str and bool(self.key)and self.store in STORES,'resource.charge_identity')
        for n in(self.live_peak,self.retained,self.guest_writes):amount(n)
        need(self.retained<=self.live_peak and(self.guest_writes>=self.live_peak if self.store=='ext4'else self.guest_writes==0),
            'resource.charge_semantics')
        need(type(self.basis)is str and bool(self.basis),'resource.missing_copy_basis')

@dataclass(frozen=True)
class Plan:
    scenario:str
    lane:str
    frontend:str
    manifest_digest:str
    source_digest:str
    attempts:int
    max_writers:int
    charges:tuple[Charge,...]
    control_cap:int
    control_stores:tuple[str,...]=STORES
    vhdx_headroom:int=VHDX_HEADROOM
    reserve:int=RESERVE
    reviewed:bool=False
    review_digest:str=''
    def validate(self,*,admission=False):
        need(self.lane in{'REF','MIX'}and type(self.scenario)is str and bool(self.scenario)
            and type(self.frontend)is str and bool(self.frontend),'resource.unknown_scenario')
        need(type(self.attempts)is int and self.attempts>0 and type(self.max_writers)is int
            and 1<=self.max_writers<=8,'resource.invalid_workload_count')
        need(type(self.charges)is tuple and self.charges and len({c.key for c in self.charges})==len(self.charges),
            'resource.duplicate_representation')
        for c in self.charges:
            need(type(c)is Charge,'resource.closed_charge_required');c.validate()
        amount(self.control_cap);amount(self.vhdx_headroom)
        need(type(self.control_stores)is tuple and self.control_stores
            and len(set(self.control_stores))==len(self.control_stores)
            and all(store in STORES for store in self.control_stores),'resource.control_placement')
        need(self.reserve==RESERVE,'resource.runtime_reserve_changed')
        # Fixed metadata/data ceilings must be justified by each exact harness;
        # no wildcard small-case fallback and no zero proof/control assumption.
        need(self.control_cap>0,'resource.unpriced_control_evidence')
        for value in(self.manifest_digest,self.source_digest):
            need(type(value)is str and len(value)==71 and value.startswith('sha256:')
                and all(c in'0123456789abcdef'for c in value[7:]),'resource.unbound_plan')
        if admission:
            need(self.reviewed is True and type(self.review_digest)is str
                and len(self.review_digest)==71 and self.review_digest.startswith('sha256:'),
                'resource.independent_review_pending')
    @property
    def peak_by_store(self):
        self.validate();return {s:sum(c.live_peak for c in self.charges if c.store==s)for s in STORES}
    @property
    def guest_allocations(self):return sum(c.guest_writes for c in self.charges)
    @property
    def vhdx_growth(self):
        return self.guest_allocations+(self.control_cap if 'ext4'in self.control_stores else 0)+self.vhdx_headroom if self.uses_guest else 0
    @property
    def uses_guest(self):return any(c.store=='ext4'and c.live_peak for c in self.charges)or'ext4'in self.control_stores
    @property
    def active_stores(self):
        rows={c.store for c in self.charges if c.live_peak}|set(self.control_stores)
        if self.uses_guest:rows.add('C')
        return frozenset(rows)
    @property
    def campaign_peak(self):return sum(self.peak_by_store.values())+self.control_cap
    @property
    def retained_upper(self):return sum(c.retained for c in self.charges)+self.control_cap
    @property
    def binding(self):
        content=asdict(self);content.pop('reviewed');content.pop('review_digest')
        return digest(content)

@dataclass(frozen=True)
class Observation:
    sample:Sample
    c_volume:str
    s_volume:str
    ext4_identity:str
    vhdx_identity:str
    vhdx_volume:str
    vhdx_allocated:int
    capture_start_ns:int
    capture_end_ns:int
    sequence:int
    def validate(self):
        need(type(self.sample)is Sample,'resource.closed_sample_required');_free(self.sample)
        amount(self.vhdx_allocated)
        for text in(self.c_volume,self.s_volume,self.ext4_identity,self.vhdx_identity,self.vhdx_volume):
            need(type(text)is str and 0<len(text)<=4096,'resource.missing_storage_identity')
        need(self.vhdx_volume==self.c_volume or(self.vhdx_volume==self.vhdx_identity=='UNUSED'and self.vhdx_allocated==0
            and self.sample.vhdx_bytes==0),'resource.unverified_backing_pool')
        now=time.monotonic_ns()
        need(all(type(v)is int for v in(self.capture_start_ns,self.capture_end_ns,self.sequence))
            and self.sequence>0 and 0<self.capture_start_ns<=self.capture_end_ns<=now,'resource.invalid_sample_clock')
        need(self.capture_end_ns-self.capture_start_ns<=5_000_000_000,'resource.sample_duration')
        need(now-self.capture_end_ns<=2_000_000_000,'resource.stale_observation')
    @property
    def identities(self):
        return self.c_volume,self.s_volume,self.ext4_identity,self.vhdx_identity,self.vhdx_volume
    @property
    def same_host_pool(self):return self.c_volume==self.s_volume


def requirements(plan,observation,*,rounded=True):
    """C and ext4 are simultaneous constraints, never additive free capacity.

    One shared control cap is a whole-scenario allocation, not 3 copies. Every
    pool must be able to host its worst placement; campaign counts it once.
    A shared C/S volume sums both payload demands and uses min observed free.
    VHDX apparent and allocated growth are monitored independently of Cfree.
    """
    need(type(plan)is Plan and type(observation)is Observation,'resource.closed_types_required')
    plan.validate();observation.validate();peaks=plan.peak_by_store
    active=plan.active_stores;shared=observation.same_host_pool and 'S'in active and 'C'in active
    if plan.uses_guest:need(observation.vhdx_volume==observation.c_volume and observation.vhdx_identity!='UNUSED','resource.unverified_backing_pool')
    physical=peaks['C']+plan.vhdx_growth+(peaks['S']if shared else 0)
    c_control=plan.control_cap if 'C'in plan.control_stores or(shared and 'S'in plan.control_stores)else 0
    floors={'C':physical+c_control+plan.reserve if 'C'in active else 0,
        'ext4':peaks['ext4']+(plan.control_cap if 'ext4'in plan.control_stores else 0)+plan.reserve if 'ext4'in active else 0,
        'S':physical+c_control+plan.reserve if shared else peaks['S']+(plan.control_cap if 'S'in plan.control_stores else 0)+plan.reserve if 'S'in active else 0}
    return {key:ceil_gib(value)if rounded else value for key,value in floors.items()}

def admit(plan,observation,retained,*,matrix):
    need(type(matrix)is ReviewedMatrix,'resource.reviewed_matrix_required')
    plan.validate()
    need(plan.scenario in PROGRAM_CASES|LATER_CASES and plan.frontend in FRONTENDS,'resource.unknown_scenario')
    need(not(plan.frontend=='REF_HOST'and plan.lane!='REF')and not(plan.frontend.startswith('MIX_')and plan.lane!='MIX'),
        'resource.frontend_lane_mismatch')
    try:matrix.permit(plan)
    except BaseException as error:raise ResourceStop('resource.unreviewed_scenario')from error
    observation.validate();amount(retained)
    need(retained+plan.campaign_peak<CAMPAIGN_CAP,'resource.campaign_cap_reached')
    floors=requirements(plan,observation)
    c,e,s=_free(observation.sample)
    if observation.same_host_pool and plan.active_stores.intersection({'C','S'}):c=s=min(c,s)
    for store,free in zip(STORES,(c,e,s)):
        if free<floors[store]:raise ResourceStop('resource.free_floor',dict(store=store,free=free,required=floors[store]))
    return dict(resource_admitted=True,qualification_credit=0,plan_digest=plan.binding,
        floors=floors,retained=retained,peak=plan.campaign_peak,campaign_cap=CAMPAIGN_CAP)


@dataclass(frozen=True)
class Closure:
    """Caller-bound actual closure facts, not a resource-produced Phase proof.

    The trusted campaign driver validates real receipts/Originals/creation
    handles. Resource code cannot mint those facts or infer them from an exit.
    """
    previous_plan_digest:str
    evidence_digest:str
    ended_ns:int
    all_known:bool
    all_owned_handles_closed:bool
    all_required_proofs_complete:bool
    def validate(self,plan,current,previous_start):
        need(self.previous_plan_digest==plan.binding and hash_value(self.evidence_digest),
            'resource.closure_binding')
        need(self.all_known is True and self.all_owned_handles_closed is True
            and self.all_required_proofs_complete is True,'resource.closure_unknown')
        need(type(self.ended_ns)is int and previous_start.capture_end_ns<=self.ended_ns<=current.capture_start_ns,'resource.closure_order')

def _draw_limits(plan,shared):
    peak=plan.peak_by_store
    controls=plan.control_stores
    limits=[peak['C']+plan.vhdx_growth+(plan.control_cap if 'C'in controls else 0),
        peak['ext4']+(plan.control_cap if 'ext4'in controls else 0),
        peak['S']+(plan.control_cap if 'S'in controls else 0)]
    active=plan.active_stores
    limits=[limits[i]if store in active else 0 for i,store in enumerate(STORES)]
    if shared and 'C'in active and 'S'in active:
        host_control=plan.control_cap if 'C'in controls or 'S'in controls else 0
        limits[0]=limits[2]=peak['C']+plan.vhdx_growth+peak['S']+host_control
    return limits

class Controller:
    """Whole-scenario preflight plus B08 reserve/draw/VHDX monitoring.

    Every active writer's bounded pending allocation must be in that plan
    BEFORE first write. Polling detects pressure; it is not a filesystem quota
    or worker-exit proof. Stop means no new dispatch, preserve all outcomes.
    Unknowns latch permanently. Next scenario needs actual caller closure,
    full fresh resource admission and immutable reviewed plan bindings.
    """
    def __init__(self,plan,start,retained,*,matrix):
        self.admission=admit(plan,start,retained,matrix=matrix)
        self.plan=plan;self.origin=start;self.start=start;self.matrix=matrix
        self.retained_floor=retained;self.draw_high=[0,0,0];self.vhdx_high=0;self.allocated_high=0
        self.draw_limits=_draw_limits(plan,start.same_host_pool);self.vhdx_limit=plan.vhdx_growth
        self.last_sequence=start.sequence;self.last_capture_end=start.capture_end_ns
        self.seen_plans={plan.binding};self.stopped=False;self.stop_reason=None;self.unknown=False
    def _stop(self,error):
        self.stopped=True;self.unknown=True
        if self.stop_reason is None:self.stop_reason={'code':getattr(error,'code',str(error)),
            'details':getattr(error,'details',{})}
    def observe(self,current,*,retained_floor=None,metadata_bytes=None):
        try:
            need(not self.stopped,'resource.stop_latched')
            current.validate();need(current.identities==self.origin.identities,'resource.storage_identity_changed')
            need(current.sequence>self.last_sequence and current.capture_start_ns>=self.last_capture_end,
                'resource.replayed_observation')
            self.last_sequence=current.sequence;self.last_capture_end=current.capture_end_ns
            if retained_floor is not None:self.retained_floor=max(self.retained_floor,amount(retained_floor))
            need(self.retained_floor<CAMPAIGN_CAP,'resource.campaign_cap_reached')
            need(self.retained_floor<=self.admission['retained']+self.plan.retained_upper,'resource.retained_bound_exceeded')
            if metadata_bytes is not None:need(amount(metadata_bytes)<=self.plan.control_cap,'resource.control_bound_exceeded')
            current_free=list(_free(current.sample));initial_free=list(_free(self.origin.sample));epoch_initial=list(_free(self.start.sample))
            if current.same_host_pool and self.plan.active_stores.intersection({'C','S'}):
                current_free[0]=current_free[2]=min(current_free[0],current_free[2])
                initial_free[0]=initial_free[2]=min(initial_free[0],initial_free[2])
                epoch_initial[0]=epoch_initial[2]=min(epoch_initial[0],epoch_initial[2])
            for i,free in enumerate(current_free):
                if STORES[i]in self.plan.active_stores:need(free>=self.plan.reserve,'resource.runtime_reserve')
                self.draw_high[i]=max(self.draw_high[i],initial_free[i]-free,0)
            self.vhdx_high=max(self.vhdx_high,current.sample.vhdx_bytes-self.origin.sample.vhdx_bytes,0)
            self.allocated_high=max(self.allocated_high,current.vhdx_allocated-self.origin.vhdx_allocated,0)
            if self.plan.uses_guest:need(max(self.vhdx_high,self.allocated_high)<=self.vhdx_limit,'resource.vhdx_growth')
            for i,(draw,limit)in enumerate(zip(self.draw_high,self.draw_limits)):
                if STORES[i]in self.plan.active_stores:need(draw<=limit,'resource.free_draw')
            epoch_limits=_draw_limits(self.plan,current.same_host_pool)
            for i,limit in enumerate(epoch_limits):
                if STORES[i]in self.plan.active_stores:need(max(0,epoch_initial[i]-current_free[i])<=limit,'resource.epoch_free_draw')
            if self.plan.uses_guest:
                need(max(0,current.sample.vhdx_bytes-self.start.sample.vhdx_bytes,
                    current.vhdx_allocated-self.start.vhdx_allocated)<=self.plan.vhdx_growth,'resource.epoch_vhdx_growth')
        except BaseException as error:self._stop(error);raise
        complete=retained_floor is not None and metadata_bytes is not None
        return dict(resource_observation='CAPACITY_AND_RETAINED_COUNTER_SAMPLE'if complete else'CAPACITY_SAMPLE_ONLY',
            retained_census_supplied=retained_floor is not None,metadata_counter_supplied=metadata_bytes is not None,
            qualification_credit=0,draw_high=tuple(self.draw_high),vhdx_high=self.vhdx_high,allocated_high=self.allocated_high,
            retained_floor=self.retained_floor,allow_next_work=False)
    def next_work(self,plan,current,*,retained_floor,metadata_bytes,closure,matrix):
        try:
            need(type(closure)is Closure,'resource.closure_required')
            closure.validate(self.plan,current,self.start)
            self.observe(current,retained_floor=retained_floor,metadata_bytes=metadata_bytes)
            need(plan.binding not in self.seen_plans,'resource.same_plan_repeat_forbidden')
            admitted=admit(plan,current,self.retained_floor,matrix=matrix)
            # New exact finite epoch. Global high-water samples and all old
            # holdings survive; neither free increase nor VHDX shrink resets.
            limits=_draw_limits(plan,current.same_host_pool)
            self.draw_limits=[a+b for a,b in zip(self.draw_limits,limits)]
            self.vhdx_limit+=plan.vhdx_growth
            self.plan=plan;self.start=current;self.matrix=matrix;self.admission=admitted
            self.seen_plans.add(plan.binding)
            return admitted
        except BaseException as error:self._stop(error);raise
    def unknown_outcome(self,reason):
        self._stop(ResourceStop('resource.unknown_outcome',{'reason':str(reason)[:1024]}))
        return dict(action='STOP_NEW_WORK_PRESERVE_UNKNOWN',retry_authorized=False,qualification_credit=0)
