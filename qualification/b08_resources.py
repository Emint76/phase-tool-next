"""Resource policy for B08 only. Byte counts are measured by the test runner."""

from dataclasses import dataclass

GIB = 1024**3
MIB = 1024**2
CAMPAIGN_CAP = 32 * GIB
RESERVE = 4 * GIB
CONTROL_BYTES = 256 * MIB
VHDX_HEADROOM = GIB


@dataclass(frozen=True)
class Sample:
    c_free: int
    ext4_free: int
    s_free: int
    vhdx_bytes: int


@dataclass(frozen=True)
class Budget:
    floors: tuple[int, int, int]
    ext4_peak: int
    s_peak: int
    guest_allocations: int

    @property
    def vhdx_growth(self) -> int:
        return self.guest_allocations + CONTROL_BYTES + VHDX_HEADROOM

    @property
    def campaign_peak(self) -> int:
        return self.ext4_peak + self.s_peak + CONTROL_BYTES


BUDGETS = {
    "REF": Budget((14, 13, 9), 8 * GIB, 4 * GIB + 1 + 2 * MIB + 1, 8 * GIB),
    "MIX": Budget((14, 11, 11), 6 * GIB + 1, 6 * GIB + 1 + 3 * MIB + 1, 8 * GIB + 1),
}
FILESYSTEMS = ("C:", "ext4", "S:")


def _free(sample: Sample) -> tuple[int, int, int]:
    values = (sample.c_free, sample.ext4_free, sample.s_free)
    if any(type(value) is not int or value < 0 for value in (*values, sample.vhdx_bytes)):
        raise ValueError("invalid B08 storage observation")
    return values


def admit(lane: str, sample: Sample, retained: int) -> None:
    """Require all three measured floors and an inclusive inventory of retained bytes."""
    budget = BUDGETS[lane]
    if type(retained) is not int or retained < 0:
        raise ValueError("invalid retained campaign byte count")
    if retained + budget.campaign_peak >= CAMPAIGN_CAP:
        raise ValueError("B08 peak reaches the 32 GiB campaign cap")
    for store, free, minimum in zip(FILESYSTEMS, _free(sample), budget.floors):
        if free < minimum * GIB:
            raise ValueError(f"B08 {lane} {store} below {minimum} GiB")


def monitor(lane: str, start: Sample, current: Sample) -> None:
    """Fail closed on reserve loss, excessive free-space draw or backing-file growth."""
    budget = BUDGETS[lane]
    current_free = _free(current)
    for store, free in zip(FILESYSTEMS, current_free):
        if free < RESERVE:
            raise ValueError(f"B08 {store} below the 4 GiB runtime reserve")
    if current.vhdx_bytes - start.vhdx_bytes > budget.vhdx_growth:
        raise ValueError("B08 Docker VHDX growth exceeds the planned bound")
    draw_limits = (budget.vhdx_growth + CONTROL_BYTES,
                   budget.ext4_peak + CONTROL_BYTES, budget.s_peak + CONTROL_BYTES)
    for store, initial, free, limit in zip(FILESYSTEMS, _free(start), current_free, draw_limits):
        if initial - free > limit:
            raise ValueError(f"B08 {store} free-space draw exceeds the planned bound")
