from __future__ import annotations

import random
from dataclasses import dataclass


TLB_ENTRY_COUNTS = (16, 32, 64, 128)


@dataclass(frozen=True)
class TlbConfig:
    entries: int
    assoc: int

    @property
    def sets(self) -> int:
        return self.entries // self.assoc

    def render(self) -> str:
        return f"{self.entries}:{self.assoc}"


@dataclass(frozen=True)
class TraceAccess:
    op: str
    address: int

    def render(self) -> str:
        return f"{self.op} 0x{self.address:08x}"


@dataclass
class TraceProgram:
    accesses: list[TraceAccess]
    tlb_config: TlbConfig | None = None

    def render(self) -> str:
        return "\n".join(access.render() for access in self.accesses) + "\n"

    def validate(self) -> list[str]:
        issues: list[str] = []
        if not self.accesses:
            issues.append("trace must contain at least one access")
        for index, access in enumerate(self.accesses):
            if access.op not in {"R", "W"}:
                issues.append(f"trace access {index} has invalid op: {access.op}")
            if not 0 <= access.address <= 0xFFFFFFFF:
                issues.append(f"trace access {index} address out of range: {access.address}")
        return issues

    def assert_valid(self) -> None:
        issues = self.validate()
        if issues:
            raise ValueError("; ".join(issues))


@dataclass
class TraceCoverage:
    tags: frozenset[str]
    access_count: int
    unique_pages: int
    read_count: int
    write_count: int
    tlb_config: TlbConfig

    def to_metadata(self) -> dict[str, object]:
        return {
            "tags": sorted(self.tags),
            "access_count": self.access_count,
            "unique_pages": self.unique_pages,
            "read_count": self.read_count,
            "write_count": self.write_count,
            "tlb_config": self.tlb_config.render(),
        }


@dataclass
class TraceGeneratorConfig:
    min_accesses: int = 1
    max_accesses: int = 256

    def __post_init__(self) -> None:
        if self.min_accesses < 1:
            raise ValueError("min_accesses must be positive")
        if self.max_accesses < self.min_accesses:
            raise ValueError("max_accesses must be >= min_accesses")


class TraceGenerator:
    def __init__(self, config: TraceGeneratorConfig | None = None) -> None:
        self.config = config or TraceGeneratorConfig()

    def pick_tlb_config(self, rng: random.Random) -> TlbConfig:
        entries = rng.choice(TLB_ENTRY_COUNTS)
        assoc_candidates = [1, 2, 4, 8, entries]
        assoc = rng.choice(tuple(dict.fromkeys(value for value in assoc_candidates if value <= entries)))
        return TlbConfig(entries=entries, assoc=assoc)

    def generate(self, seed: int, tlb_config: TlbConfig | None = None) -> TraceProgram:
        rng = random.Random(seed)
        cfg = tlb_config or self.pick_tlb_config(rng)
        length = rng.randint(self.config.min_accesses, self.config.max_accesses)
        profile = rng.choice(("locality", "conflict", "dirty", "fault_spread", "mixed"))
        accesses = self._seeded_prefix(rng, cfg, profile)

        while len(accesses) < length:
            accesses.append(self._next_access(rng, cfg, profile, accesses))

        trace = TraceProgram(accesses[:length], tlb_config=cfg)
        trace.assert_valid()
        return trace

    def collect_coverage(self, trace: TraceProgram, tlb_config: TlbConfig) -> TraceCoverage:
        pages = [access.address >> 12 for access in trace.accesses]
        tags = {
            f"tlb_entries:{tlb_config.entries}",
            f"tlb_assoc:{tlb_config.assoc}",
        }
        if tlb_config.entries == tlb_config.assoc:
            tags.add("tlb:fully_associative")
        if any(access.op == "R" for access in trace.accesses):
            tags.add("op:read")
        if any(access.op == "W" for access in trace.accesses):
            tags.add("op:write")
        if any(access.address & 0xFFF for access in trace.accesses):
            tags.add("offset:nonzero")
        if len(set(pages)) < len(pages):
            tags.add("page:reuse")
        if _has_read_then_write_same_page(trace.accesses):
            tags.add("dirty:read_then_write")
        if _has_set_conflict(pages, tlb_config.sets, tlb_config.assoc):
            tags.add("tlb:set_conflict")
        if len({page >> 10 for page in pages}) > 1:
            tags.add("l1:multiple_indexes")

        return TraceCoverage(
            tags=frozenset(tags),
            access_count=len(trace.accesses),
            unique_pages=len(set(pages)),
            read_count=sum(1 for access in trace.accesses if access.op == "R"),
            write_count=sum(1 for access in trace.accesses if access.op == "W"),
            tlb_config=tlb_config,
        )

    def _seeded_prefix(
        self, rng: random.Random, cfg: TlbConfig, profile: str
    ) -> list[TraceAccess]:
        base_page = rng.randrange(0, 1 << 20)
        accesses = [
            TraceAccess("R", _addr(base_page, 0)),
            TraceAccess("W", _addr(base_page, rng.randrange(0, 4096))),
        ]
        if profile in {"conflict", "mixed"}:
            accesses.extend(
                TraceAccess(rng.choice(("R", "W")), _addr(base_page + cfg.sets * i, 4 * i))
                for i in range(1, cfg.assoc + 2)
            )
        if profile in {"fault_spread", "mixed"}:
            accesses.extend(
                TraceAccess(rng.choice(("R", "W")), _addr((base_page + (i << 10)) & 0xFFFFF, i))
                for i in range(1, 4)
            )
        return accesses

    def _next_access(
        self,
        rng: random.Random,
        cfg: TlbConfig,
        profile: str,
        accesses: list[TraceAccess],
    ) -> TraceAccess:
        pages = [access.address >> 12 for access in accesses]
        if profile == "locality" and rng.random() < 0.8:
            page = rng.choice(pages)
        elif profile == "conflict" and rng.random() < 0.75:
            page = rng.choice(pages) + cfg.sets * rng.randint(1, cfg.assoc + 3)
        elif profile == "dirty" and rng.random() < 0.7:
            page = rng.choice(pages)
        elif profile == "fault_spread" and rng.random() < 0.65:
            page = (rng.randrange(0, 1024) << 10) | rng.randrange(0, 1024)
        elif profile == "mixed":
            page = self._mixed_page(rng, cfg, pages)
        else:
            page = rng.randrange(0, 1 << 20)

        page &= 0xFFFFF
        op = "W" if rng.random() < 0.45 else "R"
        offset = rng.randrange(0, 4096)
        return TraceAccess(op, _addr(page, offset))

    def _mixed_page(self, rng: random.Random, cfg: TlbConfig, pages: list[int]) -> int:
        choice = rng.random()
        if choice < 0.35:
            return rng.choice(pages)
        if choice < 0.65:
            return rng.choice(pages) + cfg.sets * rng.randint(1, cfg.assoc + 4)
        if choice < 0.85:
            return (rng.randrange(0, 1024) << 10) | rng.randrange(0, 1024)
        return rng.randrange(0, 1 << 20)


def _addr(page: int, offset: int) -> int:
    return ((page & 0xFFFFF) << 12) | (offset & 0xFFF)


def _has_read_then_write_same_page(accesses: list[TraceAccess]) -> bool:
    read_pages: set[int] = set()
    for access in accesses:
        page = access.address >> 12
        if access.op == "W" and page in read_pages:
            return True
        if access.op == "R":
            read_pages.add(page)
    return False


def _has_set_conflict(pages: list[int], sets: int, assoc: int) -> bool:
    by_set: dict[int, set[int]] = {}
    for page in pages:
        by_set.setdefault(page % sets, set()).add(page)
    return any(len(unique_pages) > assoc for unique_pages in by_set.values())
