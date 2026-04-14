from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass, field
from itertools import combinations

from .model import (
    ALL_OPCODES,
    BRANCH_OPCODES,
    DATA_BASE_ADDRESS,
    DataLabel,
    Instruction,
    JUMP_OPCODES,
    MEMORY_OPCODES,
    NumberLiteral,
    Program,
    SHIFT_OPCODES,
    SIGNED_IMMEDIATE_OPCODES,
    THREE_REGISTER_OPCODES,
    TextLine,
)

FAMILY_WEIGHTS: dict[str, int] = {
    "alu": 40,
    "memory": 20,
    "branch": 12,
    "jump": 8,
    "pseudo": 10,
    "immediate": 10,
}

OPCODE_FAMILIES: dict[str, tuple[str, ...]] = {
    "alu": ("addu", "subu", "and", "or", "nor", "sltu", "sll", "srl"),
    "memory": ("lw", "sw"),
    "branch": ("beq", "bne"),
    "jump": ("j", "jal", "jr"),
    "pseudo": ("la",),
    "immediate": ("addiu", "andi", "ori", "sltiu", "lui"),
}

SIGNED_IMMEDIATE_TARGETS = frozenset(
    {"signed_imm:negative", "signed_imm:zero", "signed_imm:positive"}
)
UNSIGNED_IMMEDIATE_TARGETS = frozenset(
    {"unsigned_imm:zero", "unsigned_imm:max", "unsigned_imm:other"}
)
PAIRWISE_CATEGORIES: dict[str, tuple[str, ...]] = {
    "data": ("data:empty", "data:non_empty"),
    "word": ("word:single_value", "word:multi_value"),
    "branch": ("branch:forward", "branch:backward"),
    "memory": ("mem_offset:negative", "mem_offset:zero", "mem_offset:positive"),
    "la": ("la:one_word", "la:two_word"),
    "format": ("format:hex", "format:dec"),
    "jump": ("opcode:j", "opcode:jal", "opcode:jr"),
    "signed": tuple(sorted(SIGNED_IMMEDIATE_TARGETS)),
    "unsigned": tuple(sorted(UNSIGNED_IMMEDIATE_TARGETS)),
}
PAIRWISE_CATEGORY_ORDER = tuple(PAIRWISE_CATEGORIES)
INTERACTION_TARGET_SETS = (
    frozenset({"la:two_word", "branch:backward", "mem_offset:negative"}),
    frozenset({"opcode:jal", "opcode:jr", "branch:backward"}),
    # Dormant until multi-value `.word` fuzzing is re-enabled.
    # frozenset({"word:multi_value", "opcode:la", "opcode:lw"}),
    frozenset({"signed_imm:negative", "branch:backward", "opcode:j"}),
    frozenset({"data:empty", "opcode:jal", "opcode:jr"}),
)
PRIORITY_TRIPLE_TARGET_SETS = INTERACTION_TARGET_SETS
KNOWN_COVERAGE_TARGETS = frozenset(
    {f"opcode:{opcode}" for opcode in ALL_OPCODES}
    | {
        "data:empty",
        "data:non_empty",
        "word:single_value",
        "word:multi_value",
        "branch:forward",
        "branch:backward",
        "mem_offset:negative",
        "mem_offset:zero",
        "mem_offset:positive",
        "la:one_word",
        "la:two_word",
        "format:hex",
        "format:dec",
        "dest_reg:zero",
    }
    | SIGNED_IMMEDIATE_TARGETS
    | UNSIGNED_IMMEDIATE_TARGETS
)
SUPPORTED_COVERAGE_MODES = frozenset({"biased", "stratified", "coverage_first"})
SUPPORTED_COMPLEXITY_MODES = frozenset({"simple", "mixed", "hard"})


@dataclass
class GeneratorConfig:
    min_data_labels: int = 2
    max_data_labels: int = 5
    min_words_per_label: int = 1
    max_words_per_label: int = 4
    min_text_instructions: int = 8
    max_text_instructions: int = 24
    max_total_data_words: int = 0
    max_total_text_words: int = 0
    edge_case_probability: float = 0.35
    allow_empty_data: bool = False
    allow_multi_value_word: bool = False
    allow_negative_memory_offsets: bool = False
    allow_zero_dest_register: bool = False
    coverage_mode: str = "biased"
    coverage_targets: tuple[str, ...] = ()
    complexity_mode: str = "mixed"
    complexity_ramp_interval: int = 250
    use_small_exhaustive_first: bool = False
    max_generation_attempts: int = 48

    def __post_init__(self) -> None:
        if self.min_data_labels < 0 or self.max_data_labels < self.min_data_labels:
            raise ValueError("invalid data label bounds")
        if self.min_words_per_label < 1 or self.max_words_per_label < self.min_words_per_label:
            raise ValueError("invalid words-per-label bounds")
        if self.min_text_instructions < 1 or self.max_text_instructions < self.min_text_instructions:
            raise ValueError("invalid text instruction bounds")
        if self.max_total_data_words < 0 or self.max_total_text_words < 0:
            raise ValueError("total word limits must be non-negative")
        if self.coverage_mode not in SUPPORTED_COVERAGE_MODES:
            raise ValueError(f"unsupported coverage mode: {self.coverage_mode}")
        if self.complexity_mode not in SUPPORTED_COMPLEXITY_MODES:
            raise ValueError(f"unsupported complexity mode: {self.complexity_mode}")
        if self.complexity_ramp_interval < 1:
            raise ValueError("complexity_ramp_interval must be positive")
        # TA guidance for the current course setup: treat `.word` as a single-value directive.
        # Keep the multi-value machinery in place, but force the active generator path off.
        self.allow_multi_value_word = False
        normalized_targets = tuple(sorted({target for target in self.coverage_targets if target}))
        unknown_targets = [target for target in normalized_targets if target not in KNOWN_COVERAGE_TARGETS]
        if unknown_targets:
            joined = ", ".join(sorted(unknown_targets))
            raise ValueError(f"unknown coverage targets: {joined}")
        self.coverage_targets = normalized_targets
        # Dormant on purpose: the TA clarified grading assumes exactly one value per .word.
        # Keep the implementation paths around, but disable multi-value generation in active runs.
        self.allow_multi_value_word = False


@dataclass
class ProgramCoverage:
    tags: frozenset[str]
    pairwise_tags: frozenset[str] = field(default_factory=frozenset)
    triplewise_tags: frozenset[str] = field(default_factory=frozenset)
    priority_triple_tags: frozenset[str] = field(default_factory=frozenset)
    opcode_counts: Counter[str] = field(default_factory=Counter)
    data_label_count: int = 0
    data_word_count: int = 0
    text_instruction_count: int = 0
    complexity_tier: str = "unknown"
    generation_source: str = "random"

    def to_metadata(self) -> dict[str, object]:
        return {
            "tags": sorted(self.tags),
            "pairwise_tags": sorted(self.pairwise_tags),
            "triplewise_tags": sorted(self.triplewise_tags),
            "priority_triple_tags": sorted(self.priority_triple_tags),
            "opcode_counts": dict(sorted(self.opcode_counts.items())),
            "data_label_count": self.data_label_count,
            "data_word_count": self.data_word_count,
            "text_instruction_count": self.text_instruction_count,
            "complexity_tier": self.complexity_tier,
            "generation_source": self.generation_source,
        }


@dataclass(frozen=True)
class ExhaustiveRequest:
    preferred_targets: frozenset[str]
    complexity_tier: str
    source: str
    request_id: str


class CoverageTracker:
    def __init__(
        self,
        single_targets: set[str],
        pairwise_targets: set[str] | None = None,
        triplewise_targets: set[str] | None = None,
        priority_triple_targets: set[str] | None = None,
    ) -> None:
        self.single_targets = tuple(sorted(single_targets))
        self.pairwise_targets = tuple(sorted(pairwise_targets or set()))
        self.triplewise_targets = tuple(sorted(triplewise_targets or set()))
        self.priority_triple_targets = tuple(sorted(priority_triple_targets or set()))
        self.single_counts: Counter[str] = Counter()
        self.pair_counts: Counter[str] = Counter()
        self.triple_counts: Counter[str] = Counter()
        self.priority_triple_counts: Counter[str] = Counter()
        self.program_count = 0
        self.last_new_single_at = 0
        self.last_new_pair_at = 0
        self.last_new_triple_at = 0
        self.last_new_priority_triple_at = 0

    def observe(self, coverage: ProgramCoverage) -> None:
        self.program_count += 1
        for tag in self.single_targets:
            if tag in coverage.tags:
                if self.single_counts[tag] == 0:
                    self.last_new_single_at = self.program_count
                self.single_counts[tag] += 1
        for tag in self.pairwise_targets:
            if tag in coverage.pairwise_tags:
                if self.pair_counts[tag] == 0:
                    self.last_new_pair_at = self.program_count
                self.pair_counts[tag] += 1
        for tag in self.triplewise_targets:
            if tag in coverage.triplewise_tags:
                if self.triple_counts[tag] == 0:
                    self.last_new_triple_at = self.program_count
                self.triple_counts[tag] += 1
        for tag in self.priority_triple_targets:
            if tag in coverage.priority_triple_tags:
                if self.priority_triple_counts[tag] == 0:
                    self.last_new_priority_triple_at = self.program_count
                self.priority_triple_counts[tag] += 1

    def preferred_targets(self, mode: str) -> set[str]:
        if mode == "biased":
            return set()

        missing_single = [tag for tag in self.single_targets if self.single_counts[tag] == 0]
        if missing_single:
            return {missing_single[0]}

        missing_pair = [tag for tag in self.pairwise_targets if self.pair_counts[tag] == 0]
        missing_triple = [tag for tag in self.triplewise_targets if self.triple_counts[tag] == 0]
        missing_priority_triple = [
            tag for tag in self.priority_triple_targets if self.priority_triple_counts[tag] == 0
        ]
        if mode == "coverage_first" and missing_pair:
            return set(_pair_components(missing_pair[0]))
        if mode == "coverage_first" and missing_priority_triple:
            return set(_triple_components(missing_priority_triple[0]))
        if mode == "coverage_first" and missing_triple:
            return set(_triple_components(missing_triple[0]))

        ranked_single = sorted(self.single_targets, key=lambda tag: (self.single_counts[tag], tag))
        ranked_pair = sorted(self.pairwise_targets, key=lambda tag: (self.pair_counts[tag], tag))
        ranked_triple = sorted(self.triplewise_targets, key=lambda tag: (self.triple_counts[tag], tag))
        ranked_priority_triple = sorted(
            self.priority_triple_targets,
            key=lambda tag: (self.priority_triple_counts[tag], tag),
        )

        if ranked_priority_triple:
            if mode == "stratified":
                return set(_triple_components(ranked_priority_triple[0]))
            least_single = self.single_counts[ranked_single[0]] if ranked_single else 1 << 30
            least_pair = self.pair_counts[ranked_pair[0]] if ranked_pair else 1 << 30
            least_priority_triple = self.priority_triple_counts[ranked_priority_triple[0]]
            if least_priority_triple <= min(least_single, least_pair):
                return set(_triple_components(ranked_priority_triple[0]))

        if ranked_triple:
            if mode == "stratified":
                return set(_triple_components(ranked_triple[0]))
            least_single = self.single_counts[ranked_single[0]] if ranked_single else 1 << 30
            least_pair = self.pair_counts[ranked_pair[0]] if ranked_pair else 1 << 30
            least_triple = self.triple_counts[ranked_triple[0]]
            if least_triple <= min(least_single, least_pair):
                return set(_triple_components(ranked_triple[0]))

        if ranked_pair:
            if mode == "stratified":
                return set(_pair_components(ranked_pair[0]))
            least_single = self.single_counts[ranked_single[0]] if ranked_single else 1 << 30
            least_pair = self.pair_counts[ranked_pair[0]]
            if least_pair <= least_single:
                return set(_pair_components(ranked_pair[0]))

        if ranked_single:
            return {ranked_single[0]}
        return set()

    def summary(self, limit: int = 6) -> str:
        single_hit = sum(1 for tag in self.single_targets if self.single_counts[tag] > 0)
        single_missing = [tag for tag in self.single_targets if self.single_counts[tag] == 0]
        pair_hit = sum(1 for tag in self.pairwise_targets if self.pair_counts[tag] > 0)
        pair_missing = [tag for tag in self.pairwise_targets if self.pair_counts[tag] == 0]
        triple_hit = sum(1 for tag in self.triplewise_targets if self.triple_counts[tag] > 0)
        triple_missing = [tag for tag in self.triplewise_targets if self.triple_counts[tag] == 0]
        priority_triple_missing = [
            tag for tag in self.priority_triple_targets if self.priority_triple_counts[tag] == 0
        ]

        pieces = [f"single={single_hit}/{len(self.single_targets)}"]
        if self.pairwise_targets:
            pieces.append(f"pair={pair_hit}/{len(self.pairwise_targets)}")
        if self.triplewise_targets:
            pieces.append(f"triple={triple_hit}/{len(self.triplewise_targets)}")
        if self.priority_triple_targets:
            priority_hit = sum(
                1 for tag in self.priority_triple_targets if self.priority_triple_counts[tag] > 0
            )
            pieces.append(f"priority-triple={priority_hit}/{len(self.priority_triple_targets)}")
        if self.last_new_single_at:
            pieces.append(f"single-lag={self.program_count - self.last_new_single_at}")
        if self.last_new_pair_at:
            pieces.append(f"pair-lag={self.program_count - self.last_new_pair_at}")
        if self.last_new_triple_at:
            pieces.append(f"triple-lag={self.program_count - self.last_new_triple_at}")
        if self.last_new_priority_triple_at:
            pieces.append(
                f"priority-triple-lag={self.program_count - self.last_new_priority_triple_at}"
            )
        if single_missing:
            preview = ", ".join(single_missing[:limit])
            if len(single_missing) > limit:
                preview += ", ..."
            pieces.append(f"single-missing={preview}")
        elif pair_missing:
            preview = ", ".join(pair_missing[:limit])
            if len(pair_missing) > limit:
                preview += ", ..."
            pieces.append(f"pair-missing={preview}")
        elif triple_missing:
            preview = ", ".join(triple_missing[:limit])
            if len(triple_missing) > limit:
                preview += ", ..."
            pieces.append(f"triple-missing={preview}")
        elif priority_triple_missing:
            preview = ", ".join(priority_triple_missing[:limit])
            if len(priority_triple_missing) > limit:
                preview += ", ..."
            pieces.append(f"priority-triple-missing={preview}")
        else:
            pieces.append("all-targets-hit")
        return " ".join(pieces)


class SmallExhaustiveScheduler:
    def __init__(self, config: GeneratorConfig) -> None:
        self._requests = self._build_requests(config)
        self._index = 0

    def next_request(self) -> ExhaustiveRequest | None:
        if self._index >= len(self._requests):
            return None
        request = self._requests[self._index]
        self._index += 1
        return request

    def remaining(self) -> int:
        return len(self._requests) - self._index

    def _build_requests(self, config: GeneratorConfig) -> list[ExhaustiveRequest]:
        requests: list[ExhaustiveRequest] = []
        for tag in sorted(resolve_coverage_targets(config)):
            requests.append(
                ExhaustiveRequest(
                    preferred_targets=frozenset({tag}),
                    complexity_tier="simple",
                    source="small_exhaustive_single",
                    request_id=f"single:{tag}",
                )
            )
        for pair_tag in sorted(resolve_pairwise_targets(config)):
            requests.append(
                ExhaustiveRequest(
                    preferred_targets=frozenset(_pair_components(pair_tag)),
                    complexity_tier="medium",
                    source="small_exhaustive_pair",
                    request_id=f"pair:{pair_tag}",
                )
            )
        for triple_tag in sorted(resolve_triplewise_targets(config)):
            requests.append(
                ExhaustiveRequest(
                    preferred_targets=frozenset(_triple_components(triple_tag)),
                    complexity_tier="hard",
                    source="small_exhaustive_triple",
                    request_id=f"triple:{triple_tag}",
                )
            )
        for targets in resolve_interaction_target_sets(config):
            request_id = "interaction:" + ",".join(sorted(targets))
            requests.append(
                ExhaustiveRequest(
                    preferred_targets=targets,
                    complexity_tier="hard",
                    source="small_exhaustive_interaction",
                    request_id=request_id,
                )
            )
        return requests


@dataclass
class _GenerationContext:
    random: random.Random
    text_labels: list[str]
    label_positions: dict[str, int]
    data_labels: list[DataLabel]
    data_addresses: dict[str, int]
    preferred_targets: set[str]
    complexity_tier: str
    interaction_register: int | None = None
    interaction_data_label: str | None = None
    interaction_branch_label: str | None = None
    interaction_jump_label: str | None = None


class ProgramGenerator:
    def __init__(self, config: GeneratorConfig | None = None) -> None:
        self.config = config or GeneratorConfig()

    def generate(
        self,
        seed: int,
        preferred_targets: set[str] | None = None,
        complexity_tier: str | None = None,
    ) -> Program:
        rnd = random.Random(seed)
        preferred = set(preferred_targets or ())
        tier = complexity_tier or _default_complexity_tier(self.config.complexity_mode)
        attempts = 1 if not preferred else self.config.max_generation_attempts * max(1, len(preferred))
        best_program: Program | None = None
        best_score = -1

        for _ in range(attempts):
            program = self._generate_program(rnd, preferred, tier)
            program.assert_valid()
            if self.config.max_total_text_words > 0:
                if program.expanded_text_word_count() > self.config.max_total_text_words:
                    continue
            coverage = collect_program_coverage(program, complexity_tier=tier)
            score = len(preferred & coverage.tags)
            if score > best_score:
                best_program = program
                best_score = score
            if not preferred or preferred <= coverage.tags:
                return program

        if best_program is None:
            raise ValueError("unable to generate a valid program under current config")
        return best_program

    def _generate_program(
        self,
        rnd: random.Random,
        preferred_targets: set[str],
        complexity_tier: str,
    ) -> Program:
        data_label_count = self._choose_data_label_count(rnd, preferred_targets, complexity_tier)
        data_labels = self._generate_data_labels(rnd, data_label_count, preferred_targets, complexity_tier)
        opcode_plan = self._generate_opcode_plan(rnd, preferred_targets, bool(data_labels), complexity_tier)
        label_map = self._generate_text_label_map(rnd, len(opcode_plan), opcode_plan, complexity_tier)
        text_lines = [
            TextLine(labels=label_map.get(index, []))
            for index in range(len(opcode_plan))
        ]

        data_addresses = _data_addresses(data_labels)
        label_positions = {
            label: index
            for index, line in enumerate(text_lines)
            for label in line.labels
        }
        context = _GenerationContext(
            random=rnd,
            text_labels=[label for labels in label_map.values() for label in labels],
            label_positions=label_positions,
            data_labels=data_labels,
            data_addresses=data_addresses,
            preferred_targets=set(preferred_targets),
            complexity_tier=complexity_tier,
        )
        self._apply_interaction_plan(context)

        for index, opcode in enumerate(opcode_plan):
            text_lines[index].instruction = self._generate_instruction(context, index, opcode)

        return Program(data_labels=data_labels, text_lines=text_lines)

    def _apply_interaction_plan(self, context: _GenerationContext) -> None:
        if {"opcode:la", "opcode:lw", "word:multi_value"} <= context.preferred_targets:
            context.interaction_register = self._register(context.random, allow_zero=False)
            context.interaction_data_label = self._interaction_data_label(
                context,
                prefer_multi=True,
            )
        elif {"la:two_word", "mem_offset:negative"} & context.preferred_targets:
            context.interaction_register = self._register(context.random, allow_zero=False)
            context.interaction_data_label = self._interaction_data_label(
                context,
                prefer_multi=False,
            )

        if "branch:backward" in context.preferred_targets:
            backward_labels = [
                label for label, position in sorted(context.label_positions.items(), key=lambda item: item[1])
                if position == 0 or position < max(context.label_positions.values())
            ]
            if backward_labels:
                context.interaction_branch_label = backward_labels[0]

        if "opcode:jal" in context.preferred_targets:
            jump_labels = [
                label for label, position in sorted(context.label_positions.items(), key=lambda item: item[1])
                if position > 0
            ]
            if jump_labels:
                context.interaction_jump_label = jump_labels[-1]

    def _interaction_data_label(
        self,
        context: _GenerationContext,
        *,
        prefer_multi: bool,
    ) -> str | None:
        candidates = list(context.data_labels)
        if prefer_multi:
            multi_candidates = [
                data_label for data_label in candidates if any(group_size > 1 for group_size in data_label.word_groups)
            ]
            if multi_candidates:
                candidates = multi_candidates
        if "la:two_word" in context.preferred_targets:
            nonzero = [
                data_label
                for data_label in candidates
                if (context.data_addresses[data_label.name] & 0xFFFF) != 0
            ]
            if nonzero:
                candidates = nonzero
        return candidates[0].name if candidates else None

    def _choose_data_label_count(
        self, rnd: random.Random, preferred_targets: set[str], complexity_tier: str
    ) -> int:
        force_empty = "data:empty" in preferred_targets and self.config.allow_empty_data
        needs_data = bool(
            {
                "data:non_empty",
                "word:single_value",
                "word:multi_value",
                "la:one_word",
                "la:two_word",
                "opcode:la",
            }
            & preferred_targets
        )
        minimum = self.config.min_data_labels
        if self.config.allow_empty_data:
            minimum = 0
        if force_empty and not needs_data:
            return 0
        if "la:two_word" in preferred_targets or "word:multi_value" in preferred_targets:
            minimum = max(minimum, 1)
        if "la:two_word" in preferred_targets:
            minimum = max(minimum, 2)
        maximum = max(minimum, self.config.max_data_labels)
        return _choose_count_for_tier(rnd, minimum, maximum, complexity_tier)

    def _generate_data_labels(
        self,
        rnd: random.Random,
        count: int,
        preferred_targets: set[str],
        complexity_tier: str,
    ) -> list[DataLabel]:
        if count == 0:
            return []

        remaining_cap = self.config.max_total_data_words or None
        if remaining_cap is not None and remaining_cap < count:
            raise ValueError("max_total_data_words is too small for the requested label count")

        multi_value_index: int | None = None
        if self.config.allow_multi_value_word and count > 0:
            if "word:multi_value" in preferred_targets:
                multi_value_index = rnd.randrange(count)
            elif rnd.random() < 0.25:
                multi_value_index = rnd.randrange(count)

        labels: list[DataLabel] = []
        for index in range(count):
            remaining_labels = count - index
            minimum = self.config.min_words_per_label
            if multi_value_index == index:
                minimum = max(minimum, 2)
            maximum = self.config.max_words_per_label
            if remaining_cap is not None:
                maximum = min(maximum, remaining_cap - (remaining_labels - 1))
            if minimum > maximum:
                minimum = maximum
            word_count = _choose_count_for_tier(rnd, minimum, maximum, complexity_tier)
            if remaining_cap is not None:
                remaining_cap -= word_count
            words = [self._random_word(rnd) for _ in range(word_count)]
            word_groups = self._word_groups(
                rnd,
                word_count,
                force_multi=multi_value_index == index,
            )
            labels.append(
                DataLabel(
                    name=f"data_{index}",
                    words=words,
                    word_groups=word_groups,
                )
            )
        return labels

    def _generate_opcode_plan(
        self,
        rnd: random.Random,
        preferred_targets: set[str],
        has_data_labels: bool,
        complexity_tier: str,
    ) -> list[str]:
        required = self._required_opcodes(preferred_targets, has_data_labels)
        if complexity_tier == "medium":
            required.extend(
                opcode
                for opcode in ("beq", "jal", "addiu", "sll")
                if opcode in ALL_OPCODES and (opcode != "la" or has_data_labels)
            )
        elif complexity_tier == "hard":
            required.extend(
                opcode
                for opcode in ("beq", "bne", "jal", "jr", "lw", "sw", "addiu", "andi", "sll", "addu")
                if opcode in ALL_OPCODES and (opcode != "la" or has_data_labels)
            )
            if has_data_labels:
                required.append("la")
        required = _dedupe(required)

        minimum = max(self.config.min_text_instructions, len(required))
        if any(opcode in BRANCH_OPCODES | JUMP_OPCODES for opcode in required):
            minimum = max(minimum, 2)
        instruction_count = _choose_count_for_tier(
            rnd,
            minimum,
            self.config.max_text_instructions,
            complexity_tier,
        )

        allowed = sorted(ALL_OPCODES)
        if not has_data_labels:
            allowed = [opcode for opcode in allowed if opcode != "la"]

        plan: list[str | None] = [None] * instruction_count
        used_positions: set[int] = set()
        for opcode in required:
            position = self._pick_required_position(
                rnd,
                instruction_count,
                opcode,
                preferred_targets,
                used_positions,
                complexity_tier,
            )
            plan[position] = opcode
            used_positions.add(position)

        for index in range(instruction_count):
            if plan[index] is not None:
                continue
            plan[index] = self._random_opcode(rnd, allowed, complexity_tier)
        return [opcode for opcode in plan if opcode is not None]

    def _required_opcodes(
        self, preferred_targets: set[str], has_data_labels: bool
    ) -> list[str]:
        required: list[str] = []
        for target in sorted(preferred_targets):
            if target.startswith("opcode:"):
                opcode = target.split(":", 1)[1]
                if opcode == "la" and not has_data_labels:
                    continue
                required.append(opcode)
        if "branch:forward" in preferred_targets or "branch:backward" in preferred_targets:
            if not any(opcode in BRANCH_OPCODES for opcode in required):
                required.append("beq")
        if (
            {"mem_offset:negative", "mem_offset:zero", "mem_offset:positive"} & preferred_targets
            and not any(opcode in MEMORY_OPCODES for opcode in required)
        ):
            required.append("lw")
        if (
            {"la:one_word", "la:two_word"} & preferred_targets
            and has_data_labels
            and "la" not in required
        ):
            required.append("la")
        if SIGNED_IMMEDIATE_TARGETS & preferred_targets:
            if not any(opcode in SIGNED_IMMEDIATE_OPCODES for opcode in required):
                required.append("addiu")
        if UNSIGNED_IMMEDIATE_TARGETS & preferred_targets:
            if not any(opcode in {"andi", "ori", "lui", "sll", "srl"} for opcode in required):
                required.append("andi")
        if "dest_reg:zero" in preferred_targets and not any(
            opcode in THREE_REGISTER_OPCODES
            | SHIFT_OPCODES
            | SIGNED_IMMEDIATE_OPCODES
            | {"andi", "ori", "lui", "lw", "la"}
            for opcode in required
        ):
            required.append("addiu")
        if {"format:hex", "format:dec"} & preferred_targets and not any(
            opcode in SHIFT_OPCODES
            | SIGNED_IMMEDIATE_OPCODES
            | {"andi", "ori", "lui", "lw", "sw"}
            for opcode in required
        ):
            required.append("addiu")
        return required

    def _pick_required_position(
        self,
        rnd: random.Random,
        instruction_count: int,
        opcode: str,
        preferred_targets: set[str],
        used_positions: set[int],
        complexity_tier: str,
    ) -> int:
        del complexity_tier
        candidates = [index for index in range(instruction_count) if index not in used_positions]
        if opcode in BRANCH_OPCODES and "branch:backward" in preferred_targets:
            constrained = [index for index in candidates if index > 0]
            if constrained:
                candidates = constrained
        if opcode in BRANCH_OPCODES and "branch:forward" in preferred_targets:
            constrained = [index for index in candidates if index < instruction_count - 1]
            if constrained:
                candidates = constrained
        if opcode == "jr":
            constrained = [index for index in candidates if index > 0]
            if constrained:
                candidates = constrained
        return rnd.choice(candidates)

    def _generate_text_label_map(
        self,
        rnd: random.Random,
        instruction_count: int,
        opcode_plan: list[str],
        complexity_tier: str,
    ) -> dict[int, list[str]]:
        if instruction_count == 0:
            return {}

        needs_labels = any(opcode in BRANCH_OPCODES | JUMP_OPCODES for opcode in opcode_plan)
        positions: set[int] = set()
        if needs_labels:
            positions.add(0)
            positions.add(instruction_count - 1)
        elif complexity_tier != "simple" and rnd.random() < 0.6:
            positions.add(0)

        if complexity_tier == "simple":
            max_labels = max(1, instruction_count // 4)
        elif complexity_tier == "hard":
            max_labels = max(2, instruction_count // 2)
        else:
            max_labels = max(1, instruction_count // 3)
        target_count = rnd.randint(len(positions), max(len(positions), max_labels))
        while len(positions) < target_count:
            positions.add(rnd.randrange(instruction_count))
        label_map: dict[int, list[str]] = {}
        for index, position in enumerate(sorted(positions)):
            label_map.setdefault(position, []).append(f"text_{index}")
        return label_map

    def _generate_instruction(
        self, context: _GenerationContext, index: int, opcode: str
    ) -> Instruction:
        if opcode in THREE_REGISTER_OPCODES:
            rd = self._destination_register(context.random, context.preferred_targets)
            rs = self._register(context.random)
            rt = self._register(context.random)
            return Instruction(opcode=opcode, operands=(rd, rs, rt))

        if opcode in SHIFT_OPCODES:
            rd = self._destination_register(context.random, context.preferred_targets)
            rt = self._register(context.random)
            shamt = self._unsigned_literal(
                context.random,
                5,
                context.preferred_targets,
            )
            return Instruction(opcode=opcode, operands=(rd, rt, shamt))

        if opcode in SIGNED_IMMEDIATE_OPCODES:
            rt = self._destination_register(context.random, context.preferred_targets)
            rs = self._register(context.random)
            immediate = self._signed_literal(
                context.random,
                16,
                context.preferred_targets,
            )
            return Instruction(opcode=opcode, operands=(rt, rs, immediate))

        if opcode in {"andi", "ori"}:
            rt = self._destination_register(context.random, context.preferred_targets)
            rs = self._register(context.random)
            immediate = self._unsigned_literal(
                context.random,
                16,
                context.preferred_targets,
            )
            return Instruction(opcode=opcode, operands=(rt, rs, immediate))

        if opcode == "lui":
            rt = self._destination_register(context.random, context.preferred_targets)
            immediate = self._unsigned_literal(
                context.random,
                16,
                context.preferred_targets,
            )
            return Instruction(opcode=opcode, operands=(rt, immediate))

        if opcode in MEMORY_OPCODES:
            rt = self._destination_register(
                context.random,
                context.preferred_targets,
                allow_zero_default=False,
            )
            offset = self._memory_offset(
                context.random,
                context.preferred_targets,
                context.complexity_tier,
            )
            if context.interaction_register is not None and context.interaction_data_label is not None:
                base = context.interaction_register
                if "word:multi_value" in context.preferred_targets and "mem_offset:negative" not in context.preferred_targets:
                    label_words = next(
                        len(data_label.words)
                        for data_label in context.data_labels
                        if data_label.name == context.interaction_data_label
                    )
                    max_offset = max(0, (label_words - 1) * 4)
                    offset_value = min(int(offset.value), max_offset)
                    offset = NumberLiteral(
                        value=offset_value,
                        prefer_hex=offset.prefer_hex,
                        bit_width=offset.bit_width,
                    )
            else:
                base = self._register(context.random)
            return Instruction(opcode=opcode, operands=(rt, offset, base))

        if opcode in BRANCH_OPCODES:
            rs = self._register(context.random)
            rt = self._register(context.random)
            label = context.interaction_branch_label or self._branch_target(context, index)
            return Instruction(opcode=opcode, operands=(rs, rt, label))

        if opcode in JUMP_OPCODES:
            if opcode == "jal" and context.interaction_jump_label is not None:
                label = context.interaction_jump_label
            else:
                label = self._jump_target(context, index)
            return Instruction(opcode=opcode, operands=(label,))

        if opcode == "jr":
            if "opcode:jal" in context.preferred_targets or context.complexity_tier == "hard":
                return Instruction(opcode=opcode, operands=(31,))
            if context.random.random() < 0.6:
                return Instruction(opcode=opcode, operands=(31,))
            return Instruction(opcode=opcode, operands=(self._register(context.random),))

        if opcode == "la":
            if context.interaction_register is not None:
                rd = context.interaction_register
            else:
                rd = self._destination_register(
                    context.random,
                    context.preferred_targets,
                    allow_zero_default=False,
                )
            if context.interaction_data_label is not None:
                label = context.interaction_data_label
            else:
                label = self._la_target(
                    context.random,
                    context.data_labels,
                    context.data_addresses,
                    context.preferred_targets,
                )
            return Instruction(opcode=opcode, operands=(rd, label))

        raise ValueError(f"unsupported opcode: {opcode}")

    def _random_opcode(
        self, rnd: random.Random, allowed_opcodes: list[str], complexity_tier: str
    ) -> str:
        if self.config.coverage_mode == "biased":
            family_weights = dict(FAMILY_WEIGHTS)
            if complexity_tier == "simple":
                family_weights["jump"] = 4
                family_weights["branch"] = 8
            elif complexity_tier == "hard":
                family_weights["memory"] = 26
                family_weights["branch"] = 18
                family_weights["jump"] = 14
                family_weights["immediate"] = 14
            available_families = [
                family
                for family, members in OPCODE_FAMILIES.items()
                if any(opcode in allowed_opcodes for opcode in members)
            ]
            total = sum(family_weights[family] for family in available_families)
            value = rnd.uniform(0, total)
            upto = 0.0
            for family in available_families:
                upto += family_weights[family]
                if value <= upto:
                    family_opcodes = [opcode for opcode in OPCODE_FAMILIES[family] if opcode in allowed_opcodes]
                    return rnd.choice(family_opcodes)
        return rnd.choice(allowed_opcodes)

    def _destination_register(
        self,
        rnd: random.Random,
        preferred_targets: set[str],
        allow_zero_default: bool | None = None,
    ) -> int:
        if self.config.allow_zero_dest_register and "dest_reg:zero" in preferred_targets:
            return 0
        allow_zero = self.config.allow_zero_dest_register if allow_zero_default is None else allow_zero_default
        return self._register(rnd, allow_zero=allow_zero)

    def _memory_offset(
        self,
        rnd: random.Random,
        preferred_targets: set[str],
        complexity_tier: str,
    ) -> NumberLiteral:
        preferred_class = None
        for tag, offset_class in (
            ("mem_offset:negative", "negative"),
            ("mem_offset:zero", "zero"),
            ("mem_offset:positive", "positive"),
        ):
            if tag in preferred_targets:
                preferred_class = offset_class
                break

        if complexity_tier == "hard" and self.config.allow_negative_memory_offsets:
            classes = ["negative", "zero", "positive", "positive"]
        else:
            classes = ["zero", "positive"]
            if self.config.allow_negative_memory_offsets:
                classes.append("negative")
        offset_class = preferred_class or rnd.choice(classes)
        if offset_class == "negative" and self.config.allow_negative_memory_offsets:
            magnitude = 4 * rnd.randint(1, 8)
            value = -magnitude
        elif offset_class == "zero":
            value = 0
        else:
            value = 4 * rnd.randint(1 if complexity_tier == "hard" else 0, 8)

        prefer_hex = self._preferred_format(rnd, preferred_targets, default_probability=0.3)
        return NumberLiteral(value=value, prefer_hex=prefer_hex, bit_width=16)

    def _branch_target(self, context: _GenerationContext, index: int) -> str:
        positions = context.label_positions
        if not positions:
            return f"text_{index}"
        if "branch:backward" in context.preferred_targets:
            choices = [label for label, position in positions.items() if position < index]
            if choices:
                return context.random.choice(choices)
        if "branch:forward" in context.preferred_targets:
            choices = [label for label, position in positions.items() if position > index]
            if choices:
                return context.random.choice(choices)
        choices = [label for label, position in positions.items() if position != index]
        if choices:
            return context.random.choice(choices)
        return context.random.choice(context.text_labels)

    def _jump_target(self, context: _GenerationContext, index: int) -> str:
        choices = [label for label, position in context.label_positions.items() if position != index]
        if choices:
            return context.random.choice(choices)
        if context.text_labels:
            return context.random.choice(context.text_labels)
        return "text_0"

    def _la_target(
        self,
        rnd: random.Random,
        data_labels: list[DataLabel],
        data_addresses: dict[str, int],
        preferred_targets: set[str],
    ) -> str:
        if not data_labels:
            raise ValueError("la requires at least one data label")
        zero_lower = [
            data_label.name
            for data_label in data_labels
            if (data_addresses[data_label.name] & 0xFFFF) == 0
        ]
        nonzero_lower = [
            data_label.name
            for data_label in data_labels
            if (data_addresses[data_label.name] & 0xFFFF) != 0
        ]
        if "la:one_word" in preferred_targets and zero_lower:
            return rnd.choice(zero_lower)
        if "la:two_word" in preferred_targets and nonzero_lower:
            return rnd.choice(nonzero_lower)
        choices = zero_lower + nonzero_lower
        return rnd.choice(choices)

    def _random_word(self, rnd: random.Random) -> NumberLiteral:
        edge_values = [0, 1, -1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
        use_edge = rnd.random() < self.config.edge_case_probability
        if use_edge:
            value = rnd.choice(edge_values)
        elif rnd.random() < 0.5:
            value = rnd.randint(-(1 << 31), (1 << 31) - 1)
        else:
            value = rnd.randint(0, (1 << 32) - 1)
        prefer_hex = value < 0 or value > (1 << 31) - 1 or rnd.random() < 0.5
        return NumberLiteral(value=value, prefer_hex=prefer_hex, bit_width=32)

    def _signed_literal(
        self,
        rnd: random.Random,
        bits: int,
        preferred_targets: set[str],
    ) -> NumberLiteral:
        minimum = -(1 << (bits - 1))
        maximum = (1 << (bits - 1)) - 1
        preferred_class = None
        if "signed_imm:negative" in preferred_targets:
            preferred_class = "negative"
        elif "signed_imm:zero" in preferred_targets:
            preferred_class = "zero"
        elif "signed_imm:positive" in preferred_targets:
            preferred_class = "positive"

        if preferred_class == "negative":
            value = rnd.randint(minimum, -1)
        elif preferred_class == "zero":
            value = 0
        elif preferred_class == "positive":
            value = rnd.randint(1, maximum)
        else:
            edge_values = [minimum, -1, 0, 1, maximum]
            if rnd.random() < self.config.edge_case_probability:
                value = rnd.choice(edge_values)
            else:
                value = rnd.randint(minimum, maximum)

        prefer_hex = self._preferred_format(
            rnd,
            preferred_targets,
            default_probability=0.45 if value >= 0 else 0.0,
        )
        return NumberLiteral(value=value, prefer_hex=prefer_hex, bit_width=bits)

    def _unsigned_literal(
        self,
        rnd: random.Random,
        bits: int,
        preferred_targets: set[str],
    ) -> NumberLiteral:
        maximum = (1 << bits) - 1
        preferred_class = None
        if "unsigned_imm:zero" in preferred_targets:
            preferred_class = "zero"
        elif "unsigned_imm:max" in preferred_targets:
            preferred_class = "max"
        elif "unsigned_imm:other" in preferred_targets:
            preferred_class = "other"

        if preferred_class == "zero":
            value = 0
        elif preferred_class == "max":
            value = maximum
        elif preferred_class == "other":
            candidates = [value for value in (1, 4, maximum // 2) if 0 < value < maximum]
            value = rnd.choice(candidates) if candidates else 0
        else:
            edge_values = [0, 1, 4, maximum]
            if rnd.random() < self.config.edge_case_probability:
                value = rnd.choice(edge_values)
            else:
                value = rnd.randint(0, maximum)

        prefer_hex = self._preferred_format(
            rnd,
            preferred_targets,
            default_probability=0.65,
        )
        return NumberLiteral(value=value, prefer_hex=prefer_hex, bit_width=bits)

    def _preferred_format(
        self,
        rnd: random.Random,
        preferred_targets: set[str],
        default_probability: float,
    ) -> bool:
        if "format:hex" in preferred_targets:
            return True
        if "format:dec" in preferred_targets:
            return False
        return rnd.random() < default_probability

    def _register(self, rnd: random.Random, allow_zero: bool = True) -> int:
        if allow_zero:
            return rnd.randint(0, 31)
        return rnd.randint(1, 31)

    def _word_groups(
        self, rnd: random.Random, word_count: int, force_multi: bool
    ) -> tuple[int, ...]:
        if word_count <= 1 or not self.config.allow_multi_value_word:
            return ()
        if not force_multi and rnd.random() >= 0.35:
            return ()

        remaining = word_count
        groups: list[int] = []
        while remaining > 0:
            if force_multi and not groups:
                group_size = rnd.randint(2, remaining) if remaining > 1 else 1
            else:
                group_size = rnd.randint(1, remaining)
            groups.append(group_size)
            remaining -= group_size

        if max(groups) == 1:
            groups[0] = min(word_count, 2)
            groups[1:] = [1] * (word_count - groups[0])
        return tuple(groups)


def collect_program_coverage(
    program: Program,
    *,
    complexity_tier: str | None = None,
    generation_source: str = "random",
) -> ProgramCoverage:
    tags: set[str] = set()
    opcode_counts: Counter[str] = Counter()
    data_word_count = sum(len(data_label.words) for data_label in program.data_labels)
    text_instruction_count = sum(
        1 for line in program.text_lines if line.instruction is not None
    )

    if program.data_labels:
        tags.add("data:non_empty")
        multi_value_word = any(
            any(group_size > 1 for group_size in data_label.word_groups)
            for data_label in program.data_labels
        )
        tags.add("word:multi_value" if multi_value_word else "word:single_value")
    else:
        tags.add("data:empty")

    data_addresses = program.data_addresses()
    label_positions = {
        label: index
        for index, line in enumerate(program.text_lines)
        for label in line.labels
    }

    for data_label in program.data_labels:
        for word in data_label.words:
            tags.add("format:hex" if word.prefer_hex else "format:dec")

    for index, line in enumerate(program.text_lines):
        instruction = line.instruction
        if instruction is None:
            continue
        opcode = instruction.opcode
        opcode_counts[opcode] += 1
        tags.add(f"opcode:{opcode}")

        if 0 in instruction.written_registers():
            tags.add("dest_reg:zero")

        for operand in instruction.operands:
            if isinstance(operand, NumberLiteral):
                tags.add("format:hex" if operand.prefer_hex else "format:dec")

        if opcode in SIGNED_IMMEDIATE_OPCODES:
            immediate = instruction.operands[2]
            value = int(immediate.value)
            if value < 0:
                tags.add("signed_imm:negative")
            elif value == 0:
                tags.add("signed_imm:zero")
            else:
                tags.add("signed_imm:positive")

        if opcode in {"andi", "ori", "lui"}:
            immediate = instruction.operands[-1]
            _add_unsigned_immediate_tags(tags, immediate.value, immediate.bit_width)

        if opcode in SHIFT_OPCODES:
            shamt = instruction.operands[2]
            _add_unsigned_immediate_tags(tags, shamt.value, shamt.bit_width)

        if opcode in MEMORY_OPCODES:
            offset = instruction.operands[1]
            value = int(offset.value)
            if value < 0:
                tags.add("mem_offset:negative")
            elif value == 0:
                tags.add("mem_offset:zero")
            else:
                tags.add("mem_offset:positive")

        if opcode in BRANCH_OPCODES:
            target = str(instruction.operands[2])
            target_position = label_positions.get(target)
            if target_position is not None:
                if target_position < index:
                    tags.add("branch:backward")
                elif target_position > index:
                    tags.add("branch:forward")

        if opcode == "la":
            target = str(instruction.operands[1])
            address = data_addresses[target]
            tags.add("la:one_word" if (address & 0xFFFF) == 0 else "la:two_word")

    final_tier = complexity_tier or _infer_complexity_tier(program)
    pairwise_tags = _collect_pairwise_tags(tags)
    triplewise_tags = _collect_triplewise_tags(tags)
    priority_triple_tags = _collect_priority_triple_tags(tags)
    return ProgramCoverage(
        tags=frozenset(tags),
        pairwise_tags=frozenset(pairwise_tags),
        triplewise_tags=frozenset(triplewise_tags),
        priority_triple_tags=frozenset(priority_triple_tags),
        opcode_counts=opcode_counts,
        data_label_count=len(program.data_labels),
        data_word_count=data_word_count,
        text_instruction_count=text_instruction_count,
        complexity_tier=final_tier,
        generation_source=generation_source,
    )


def resolve_coverage_targets(config: GeneratorConfig) -> set[str]:
    if config.coverage_targets:
        return set(config.coverage_targets)

    targets = {f"opcode:{opcode}" for opcode in ALL_OPCODES}
    targets.add("data:non_empty")
    targets.add("format:hex")
    targets.add("format:dec")
    targets |= SIGNED_IMMEDIATE_TARGETS
    targets |= UNSIGNED_IMMEDIATE_TARGETS
    targets |= {"branch:forward", "branch:backward"}
    targets |= {"mem_offset:zero", "mem_offset:positive"}
    if config.allow_empty_data or config.min_data_labels == 0:
        targets.add("data:empty")
    if config.max_data_labels > 0:
        targets.add("word:single_value")
        targets.add("la:one_word")
    if config.allow_multi_value_word and config.max_words_per_label > 1 and config.max_data_labels > 0:
        targets.add("word:multi_value")
    if config.max_data_labels < 1:
        targets.discard("opcode:la")
        targets.discard("la:one_word")
        targets.discard("la:two_word")
    elif config.max_data_labels > 1:
        targets.add("la:two_word")
    if config.allow_negative_memory_offsets:
        targets.add("mem_offset:negative")
    if config.allow_zero_dest_register:
        targets.add("dest_reg:zero")
    return targets


def resolve_pairwise_targets(config: GeneratorConfig) -> set[str]:
    single_targets = resolve_coverage_targets(config)
    enabled_by_category = {
        category: tuple(tag for tag in tags if tag in single_targets)
        for category, tags in PAIRWISE_CATEGORIES.items()
    }
    pairwise: set[str] = set()
    for left_category, right_category in combinations(PAIRWISE_CATEGORY_ORDER, 2):
        for left_tag in enabled_by_category[left_category]:
            for right_tag in enabled_by_category[right_category]:
                atoms = frozenset({left_tag, right_tag})
                if _pair_is_possible(atoms):
                    pairwise.add(_pair_key(left_tag, right_tag))
    return pairwise


def resolve_triplewise_targets(config: GeneratorConfig) -> set[str]:
    single_targets = resolve_coverage_targets(config)
    enabled_by_category = {
        category: tuple(tag for tag in tags if tag in single_targets)
        for category, tags in PAIRWISE_CATEGORIES.items()
    }
    triplewise: set[str] = set()
    for category_names in combinations(PAIRWISE_CATEGORY_ORDER, 3):
        left, middle, right = category_names
        for left_tag in enabled_by_category[left]:
            for middle_tag in enabled_by_category[middle]:
                for right_tag in enabled_by_category[right]:
                    atoms = frozenset({left_tag, middle_tag, right_tag})
                    if _triple_is_possible(atoms):
                        triplewise.add(_triple_key(left_tag, middle_tag, right_tag))
    return triplewise


def resolve_priority_triple_targets(config: GeneratorConfig) -> set[str]:
    single_targets = resolve_coverage_targets(config)
    targets: set[str] = set()
    for atoms in PRIORITY_TRIPLE_TARGET_SETS:
        if atoms <= single_targets and _interaction_is_possible(atoms):
            tags = sorted(atoms)
            targets.add(_triple_key(tags[0], tags[1], tags[2]))
    return targets


def resolve_interaction_target_sets(config: GeneratorConfig) -> tuple[frozenset[str], ...]:
    single_targets = resolve_coverage_targets(config)
    selected: list[frozenset[str]] = []
    for targets in INTERACTION_TARGET_SETS:
        if targets <= single_targets and _interaction_is_possible(targets):
            selected.append(targets)
    return tuple(sorted(selected, key=lambda item: tuple(sorted(item))))


def pick_complexity_tier(
    iteration: int,
    mode: str,
    rnd: random.Random,
    ramp_interval: int,
) -> str:
    if mode == "simple":
        return "simple"
    if mode == "hard":
        return "hard"

    stage = min(3, max(0, iteration) // ramp_interval)
    weights_by_stage = (
        (70, 25, 5),
        (50, 30, 20),
        (30, 40, 30),
        (20, 40, 40),
    )
    simple_weight, medium_weight, hard_weight = weights_by_stage[stage]
    return _weighted_pick(
        rnd,
        (
            ("simple", simple_weight),
            ("medium", medium_weight),
            ("hard", hard_weight),
        ),
    )


def _default_complexity_tier(mode: str) -> str:
    if mode == "simple":
        return "simple"
    if mode == "hard":
        return "hard"
    return "medium"


def _data_addresses(data_labels: list[DataLabel]) -> dict[str, int]:
    address = DATA_BASE_ADDRESS
    result: dict[str, int] = {}
    for data_label in data_labels:
        result[data_label.name] = address
        address += len(data_label.words) * 4
    return result


def _add_unsigned_immediate_tags(tags: set[str], value: int, bit_width: int) -> None:
    maximum = (1 << bit_width) - 1
    if value == 0:
        tags.add("unsigned_imm:zero")
    elif value == maximum:
        tags.add("unsigned_imm:max")
    else:
        tags.add("unsigned_imm:other")


def _collect_pairwise_tags(tags: set[str]) -> set[str]:
    pairwise: set[str] = set()
    for left_category, right_category in combinations(PAIRWISE_CATEGORY_ORDER, 2):
        left_atoms = [tag for tag in PAIRWISE_CATEGORIES[left_category] if tag in tags]
        right_atoms = [tag for tag in PAIRWISE_CATEGORIES[right_category] if tag in tags]
        for left_tag in left_atoms:
            for right_tag in right_atoms:
                atoms = frozenset({left_tag, right_tag})
                if _pair_is_possible(atoms):
                    pairwise.add(_pair_key(left_tag, right_tag))
    return pairwise


def _collect_triplewise_tags(tags: set[str]) -> set[str]:
    triplewise: set[str] = set()
    for category_names in combinations(PAIRWISE_CATEGORY_ORDER, 3):
        left, middle, right = category_names
        left_atoms = [tag for tag in PAIRWISE_CATEGORIES[left] if tag in tags]
        middle_atoms = [tag for tag in PAIRWISE_CATEGORIES[middle] if tag in tags]
        right_atoms = [tag for tag in PAIRWISE_CATEGORIES[right] if tag in tags]
        for left_tag in left_atoms:
            for middle_tag in middle_atoms:
                for right_tag in right_atoms:
                    atoms = frozenset({left_tag, middle_tag, right_tag})
                    if _triple_is_possible(atoms):
                        triplewise.add(_triple_key(left_tag, middle_tag, right_tag))
    return triplewise


def _collect_priority_triple_tags(tags: set[str]) -> set[str]:
    priority: set[str] = set()
    for atoms in PRIORITY_TRIPLE_TARGET_SETS:
        if atoms <= tags:
            ordered = sorted(atoms)
            priority.add(_triple_key(ordered[0], ordered[1], ordered[2]))
    return priority


def _pair_is_possible(atoms: frozenset[str]) -> bool:
    if "data:empty" in atoms:
        for forbidden in ("word:single_value", "word:multi_value", "la:one_word", "la:two_word", "opcode:la"):
            if forbidden in atoms:
                return False
    return True


def _triple_is_possible(atoms: frozenset[str]) -> bool:
    return _pair_is_possible(frozenset(atoms))


def _interaction_is_possible(targets: frozenset[str]) -> bool:
    if "data:empty" in targets and {"opcode:la", "la:one_word", "la:two_word"} & targets:
        return False
    return True


def _pair_key(left_tag: str, right_tag: str) -> str:
    left, right = sorted((left_tag, right_tag))
    return f"pair:{left}|{right}"


def _pair_components(pair_tag: str) -> tuple[str, str]:
    if not pair_tag.startswith("pair:"):
        raise ValueError(f"invalid pairwise target: {pair_tag}")
    payload = pair_tag.split(":", 1)[1]
    left, right = payload.split("|", 1)
    return left, right


def _triple_key(left_tag: str, middle_tag: str, right_tag: str) -> str:
    ordered = sorted((left_tag, middle_tag, right_tag))
    return f"triple:{ordered[0]}|{ordered[1]}|{ordered[2]}"


def _triple_components(triple_tag: str) -> tuple[str, str, str]:
    if not triple_tag.startswith("triple:"):
        raise ValueError(f"invalid triplewise target: {triple_tag}")
    payload = triple_tag.split(":", 1)[1]
    left, middle, right = payload.split("|", 2)
    return left, middle, right


def _infer_complexity_tier(program: Program) -> str:
    text_words = program.expanded_text_word_count()
    data_words = sum(len(data_label.words) for data_label in program.data_labels)
    label_count = sum(len(line.labels) for line in program.text_lines)
    control_flow = sum(
        1
        for line in program.text_lines
        if line.instruction is not None and line.instruction.opcode in BRANCH_OPCODES | JUMP_OPCODES | {"la"}
    )
    if text_words >= 24 or data_words >= 10 or label_count >= 6 or control_flow >= 6:
        return "hard"
    if text_words <= 8 and data_words <= 4 and label_count <= 3:
        return "simple"
    return "medium"


def _tier_bounds(minimum: int, maximum: int, tier: str) -> tuple[int, int]:
    if maximum <= minimum:
        return minimum, maximum
    span = maximum - minimum
    if tier == "simple":
        upper = minimum + max(0, span // 3)
        return minimum, max(minimum, upper)
    if tier == "hard":
        lower = minimum + max(0, span // 2)
        return min(maximum, lower), maximum
    lower = minimum + max(0, span // 4)
    upper = minimum + max(0, (span * 3) // 4)
    return min(lower, maximum), max(min(upper, maximum), min(lower, maximum))


def _choose_count_for_tier(
    rnd: random.Random,
    minimum: int,
    maximum: int,
    tier: str,
) -> int:
    lower, upper = _tier_bounds(minimum, maximum, tier)
    if lower > upper:
        lower = upper
    return rnd.randint(lower, upper)


def _weighted_pick(
    rnd: random.Random,
    choices: tuple[tuple[str, int], ...],
) -> str:
    total = sum(weight for _, weight in choices)
    value = rnd.uniform(0, total)
    upto = 0.0
    for item, weight in choices:
        upto += weight
        if value <= upto:
            return item
    return choices[-1][0]


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
