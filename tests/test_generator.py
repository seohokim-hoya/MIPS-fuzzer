from __future__ import annotations

import random
import unittest

from mips_fuzzer.generator import (
    CoverageTracker,
    GeneratorConfig,
    ProgramGenerator,
    SmallExhaustiveScheduler,
    collect_program_coverage,
    pick_complexity_tier,
    resolve_coverage_targets,
    resolve_pairwise_targets,
    resolve_priority_triple_targets,
    resolve_triplewise_targets,
)


class GeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = GeneratorConfig(
            min_data_labels=0,
            max_data_labels=6,
            min_words_per_label=1,
            max_words_per_label=5,
            min_text_instructions=1,
            max_text_instructions=24,
            edge_case_probability=0.6,
            allow_empty_data=True,
            allow_multi_value_word=False,
            allow_negative_memory_offsets=True,
            allow_zero_dest_register=True,
            coverage_mode="coverage_first",
            complexity_mode="mixed",
            use_small_exhaustive_first=True,
        )
        self.generator = ProgramGenerator(self.config)

    def test_generated_programs_validate_and_render(self) -> None:
        for seed in range(20):
            program = self.generator.generate(seed)
            program.assert_valid()
            rendered = program.render()
            self.assertTrue(rendered.startswith(".data\n"))
            self.assertIn("\n.text\n", rendered)

    def test_generator_can_produce_both_la_shapes(self) -> None:
        one_word = self.generator.generate(100, preferred_targets={"la:one_word"})
        two_word = self.generator.generate(101, preferred_targets={"la:two_word"})
        self.assertIn("la:one_word", collect_program_coverage(one_word).tags)
        self.assertIn("la:two_word", collect_program_coverage(two_word).tags)

    def test_generator_can_produce_negative_memory_offsets(self) -> None:
        program = self.generator.generate(200, preferred_targets={"mem_offset:negative"})
        coverage = collect_program_coverage(program)
        self.assertIn("mem_offset:negative", coverage.tags)

    def test_generator_can_produce_empty_data_programs(self) -> None:
        program = self.generator.generate(300, preferred_targets={"data:empty"})
        coverage = collect_program_coverage(program)
        self.assertIn("data:empty", coverage.tags)
        self.assertEqual(len(program.data_labels), 0)

    def test_generator_keeps_word_single_value_only(self) -> None:
        program = self.generator.generate(400)
        coverage = collect_program_coverage(program)
        self.assertNotIn("word:multi_value", coverage.tags)
        if program.data_labels:
            self.assertIn("word:single_value", coverage.tags)
        rendered = program.render()
        for line in rendered.splitlines():
            if line.strip().startswith(".word "):
                self.assertNotIn(", ", line)

    def test_generator_can_use_register_zero_as_destination(self) -> None:
        program = self.generator.generate(500, preferred_targets={"dest_reg:zero"})
        coverage = collect_program_coverage(program)
        self.assertIn("dest_reg:zero", coverage.tags)

    def test_generator_eventually_emits_all_opcodes(self) -> None:
        seen: set[str] = set()
        for seed in range(500):
            program = self.generator.generate(seed)
            coverage = collect_program_coverage(program)
            seen.update(tag for tag in coverage.tags if tag.startswith("opcode:"))
        expected = {f"opcode:{opcode}" for opcode in [
            "addiu",
            "addu",
            "and",
            "andi",
            "beq",
            "bne",
            "j",
            "jal",
            "jr",
            "la",
            "lui",
            "lw",
            "nor",
            "or",
            "ori",
            "sll",
            "sltiu",
            "sltu",
            "srl",
            "subu",
            "sw",
        ]}
        self.assertTrue(expected <= seen)

    def test_pairwise_targets_are_resolved_and_observable(self) -> None:
        pairwise_targets = resolve_pairwise_targets(self.config)
        self.assertTrue(pairwise_targets)
        program = self.generator.generate(
            610,
            preferred_targets={"data:empty", "opcode:jal"},
            complexity_tier="simple",
        )
        coverage = collect_program_coverage(program, complexity_tier="simple")
        self.assertIn("data:empty", coverage.tags)
        self.assertIn("opcode:jal", coverage.tags)
        self.assertTrue(
            any("data:empty" in pair and "opcode:jal" in pair for pair in coverage.pairwise_tags)
        )

    def test_triplewise_targets_are_resolved_and_observable(self) -> None:
        triplewise_targets = resolve_triplewise_targets(self.config)
        self.assertTrue(triplewise_targets)
        program = self.generator.generate(
            611,
            preferred_targets={"data:non_empty", "branch:backward", "format:hex"},
            complexity_tier="hard",
        )
        coverage = collect_program_coverage(program, complexity_tier="hard")
        self.assertIn("data:non_empty", coverage.tags)
        self.assertIn("branch:backward", coverage.tags)
        self.assertIn("format:hex", coverage.tags)
        self.assertTrue(
            any(
                "data:non_empty" in triple and "branch:backward" in triple and "format:hex" in triple
                for triple in coverage.triplewise_tags
            )
        )

    def test_coverage_tracker_prefers_missing_targets_then_pairs_then_triples(self) -> None:
        tracker = CoverageTracker(
            resolve_coverage_targets(self.config),
            resolve_pairwise_targets(self.config),
            resolve_triplewise_targets(self.config),
            resolve_priority_triple_targets(self.config),
        )
        preferred = tracker.preferred_targets("coverage_first")
        self.assertEqual(len(preferred), 1)
        program = self.generator.generate(600, preferred_targets=preferred)
        tracker.observe(collect_program_coverage(program))
        next_preferred = tracker.preferred_targets("coverage_first")
        self.assertTrue(next_preferred)
        tracker.single_counts.update({tag: 1 for tag in resolve_coverage_targets(self.config)})
        tracker.pair_counts.update({tag: 1 for tag in resolve_pairwise_targets(self.config)})
        priority_next = tracker.preferred_targets("coverage_first")
        self.assertGreaterEqual(len(priority_next), 2)

    def test_priority_triple_targets_are_resolved_and_observable(self) -> None:
        priority_targets = resolve_priority_triple_targets(self.config)
        self.assertTrue(priority_targets)
        preferred = {"data:empty", "opcode:jal", "opcode:jr"}
        program = self.generator.generate(612, preferred_targets=preferred, complexity_tier="hard")
        coverage = collect_program_coverage(program, complexity_tier="hard")
        self.assertTrue(coverage.priority_triple_tags)
        self.assertIn("triple:data:empty|opcode:jal|opcode:jr", coverage.priority_triple_tags)

    def test_small_exhaustive_scheduler_emits_representative_requests(self) -> None:
        scheduler = SmallExhaustiveScheduler(self.config)
        first = scheduler.next_request()
        self.assertIsNotNone(first)
        self.assertEqual(first.source, "small_exhaustive_single")
        seen_sources = {first.source}
        for _ in range(500):
            request = scheduler.next_request()
            if request is None:
                break
            seen_sources.add(request.source)
        self.assertIn("small_exhaustive_single", seen_sources)
        self.assertIn("small_exhaustive_pair", seen_sources)
        self.assertIn("small_exhaustive_triple", seen_sources)

    def test_pick_complexity_tier_respects_mode(self) -> None:
        rnd = random.Random(7)
        self.assertEqual(pick_complexity_tier(0, "simple", rnd, 100), "simple")
        self.assertEqual(pick_complexity_tier(0, "hard", rnd, 100), "hard")

    def test_hard_generation_is_larger_on_average_than_simple(self) -> None:
        simple_total = 0
        hard_total = 0
        for seed in range(20):
            simple_program = self.generator.generate(seed, complexity_tier="simple")
            hard_program = self.generator.generate(seed, complexity_tier="hard")
            simple_total += simple_program.expanded_text_word_count() + len(simple_program.data_labels)
            hard_total += hard_program.expanded_text_word_count() + len(hard_program.data_labels)
        self.assertGreater(hard_total, simple_total)


if __name__ == "__main__":
    unittest.main()
