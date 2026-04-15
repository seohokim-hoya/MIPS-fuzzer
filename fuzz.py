#!/usr/bin/env python3
from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

from mips_fuzzer.config import DEFAULT_CONFIG, load_config
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
from mips_fuzzer.harness import FuzzerConfig, FuzzerRunner

PRESET_SETTINGS: dict[str, dict[str, object]] = {
    "default": {},
    "pdf_full": {
        "min_data_labels": 0,
        "max_data_labels": 8,
        "min_words_per_label": 1,
        "max_words_per_label": 6,
        "min_text": 1,
        "max_text": 64,
        "max_total_data_words": 32,
        "max_total_text_words": 96,
        "allow_empty_data": True,
        # TA confirmed `.word` can be treated as single-value only for grading.
        "allow_multi_value_word": False,
        "allow_negative_memory_offsets": True,
        "allow_zero_dest_register": True,
        "coverage_mode": "coverage_first",
        "complexity_mode": "mixed",
        "use_small_exhaustive_first": True,
    },
}


def _preset_settings(name: str) -> dict[str, object]:
    try:
        return PRESET_SETTINGS[name]
    except KeyError as exc:
        raise ValueError(f"unknown preset: {name}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Grammar-based differential fuzzer for sample/main.c|main.cpp and user/main.c|main.cpp"
    )
    parser.add_argument(
        "--preset",
        choices=sorted(PRESET_SETTINGS),
        default=None,
        help="generation preset; command-line preset overrides config.yml preset",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path("."),
        help="workspace root containing sample/, user/, and Makefile",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="config file path; defaults to <workspace>/config.yml",
    )
    parser.add_argument(
        "--iters",
        type=int,
        default=None,
        help="number of generated programs to run; 0 means run forever",
    )
    parser.add_argument(
        "--seed", type=int, default=None, help="master seed for reproducible generation"
    )
    parser.add_argument(
        "--timeout", type=float, default=None, help="per-execution timeout in seconds"
    )
    parser.add_argument(
        "--artifact-dir",
        "--out",
        dest="artifact_dir",
        type=Path,
        default=None,
        help="artifact output directory; defaults to <workspace>/artifacts",
    )
    parser.add_argument(
        "--log-every",
        type=int,
        default=None,
        help="print progress every N checked inputs; 0 disables periodic progress logs",
    )
    parser.add_argument(
        "--report-coverage-every",
        type=int,
        default=None,
        help="print coverage summary every N checked inputs; 0 disables periodic coverage logs",
    )
    parser.add_argument("--min-data-labels", type=int, default=None)
    parser.add_argument("--max-data-labels", type=int, default=None)
    parser.add_argument("--min-words-per-label", type=int, default=None)
    parser.add_argument("--max-words-per-label", type=int, default=None)
    parser.add_argument("--min-text", type=int, default=None)
    parser.add_argument("--max-text", type=int, default=None)
    parser.add_argument("--max-total-data-words", type=int, default=None)
    parser.add_argument("--max-total-text-words", type=int, default=None)
    parser.add_argument(
        "--edge-prob",
        type=float,
        default=None,
        help="probability of choosing edge-case values",
    )
    parser.add_argument(
        "--coverage-mode",
        choices=["biased", "stratified", "coverage_first"],
        default=None,
        help="generation strategy to use when selecting new programs",
    )
    parser.add_argument(
        "--coverage-targets",
        default=None,
        help="comma-separated coverage targets to prioritize; defaults to all compatible targets",
    )
    parser.add_argument(
        "--allow-empty-data",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="allow programs with an empty .data section",
    )
    parser.add_argument(
        "--allow-multi-value-word",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="allow .word directives with multiple values on one line",
    )
    parser.add_argument(
        "--allow-negative-memory-offsets",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="allow negative aligned offsets in lw/sw instructions",
    )
    parser.add_argument(
        "--allow-zero-dest-register",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="allow instructions that write to register $0",
    )
    parser.add_argument(
        "--complexity-mode",
        choices=["simple", "mixed", "hard"],
        default=None,
        help="complexity schedule to use when generating programs",
    )
    parser.add_argument(
        "--complexity-ramp-interval",
        type=int,
        default=None,
        help="number of iterations between complexity schedule shifts in mixed mode",
    )
    parser.add_argument(
        "--use-small-exhaustive-first",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="run deterministic representative single/pair/interactions before random generation",
    )
    parser.add_argument(
        "--project",
        type=int,
        choices=[1, 2, 3, 4],
        default=1,
        help="which project to fuzz: 1=assembler, 2=simulator (default: 1)",
    )
    return parser.parse_args()


def resolve_settings(args: argparse.Namespace) -> tuple[Path, dict[str, object]]:
    workspace = args.workspace.resolve()
    config_path = args.config if args.config is not None else workspace / "config.yml"
    if not config_path.is_absolute():
        config_path = (workspace / config_path).resolve()

    loaded = load_config(config_path)
    settings: dict[str, object] = dict(DEFAULT_CONFIG)
    loaded_preset = str(loaded.get("preset", DEFAULT_CONFIG["preset"]))
    if args.preset is None and loaded_preset != "default":
        settings.update(_preset_settings(loaded_preset))
    settings.update({key: value for key, value in loaded.items() if key != "preset"})
    if args.preset is not None:
        settings.update(_preset_settings(args.preset))
        settings["preset"] = args.preset
    else:
        settings["preset"] = loaded_preset

    overrides = {
        "artifact_dir": args.artifact_dir,
        "iters": args.iters,
        "timeout": args.timeout,
        "log_every": args.log_every,
        "report_coverage_every": args.report_coverage_every,
        "min_data_labels": args.min_data_labels,
        "max_data_labels": args.max_data_labels,
        "min_words_per_label": args.min_words_per_label,
        "max_words_per_label": args.max_words_per_label,
        "min_text": args.min_text,
        "max_text": args.max_text,
        "max_total_data_words": args.max_total_data_words,
        "max_total_text_words": args.max_total_text_words,
        "edge_prob": args.edge_prob,
        "coverage_mode": args.coverage_mode,
        "allow_empty_data": args.allow_empty_data,
        "allow_multi_value_word": args.allow_multi_value_word,
        "allow_negative_memory_offsets": args.allow_negative_memory_offsets,
        "allow_zero_dest_register": args.allow_zero_dest_register,
        "complexity_mode": args.complexity_mode,
        "complexity_ramp_interval": args.complexity_ramp_interval,
        "use_small_exhaustive_first": args.use_small_exhaustive_first,
    }
    for key, value in overrides.items():
        if value is not None:
            settings[key] = value
    if args.coverage_targets is not None:
        settings["coverage_targets"] = tuple(
            part.strip() for part in args.coverage_targets.split(",") if part.strip()
        )
    return config_path, settings


def main() -> int:
    args = parse_args()
    try:
        config_path, settings = resolve_settings(args)
    except ValueError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    master_seed = (
        args.seed if args.seed is not None else random.SystemRandom().randrange(1 << 63)
    )
    driver_rng = random.Random(master_seed)

    generator = ProgramGenerator(
        GeneratorConfig(
            min_data_labels=int(settings["min_data_labels"]),
            max_data_labels=int(settings["max_data_labels"]),
            min_words_per_label=int(settings["min_words_per_label"]),
            max_words_per_label=int(settings["max_words_per_label"]),
            min_text_instructions=int(settings["min_text"]),
            max_text_instructions=int(settings["max_text"]),
            max_total_data_words=int(settings["max_total_data_words"]),
            max_total_text_words=int(settings["max_total_text_words"]),
            edge_case_probability=float(settings["edge_prob"]),
            allow_empty_data=bool(settings["allow_empty_data"]),
            allow_multi_value_word=bool(settings["allow_multi_value_word"]),
            allow_negative_memory_offsets=bool(
                settings["allow_negative_memory_offsets"]
            ),
            allow_zero_dest_register=bool(settings["allow_zero_dest_register"]),
            coverage_mode=str(settings["coverage_mode"]),
            coverage_targets=tuple(
                str(target) for target in settings["coverage_targets"]
            ),
            complexity_mode=str(settings["complexity_mode"]),
            complexity_ramp_interval=int(settings["complexity_ramp_interval"]),
            use_small_exhaustive_first=bool(settings["use_small_exhaustive_first"]),
        )
    )
    project = args.project
    if project in (3, 4):
        print(f"error: project {project} is not yet implemented", file=sys.stderr)
        return 2
    artifact_root = Path(str(settings["artifact_dir"]))
    timeout = float(settings["timeout"])
    if project == 2:
        fuzzer_config = FuzzerConfig(
            workspace_root=args.workspace,
            artifact_root=artifact_root,
            timeout_seconds=timeout,
            build_command=("make", "all", "PROJECT=2"),
            ref_executable=Path("build/ref/p2sim"),
            user_executable=Path("build/user/p2sim"),
            project=2,
            ref_assembler=Path("build/ref/p1asm"),
            sim_args=("-n", "1000"),
        )
    else:
        fuzzer_config = FuzzerConfig(
            workspace_root=args.workspace,
            artifact_root=artifact_root,
            timeout_seconds=timeout,
            build_command=("make", "all", "PROJECT=1"),
            ref_executable=Path("build/ref/p1asm"),
            user_executable=Path("build/user/p1asm"),
            project=1,
        )
    runner = FuzzerRunner(fuzzer_config)
    log_every = int(settings["log_every"])
    report_coverage_every = int(settings["report_coverage_every"])
    max_iters = int(settings["iters"])
    coverage_targets = resolve_coverage_targets(generator.config)
    pairwise_targets = resolve_pairwise_targets(generator.config)
    triplewise_targets = resolve_triplewise_targets(generator.config)
    priority_triple_targets = resolve_priority_triple_targets(generator.config)
    coverage_tracker = CoverageTracker(
        coverage_targets,
        pairwise_targets,
        triplewise_targets,
        priority_triple_targets,
    )
    exhaustive_scheduler = (
        SmallExhaustiveScheduler(generator.config)
        if generator.config.use_small_exhaustive_first
        else None
    )

    build_result = runner.build_targets()
    if not build_result.succeeded:
        print(f"build failed: {build_result.reason}", file=sys.stderr)
        if build_result.launch_error:
            print(build_result.launch_error, file=sys.stderr)
        if build_result.stdout:
            print(build_result.stdout, end="", file=sys.stderr)
        if build_result.stderr:
            print(build_result.stderr, end="", file=sys.stderr)
        if build_result.missing_targets:
            joined = ", ".join(build_result.missing_targets)
            print(f"missing executables: {joined}", file=sys.stderr)
        return 2

    print(f"project: {project}")
    print(f"master-seed: {master_seed}")
    print(f"config: {config_path}")
    print(f"workspace: {runner.workspace_root}")
    print(f"ref: {runner.ref_executable}")
    print(f"user: {runner.user_executable}")
    print(f"log-every: {log_every}")
    print(f"coverage-mode: {generator.config.coverage_mode}")
    print(f"coverage-targets: {len(coverage_targets)}")
    print(f"pairwise-targets: {len(pairwise_targets)}")
    print(f"triplewise-targets: {len(triplewise_targets)}")
    print(f"priority-triple-targets: {len(priority_triple_targets)}")
    print(f"complexity-mode: {generator.config.complexity_mode}")
    if exhaustive_scheduler is not None:
        print(f"small-exhaustive-requests: {exhaustive_scheduler.remaining()}")

    iteration = 0
    started_at = time.monotonic()
    try:
        while max_iters == 0 or iteration < max_iters:
            case_seed = driver_rng.randrange(1 << 63)
            request = (
                exhaustive_scheduler.next_request()
                if exhaustive_scheduler is not None
                else None
            )
            if request is not None:
                preferred_targets = set(request.preferred_targets)
                complexity_tier = request.complexity_tier
                generation_source = request.source
                target_id = request.request_id
            else:
                preferred_targets = coverage_tracker.preferred_targets(
                    generator.config.coverage_mode
                )
                complexity_tier = pick_complexity_tier(
                    iteration,
                    generator.config.complexity_mode,
                    driver_rng,
                    generator.config.complexity_ramp_interval,
                )
                generation_source = "coverage_random"
                target_id = None
            program = generator.generate(
                case_seed,
                preferred_targets=preferred_targets,
                complexity_tier=complexity_tier,
            )
            coverage = collect_program_coverage(
                program,
                complexity_tier=complexity_tier,
                generation_source=generation_source,
            )
            coverage_tracker.observe(coverage)
            result = runner.evaluate_program_with_details(
                program,
                seed=case_seed,
                iteration=iteration,
                program_details={
                    "coverage": coverage.to_metadata(),
                    "preferred_targets": sorted(preferred_targets),
                    "pairwise_targets": sorted(coverage.pairwise_tags),
                    "triplewise_targets": sorted(coverage.triplewise_tags),
                    "priority_triple_targets": sorted(coverage.priority_triple_tags),
                    "complexity_tier": complexity_tier,
                    "generation_source": generation_source,
                    "target_id": target_id,
                },
            )
            if result.interesting:
                print(
                    f"[{iteration:05d}] seed={case_seed} status={result.failure_class} "
                    f"text_words={program.expanded_text_word_count()} "
                    f"data_words={sum(len(label.words) for label in program.data_labels)}"
                )
                if result.artifact_dir is not None:
                    print(f"saved={result.artifact_dir}")
                print(f"reason={result.reason}")
                print(f"complexity-tier={complexity_tier} source={generation_source}")
                print(f"coverage-tags={','.join(sorted(coverage.tags))}")
                if coverage.pairwise_tags:
                    print(
                        f"pairwise-tags={','.join(sorted(coverage.pairwise_tags)[:12])}"
                    )
                if coverage.triplewise_tags:
                    print(
                        f"triplewise-tags={','.join(sorted(coverage.triplewise_tags)[:12])}"
                    )
                if coverage.priority_triple_tags:
                    print(
                        f"priority-triple-tags={','.join(sorted(coverage.priority_triple_tags))}"
                    )
                print(f"last-run={runner.artifact_root / 'last_run'}")
                if result.diff_summary is not None:
                    print(result.diff_summary.text)
                return 1
            iteration += 1
            if log_every > 0 and iteration % log_every == 0:
                elapsed = time.monotonic() - started_at
                rate = iteration / elapsed if elapsed > 0 else 0.0
                print(
                    f"[progress] checked={iteration} elapsed={elapsed:.1f}s "
                    f"rate={rate:.1f}/s last-seed={case_seed}"
                )
            if report_coverage_every > 0 and iteration % report_coverage_every == 0:
                print(f"[coverage] {coverage_tracker.summary()}")
    except KeyboardInterrupt:
        print("stopped by user", file=sys.stderr)
        return 130

    elapsed = time.monotonic() - started_at
    print(f"finished without mismatches checked={iteration} elapsed={elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
