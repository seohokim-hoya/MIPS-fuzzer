from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .model import Program


@dataclass
class BuildResult:
    command: list[str]
    return_code: int | None
    stdout: str
    stderr: str
    succeeded: bool
    reason: str
    missing_targets: list[str]
    launch_error: str | None = None


@dataclass
class RunResult:
    role: str
    executable: str
    command: list[str]
    return_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    runtime_seconds: float
    output_files: list[Path]
    output_bytes: bytes | None
    launch_error: str | None = None

    @property
    def output_state(self) -> str:
        if self.output_bytes is not None:
            return "present"
        if len(self.output_files) > 1:
            return "multiple"
        return "missing"


@dataclass
class DiffResult:
    iteration: int
    seed: int
    interesting: bool
    failure_class: str | None
    reason: str
    artifact_dir: Path | None
    run_ref: RunResult
    run_user: RunResult
    asm_text: str
    diff_summary: "DiffSummary | None"


@dataclass
class DiffSummary:
    text: str
    details: dict[str, object]


@dataclass
class FuzzerConfig:
    workspace_root: Path
    artifact_root: Path | None = None
    timeout_seconds: float = 2.0
    build_command: tuple[str, ...] = ("make", "all")
    ref_executable: Path = Path("build/ref/runfile")
    user_executable: Path = Path("build/user/runfile")


class FuzzerRunner:
    def __init__(self, config: FuzzerConfig) -> None:
        self.config = config
        self.workspace_root = config.workspace_root.resolve()
        if config.artifact_root is None:
            self.artifact_root = self.workspace_root / "artifacts"
        elif config.artifact_root.is_absolute():
            self.artifact_root = config.artifact_root.resolve()
        else:
            self.artifact_root = (self.workspace_root / config.artifact_root).resolve()
        self.ref_executable = (self.workspace_root / config.ref_executable).resolve()
        self.user_executable = (self.workspace_root / config.user_executable).resolve()

    def build_targets(self) -> BuildResult:
        command = list(self.config.build_command)
        try:
            completed = subprocess.run(
                command,
                cwd=self.workspace_root,
                capture_output=True,
                text=True,
            )
        except OSError as exc:
            return BuildResult(
                command=command,
                return_code=None,
                stdout="",
                stderr="",
                succeeded=False,
                reason="failed to launch build command",
                missing_targets=[],
                launch_error=str(exc),
            )

        missing_targets = [
            str(path.relative_to(self.workspace_root))
            for path in (self.ref_executable, self.user_executable)
            if not path.is_file()
        ]
        succeeded = completed.returncode == 0 and not missing_targets
        if completed.returncode != 0:
            reason = "build command failed"
        elif missing_targets:
            reason = "build completed but expected executables are missing"
        else:
            reason = "build succeeded"
        return BuildResult(
            command=command,
            return_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            succeeded=succeeded,
            reason=reason,
            missing_targets=missing_targets,
        )

    def evaluate_program(self, program: Program, seed: int, iteration: int) -> DiffResult:
        return self.evaluate_program_with_details(program, seed, iteration)

    def evaluate_program_with_details(
        self,
        program: Program,
        seed: int,
        iteration: int,
        program_details: dict[str, object] | None = None,
    ) -> DiffResult:
        self._assert_built()
        asm_text = program.render()
        with tempfile.TemporaryDirectory(prefix="mips-fuzz-") as temp_root:
            temp_path = Path(temp_root)
            run_ref = self._run_target("ref", self.ref_executable, temp_path / "ref", asm_text)
            run_user = self._run_target("user", self.user_executable, temp_path / "user", asm_text)
            failure_class, reason = classify_difference(run_ref, run_user)
            diff_summary = build_diff_summary(run_ref, run_user, failure_class, reason)
            self._save_last_run(
                seed=seed,
                iteration=iteration,
                asm_text=asm_text,
                failure_class=failure_class,
                reason=reason,
                run_ref=run_ref,
                run_user=run_user,
                diff_summary=diff_summary,
                program_details=program_details,
            )
            interesting = failure_class is not None
            artifact_dir = None
            if interesting:
                artifact_dir = self._save_artifacts(
                    seed=seed,
                    iteration=iteration,
                    asm_text=asm_text,
                    failure_class=failure_class,
                    reason=reason,
                    run_ref=run_ref,
                    run_user=run_user,
                    diff_summary=diff_summary,
                    program_details=program_details,
                )
            else:
                diff_summary = None
            return DiffResult(
                iteration=iteration,
                seed=seed,
                interesting=interesting,
                failure_class=failure_class,
                reason=reason,
                artifact_dir=artifact_dir,
                run_ref=run_ref,
                run_user=run_user,
                asm_text=asm_text,
                diff_summary=diff_summary,
            )

    def _assert_built(self) -> None:
        missing = [str(path) for path in (self.ref_executable, self.user_executable) if not path.is_file()]
        if missing:
            joined = ", ".join(missing)
            raise FileNotFoundError(f"missing built executables: {joined}; run build_targets() first")

    def _run_target(self, role: str, executable: Path, workdir: Path, asm_text: str) -> RunResult:
        workdir.mkdir(parents=True, exist_ok=True)
        asm_path = workdir / "input.s"
        asm_path.write_text(asm_text, encoding="utf-8")
        command = [str(executable), str(asm_path)]
        start = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
            )
            runtime = time.monotonic() - start
            output_files = sorted(workdir.rglob("*.o"))
            output_bytes = None
            if len(output_files) == 1:
                output_bytes = output_files[0].read_bytes()
            return RunResult(
                role=role,
                executable=str(executable),
                command=command,
                return_code=completed.returncode,
                timed_out=False,
                stdout=completed.stdout,
                stderr=completed.stderr,
                runtime_seconds=runtime,
                output_files=output_files,
                output_bytes=output_bytes,
            )
        except subprocess.TimeoutExpired as exc:
            runtime = time.monotonic() - start
            output_files = sorted(workdir.rglob("*.o"))
            return RunResult(
                role=role,
                executable=str(executable),
                command=command,
                return_code=None,
                timed_out=True,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                runtime_seconds=runtime,
                output_files=output_files,
                output_bytes=None,
            )
        except OSError as exc:
            runtime = time.monotonic() - start
            return RunResult(
                role=role,
                executable=str(executable),
                command=command,
                return_code=None,
                timed_out=False,
                stdout="",
                stderr="",
                runtime_seconds=runtime,
                output_files=[],
                output_bytes=None,
                launch_error=str(exc),
            )

    def _save_artifacts(
        self,
        seed: int,
        iteration: int,
        asm_text: str,
        failure_class: str,
        reason: str,
        run_ref: RunResult,
        run_user: RunResult,
        diff_summary: DiffSummary,
        program_details: dict[str, object] | None = None,
    ) -> Path:
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        target = self.artifact_root / f"iter-{iteration:06d}-seed-{seed}-{failure_class}"
        suffix = 1
        while target.exists():
            target = self.artifact_root / f"iter-{iteration:06d}-seed-{seed}-{failure_class}-{suffix}"
            suffix += 1
        target.mkdir(parents=True, exist_ok=False)

        (target / "input.s").write_text(asm_text, encoding="utf-8")
        self._write_run(target, run_ref)
        self._write_run(target, run_user)
        (target / "diff.txt").write_text(diff_summary.text + "\n", encoding="utf-8")
        metadata = {
            "seed": seed,
            "iteration": iteration,
            "failure_class": failure_class,
            "reason": reason,
            "workspace_root": str(self.workspace_root),
            "command_ref": run_ref.command,
            "command_user": run_user.command,
            "return_code_ref": run_ref.return_code,
            "return_code_user": run_user.return_code,
            "timed_out_ref": run_ref.timed_out,
            "timed_out_user": run_user.timed_out,
            "runtime_ref": run_ref.runtime_seconds,
            "runtime_user": run_user.runtime_seconds,
            "diff_summary": diff_summary.details,
        }
        if program_details is not None:
            metadata["program_details"] = program_details
        (target / "meta.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return target

    def _save_last_run(
        self,
        seed: int,
        iteration: int,
        asm_text: str,
        failure_class: str | None,
        reason: str,
        run_ref: RunResult,
        run_user: RunResult,
        diff_summary: DiffSummary,
        program_details: dict[str, object] | None = None,
    ) -> Path:
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        target = self.artifact_root / "last_run"
        temp_target = self.artifact_root / ".last_run_tmp"
        if temp_target.exists():
            shutil.rmtree(temp_target)
        temp_target.mkdir(parents=True, exist_ok=False)
        (temp_target / "input.s").write_text(asm_text, encoding="utf-8")
        self._write_run(temp_target, run_ref)
        self._write_run(temp_target, run_user)
        (temp_target / "diff.txt").write_text(diff_summary.text + "\n", encoding="utf-8")
        metadata = {
            "seed": seed,
            "iteration": iteration,
            "failure_class": failure_class,
            "reason": reason,
            "workspace_root": str(self.workspace_root),
            "command_ref": run_ref.command,
            "command_user": run_user.command,
            "return_code_ref": run_ref.return_code,
            "return_code_user": run_user.return_code,
            "timed_out_ref": run_ref.timed_out,
            "timed_out_user": run_user.timed_out,
            "runtime_ref": run_ref.runtime_seconds,
            "runtime_user": run_user.runtime_seconds,
            "diff_summary": diff_summary.details,
        }
        if program_details is not None:
            metadata["program_details"] = program_details
        (temp_target / "meta.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        if target.exists():
            shutil.rmtree(target)
        temp_target.replace(target)
        return target

    def _write_run(self, target: Path, result: RunResult) -> None:
        prefix = result.role
        (target / f"{prefix}.stdout").write_text(result.stdout, encoding="utf-8")
        (target / f"{prefix}.stderr").write_text(result.stderr, encoding="utf-8")
        if result.output_bytes is not None:
            (target / f"{prefix}.o").write_bytes(result.output_bytes)
        if result.output_files:
            listing = "\n".join(str(path) for path in result.output_files)
            (target / f"{prefix}.outputs.txt").write_text(listing + "\n", encoding="utf-8")
        if result.launch_error:
            (target / f"{prefix}.launch_error.txt").write_text(result.launch_error + "\n", encoding="utf-8")


def classify_difference(run_ref: RunResult, run_user: RunResult) -> tuple[str | None, str]:
    if run_ref.launch_error != run_user.launch_error:
        return "crash", "launcher failure differed between targets"
    if run_ref.timed_out != run_user.timed_out:
        return "timeout", "exactly one target timed out"
    if run_ref.timed_out and run_user.timed_out:
        return None, "both targets timed out"
    if run_ref.return_code != run_user.return_code:
        return "crash", "return codes differed"
    if run_ref.output_state != run_user.output_state:
        if "missing" in {run_ref.output_state, run_user.output_state}:
            return "missing_output", f"output file state differed: {run_ref.output_state} vs {run_user.output_state}"
        return "output_mismatch", f"output file state differed: {run_ref.output_state} vs {run_user.output_state}"
    if run_ref.output_bytes is not None and run_user.output_bytes is not None and run_ref.output_bytes != run_user.output_bytes:
        return "output_mismatch", "output bytes differed"
    return None, "no differential behavior observed"


def build_diff_summary(
    run_ref: RunResult,
    run_user: RunResult,
    failure_class: str | None,
    reason: str,
) -> DiffSummary:
    details: dict[str, object] = {
        "failure_class": failure_class,
        "reason": reason,
        "ref_return_code": run_ref.return_code,
        "user_return_code": run_user.return_code,
        "ref_timed_out": run_ref.timed_out,
        "user_timed_out": run_user.timed_out,
        "ref_output_state": run_ref.output_state,
        "user_output_state": run_user.output_state,
        "ref_output_bytes": len(run_ref.output_bytes) if run_ref.output_bytes is not None else None,
        "user_output_bytes": len(run_user.output_bytes) if run_user.output_bytes is not None else None,
    }
    lines = [
        f"failure-class: {failure_class}",
        f"reason: {reason}",
        (
            f"ref: return={run_ref.return_code} timeout={run_ref.timed_out} "
            f"output={run_ref.output_state} bytes={details['ref_output_bytes']}"
        ),
        (
            f"user: return={run_user.return_code} timeout={run_user.timed_out} "
            f"output={run_user.output_state} bytes={details['user_output_bytes']}"
        ),
    ]

    if run_ref.output_bytes is None or run_user.output_bytes is None:
        return DiffSummary(text="\n".join(lines), details=details)

    ref_text = run_ref.output_bytes.decode("ascii", errors="replace")
    user_text = run_user.output_bytes.decode("ascii", errors="replace")
    ref_is_binary = _is_binary_ascii(ref_text)
    user_is_binary = _is_binary_ascii(user_text)
    first_diff_index = _first_diff_index(ref_text, user_text)
    details["first_diff_index"] = first_diff_index

    if first_diff_index is not None:
        lines.append(f"first-diff-index: {first_diff_index}")
    else:
        lines.append("first-diff-index: none")

    if ref_is_binary and user_is_binary:
        ref_words = _split_words(ref_text)
        user_words = _split_words(user_text)
        differing_words = _find_differing_words(ref_words, user_words)
        details["differing_word_count"] = len(differing_words)
        details["word_diffs"] = []
        if first_diff_index is not None:
            first_diff_word = first_diff_index // 32
            details["first_diff_word"] = first_diff_word
            lines.append(f"first-diff-word: {first_diff_word} ({_word_label(first_diff_word, ref_words, user_words)})")
            window = _bit_window(ref_text, user_text, first_diff_index)
            details["bit_window"] = window
            lines.append(
                f"bit-window[{window['start']}:{window['end']}]: "
                f"ref={window['ref']} user={window['user']}"
            )
        preview = differing_words[:5]
        lines.append(f"differing-words: {len(differing_words)}")
        for word_index in preview:
            ref_word = ref_words[word_index] if word_index < len(ref_words) else None
            user_word = user_words[word_index] if word_index < len(user_words) else None
            entry = {
                "index": word_index,
                "label": _word_label(word_index, ref_words, user_words),
                "ref": _format_word(ref_word),
                "user": _format_word(user_word),
            }
            details["word_diffs"].append(entry)
            lines.append(
                f"  word[{word_index}] {entry['label']}: "
                f"ref={entry['ref']} user={entry['user']}"
            )
    elif first_diff_index is not None:
        details["byte_window"] = _byte_window(run_ref.output_bytes, run_user.output_bytes, first_diff_index)
        window = details["byte_window"]
        lines.append(
            f"byte-window[{window['start']}:{window['end']}]: "
            f"ref={window['ref_hex']} user={window['user_hex']}"
        )

    return DiffSummary(text="\n".join(lines), details=details)


def _is_binary_ascii(text: str) -> bool:
    return bool(text) and set(text) <= {"0", "1"} and len(text) % 32 == 0


def _first_diff_index(ref_text: str, user_text: str) -> int | None:
    limit = min(len(ref_text), len(user_text))
    for index in range(limit):
        if ref_text[index] != user_text[index]:
            return index
    if len(ref_text) != len(user_text):
        return limit
    return None


def _split_words(text: str) -> list[str]:
    return [text[index : index + 32] for index in range(0, len(text), 32)]


def _find_differing_words(ref_words: list[str], user_words: list[str]) -> list[int]:
    limit = max(len(ref_words), len(user_words))
    differing: list[int] = []
    for index in range(limit):
        ref_word = ref_words[index] if index < len(ref_words) else None
        user_word = user_words[index] if index < len(user_words) else None
        if ref_word != user_word:
            differing.append(index)
    return differing


def _word_label(index: int, ref_words: list[str], user_words: list[str]) -> str:
    if index == 0:
        return "header.text_size"
    if index == 1:
        return "header.data_size"
    text_words = _header_text_words(ref_words, user_words)
    if text_words is None:
        return "payload"
    payload_index = index - 2
    if payload_index < text_words:
        return f"text[{payload_index}]"
    return f"data[{payload_index - text_words}]"


def _header_text_words(ref_words: list[str], user_words: list[str]) -> int | None:
    if len(ref_words) < 2 or len(user_words) < 2:
        return None
    ref_text_bytes = int(ref_words[0], 2)
    user_text_bytes = int(user_words[0], 2)
    if ref_text_bytes != user_text_bytes:
        return None
    return ref_text_bytes // 4


def _format_word(word: str | None) -> str:
    if word is None:
        return "<missing>"
    return f"0x{int(word, 2):08x}/{word}"


def _bit_window(ref_text: str, user_text: str, index: int, radius: int = 16) -> dict[str, object]:
    start = max(0, index - radius)
    end = min(max(len(ref_text), len(user_text)), index + radius)
    return {
        "start": start,
        "end": end,
        "ref": ref_text[start:end],
        "user": user_text[start:end],
    }


def _byte_window(ref_bytes: bytes, user_bytes: bytes, index: int, radius: int = 8) -> dict[str, object]:
    start = max(0, index - radius)
    end = min(max(len(ref_bytes), len(user_bytes)), index + radius)
    return {
        "start": start,
        "end": end,
        "ref_hex": ref_bytes[start:end].hex(),
        "user_hex": user_bytes[start:end].hex(),
    }
