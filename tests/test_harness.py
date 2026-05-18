from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path
import subprocess
import shutil

from mips_fuzzer.generator import ProgramGenerator
from mips_fuzzer.harness import FuzzerConfig, FuzzerRunner


REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_workspace(
    root: Path,
    sample_source: str,
    user_source: str | None,
    *,
    sample_ext: str = ".c",
    user_ext: str = ".cpp",
) -> None:
    ref_dir = root / "runfiles" / "Project-1" / "ref"
    user_dir = root / "runfiles" / "Project-1" / "user"
    ref_dir.mkdir(parents=True, exist_ok=True)
    user_dir.mkdir(parents=True, exist_ok=True)
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    (root / "Makefile").write_text(makefile, encoding="utf-8")
    (ref_dir / f"main{sample_ext}").write_text(sample_source, encoding="utf-8")
    if user_source is not None:
        (user_dir / f"main{user_ext}").write_text(user_source, encoding="utf-8")


def _write_project3_workspace(root: Path) -> None:
    (root / "Makefile").write_text((REPO_ROOT / "Makefile").read_text(encoding="utf-8"), encoding="utf-8")
    shutil.copytree(REPO_ROOT / "runfiles" / "Project-1", root / "runfiles" / "Project-1")
    shutil.copytree(REPO_ROOT / "runfiles" / "Project-3", root / "runfiles" / "Project-3")
    shutil.copytree(REPO_ROOT / "shared" / "Project-3", root / "shared" / "Project-3")


def _constant_output_program(payload: str) -> str:
    escaped = payload.replace("\\", "\\\\").replace('"', '\\"')
    return textwrap.dedent(
        f"""\
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>

        int main(int argc, char **argv) {{
            char output_path[1024];
            FILE *out;

            if (argc != 2) {{
                return 2;
            }}
            strncpy(output_path, argv[1], sizeof(output_path) - 1);
            output_path[sizeof(output_path) - 1] = '\\0';
            {{
                char *dot = strrchr(output_path, '.');
                if (dot == NULL) {{
                    strncat(output_path, ".o", sizeof(output_path) - strlen(output_path) - 1);
                }} else {{
                    dot[1] = 'o';
                    dot[2] = '\\0';
                }}
            }}
            out = fopen(output_path, "w");
            if (out == NULL) {{
                return 3;
            }}
            fputs("{escaped}", out);
            fclose(out);
            return 0;
        }}
        """
    )


def _constant_output_program_cpp(payload: str) -> str:
    escaped = payload.replace("\\", "\\\\").replace('"', '\\"')
    return textwrap.dedent(
        f"""\
        #include <fstream>
        #include <string>

        int main(int argc, char** argv) {{
            if (argc != 2) {{
                return 2;
            }}
            std::string output_path = argv[1];
            std::size_t pos = output_path.rfind('.');
            if (pos == std::string::npos) {{
                output_path += ".o";
            }} else {{
                output_path = output_path.substr(0, pos) + ".o";
            }}
            std::ofstream out(output_path);
            out << "{escaped}";
            return 0;
        }}
        """
    )


def _timeout_program() -> str:
    return textwrap.dedent(
        """\
        #include <chrono>
        #include <thread>

        int main() {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            return 0;
        }
        """
    )


class HarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.generator = ProgramGenerator()

    def test_build_targets_and_identical_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = _constant_output_program("same-output")
            _write_workspace(root, source, _constant_output_program_cpp("same-output"))

            runner = FuzzerRunner(FuzzerConfig(workspace_root=root, artifact_root=root / "artifacts"))
            build_result = runner.build_targets()
            self.assertTrue(build_result.succeeded)
            self.assertTrue((root / "build" / "ref" / "p1asm").exists())
            self.assertTrue((root / "build" / "user" / "p1asm").exists())

            result = runner.evaluate_program(self.generator.generate(1), seed=1, iteration=0)
            self.assertFalse(result.interesting)
            self.assertIsNone(result.failure_class)
            last_run = root / "artifacts" / "last_run"
            self.assertTrue((last_run / "input.s").exists())
            self.assertTrue((last_run / "diff.txt").exists())
            self.assertTrue((last_run / "meta.json").exists())

    def test_output_mismatch_is_captured(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_workspace(
                root,
                _constant_output_program("ref-output"),
                _constant_output_program_cpp("user-output"),
            )

            runner = FuzzerRunner(FuzzerConfig(workspace_root=root, artifact_root=root / "artifacts"))
            self.assertTrue(runner.build_targets().succeeded)

            result = runner.evaluate_program(self.generator.generate(2), seed=2, iteration=3)
            self.assertTrue(result.interesting)
            self.assertEqual(result.failure_class, "output_mismatch")
            self.assertIsNotNone(result.artifact_dir)
            self.assertTrue((result.artifact_dir / "input.s").exists())
            self.assertTrue((result.artifact_dir / "diff.txt").exists())
            self.assertTrue((result.artifact_dir / "ref.o").exists())
            self.assertTrue((result.artifact_dir / "user.o").exists())
            self.assertIsNotNone(result.diff_summary)
            self.assertIn("first-diff-index", result.diff_summary.text)
            last_run = root / "artifacts" / "last_run"
            self.assertTrue((last_run / "ref.o").exists())
            self.assertTrue((last_run / "user.o").exists())
            self.assertTrue((last_run / "meta.json").exists())

    def test_last_run_is_overwritten_with_latest_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = _constant_output_program("same-output")
            _write_workspace(root, source, _constant_output_program_cpp("same-output"))

            runner = FuzzerRunner(FuzzerConfig(workspace_root=root, artifact_root=root / "artifacts"))
            self.assertTrue(runner.build_targets().succeeded)

            runner.evaluate_program(self.generator.generate(1), seed=10, iteration=1)
            meta_path = root / "artifacts" / "last_run" / "meta.json"
            first_meta = meta_path.read_text(encoding="utf-8")
            self.assertIn('"seed": 10', first_meta)

            runner.evaluate_program(self.generator.generate(2), seed=20, iteration=2)
            second_meta = meta_path.read_text(encoding="utf-8")
            self.assertIn('"seed": 20', second_meta)
            self.assertIn('"iteration": 2', second_meta)
            self.assertNotEqual(first_meta, second_meta)

    def test_build_failure_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_workspace(root, _constant_output_program("ref-output"), None)

            runner = FuzzerRunner(FuzzerConfig(workspace_root=root, artifact_root=root / "artifacts"))
            build_result = runner.build_targets()
            self.assertFalse(build_result.succeeded)
            self.assertEqual(build_result.reason, "build command failed")
            self.assertIn("missing runfiles/Project-1/user/main.c or runfiles/Project-1/user/main.cpp", build_result.stderr)

    def test_build_targets_support_cpp_reference_and_c_user(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_workspace(
                root,
                _constant_output_program_cpp("same-output"),
                _constant_output_program("same-output"),
                sample_ext=".cpp",
                user_ext=".c",
            )

            runner = FuzzerRunner(FuzzerConfig(workspace_root=root, artifact_root=root / "artifacts"))
            build_result = runner.build_targets()
            self.assertTrue(build_result.succeeded)

            result = runner.evaluate_program(self.generator.generate(10), seed=10, iteration=1)
            self.assertFalse(result.interesting)
            self.assertIsNone(result.failure_class)

    def test_build_failure_when_both_entrypoints_exist(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_workspace(root, _constant_output_program("ref-output"), _constant_output_program_cpp("user-output"))
            (root / "runfiles" / "Project-1" / "user" / "main.c").write_text(_constant_output_program("other-user"), encoding="utf-8")

            runner = FuzzerRunner(FuzzerConfig(workspace_root=root, artifact_root=root / "artifacts"))
            build_result = runner.build_targets()
            self.assertFalse(build_result.succeeded)
            self.assertEqual(build_result.reason, "build command failed")
            self.assertIn("multiple entry files: runfiles/Project-1/user/main.c and runfiles/Project-1/user/main.cpp", build_result.stderr)

    def test_timeout_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_workspace(root, _constant_output_program("ref-output"), _timeout_program())

            runner = FuzzerRunner(
                FuzzerConfig(
                    workspace_root=root,
                    artifact_root=root / "artifacts",
                    timeout_seconds=0.2,
                )
            )
            self.assertTrue(runner.build_targets().succeeded)

            result = runner.evaluate_program(self.generator.generate(4), seed=4, iteration=5)
            self.assertTrue(result.interesting)
            self.assertEqual(result.failure_class, "timeout")

    def test_current_user_cpp_accepts_hex_signed_16bit_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sample_source = (REPO_ROOT / "runfiles" / "Project-1" / "ref" / "main.c").read_text(encoding="utf-8")
            user_source = (REPO_ROOT / "runfiles" / "Project-1" / "user" / "main.cpp").read_text(encoding="utf-8")
            _write_workspace(root, sample_source, user_source, sample_ext=".c", user_ext=".cpp")

            runner = FuzzerRunner(FuzzerConfig(workspace_root=root, artifact_root=root / "artifacts"))
            self.assertTrue(runner.build_targets().succeeded)

            input_path = root / "hex-signed.s"
            input_path.write_text(
                textwrap.dedent(
                    """\
                    .data
                    .text
                    text_0:
                    ori $20, $24, 0xa474
                    andi $7, $24, 0x169c
                    beq $17, $0, text_1
                    nor $9, $23, $28
                    beq $2, $4, text_1
                    or $18, $7, $11
                    sw $3, 0xfff4($18)
                    and $24, $30, $1
                    addiu $20, $30, 0xe1d1
                    text_1:
                    sll $16, $24, 0x03
                    """
                ),
                encoding="utf-8",
            )

            ref_run = subprocess.run(
                [str(root / "build" / "ref" / "p1asm"), str(input_path)],
                cwd=root,
                capture_output=True,
                text=True,
            )
            ref_output = (root / "hex-signed.o").read_text(encoding="ascii")
            user_run = subprocess.run(
                [str(root / "build" / "user" / "p1asm"), str(input_path)],
                cwd=root,
                capture_output=True,
                text=True,
            )
            user_output = (root / "hex-signed.o").read_text(encoding="ascii")
            self.assertEqual(ref_run.returncode, 0)
            self.assertEqual(user_run.returncode, 0)
            self.assertTrue((root / "hex-signed.o").exists())
            self.assertEqual(ref_output, user_output)

    def test_project3_builds_and_runs_identical_pipeline_simulators(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_project3_workspace(root)

            runner = FuzzerRunner(
                FuzzerConfig(
                    workspace_root=root,
                    artifact_root=root / "artifacts",
                    build_command=("make", "all", "PROJECT=3"),
                    ref_executable=Path("build/ref/p3sim"),
                    user_executable=Path("build/user/p3sim"),
                    project=3,
                    ref_assembler=Path("build/ref/p1asm"),
                    sim_args=("-n", "1000"),
                )
            )
            build_result = runner.build_targets()
            self.assertTrue(build_result.succeeded, build_result.stderr)
            self.assertTrue((root / "build" / "ref" / "p1asm").exists())
            self.assertTrue((root / "build" / "ref" / "p3sim").exists())
            self.assertTrue((root / "build" / "user" / "p3sim").exists())

            result = runner.evaluate_program(self.generator.generate(3), seed=3, iteration=0)
            self.assertFalse(result.interesting)
            self.assertIsNone(result.failure_class)
            last_run = root / "artifacts" / "last_run"
            self.assertTrue((last_run / "input.s").exists())
            self.assertTrue((last_run / "input.o").exists())
            self.assertIn('"project": 3', (last_run / "meta.json").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
