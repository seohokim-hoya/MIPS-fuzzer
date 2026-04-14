from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mips_fuzzer.config import load_config


class ConfigTests(unittest.TestCase):
    def test_load_config_reads_scalar_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "config.yml"
            path.write_text(
                "\n".join(
                    [
                        "preset: pdf_full",
                        "artifact_dir: custom-artifacts",
                        "iters: 25",
                        "timeout: 3.5",
                        "log_every: 7",
                        "report_coverage_every: 11",
                        "allow_empty_data: true",
                        "allow_negative_memory_offsets: yes",
                        "coverage_mode: coverage_first",
                        "coverage_targets: opcode:lw, mem_offset:negative",
                        "complexity_mode: hard",
                        "complexity_ramp_interval: 99",
                        "use_small_exhaustive_first: on",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            config = load_config(path)
            self.assertEqual(config["preset"], "pdf_full")
            self.assertEqual(config["artifact_dir"], "custom-artifacts")
            self.assertEqual(config["iters"], 25)
            self.assertEqual(config["timeout"], 3.5)
            self.assertEqual(config["log_every"], 7)
            self.assertEqual(config["report_coverage_every"], 11)
            self.assertTrue(config["allow_empty_data"])
            self.assertTrue(config["allow_negative_memory_offsets"])
            self.assertEqual(config["coverage_mode"], "coverage_first")
            self.assertEqual(config["coverage_targets"], ("opcode:lw", "mem_offset:negative"))
            self.assertEqual(config["complexity_mode"], "hard")
            self.assertEqual(config["complexity_ramp_interval"], 99)
            self.assertTrue(config["use_small_exhaustive_first"])

    def test_load_config_rejects_unknown_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "config.yml"
            path.write_text("unknown_key: 1\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
