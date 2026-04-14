from __future__ import annotations

from pathlib import Path


DEFAULT_CONFIG: dict[str, object] = {
    "preset": "default",
    "artifact_dir": "artifacts",
    "iters": 0,
    "timeout": 2.0,
    "log_every": 100,
    "report_coverage_every": 100,
    "min_data_labels": 2,
    "max_data_labels": 5,
    "min_words_per_label": 1,
    "max_words_per_label": 4,
    "min_text": 8,
    "max_text": 24,
    "max_total_data_words": 0,
    "max_total_text_words": 0,
    "edge_prob": 0.35,
    "allow_empty_data": False,
    "allow_multi_value_word": False,
    "allow_negative_memory_offsets": False,
    "allow_zero_dest_register": False,
    "coverage_mode": "biased",
    "coverage_targets": (),
    "complexity_mode": "mixed",
    "complexity_ramp_interval": 250,
    "use_small_exhaustive_first": False,
}


def load_config(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}

    result: dict[str, object] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            raise ValueError(f"{path}:{line_number}: expected 'key: value'")
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key not in DEFAULT_CONFIG:
            raise ValueError(f"{path}:{line_number}: unknown config key '{key}'")
        result[key] = _coerce_value(key, value)
    return result


def _coerce_value(key: str, raw_value: str) -> object:
    value = _strip_quotes(raw_value)
    if key == "coverage_targets":
        if not value:
            return ()
        return tuple(part.strip() for part in value.split(",") if part.strip())
    if key in {
        "allow_empty_data",
        "allow_multi_value_word",
        "allow_negative_memory_offsets",
        "allow_zero_dest_register",
        "use_small_exhaustive_first",
    }:
        return _parse_bool(key, value)

    default_value = DEFAULT_CONFIG[key]
    if isinstance(default_value, bool):
        return _parse_bool(key, value)
    if isinstance(default_value, int):
        return int(value, 10)
    if isinstance(default_value, float):
        return float(value)
    return value


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _parse_bool(key: str, value: str) -> bool:
    normalized = value.lower()
    if normalized in {"true", "yes", "on", "1"}:
        return True
    if normalized in {"false", "no", "off", "0"}:
        return False
    raise ValueError(f"invalid boolean value for {key}: {value}")
