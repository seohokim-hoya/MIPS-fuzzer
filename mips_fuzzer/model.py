from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace

DATA_BASE_ADDRESS = 0x10000000
TEXT_BASE_ADDRESS = 0x00400000

THREE_REGISTER_OPCODES = {"addu", "subu", "and", "or", "nor", "sltu"}
SHIFT_OPCODES = {"sll", "srl"}
SIGNED_IMMEDIATE_OPCODES = {"addiu", "sltiu"}
UNSIGNED_IMMEDIATE_OPCODES = {"andi", "ori", "lui"}
MEMORY_OPCODES = {"lw", "sw"}
BRANCH_OPCODES = {"beq", "bne"}
JUMP_OPCODES = {"j", "jal"}
SPECIAL_OPCODES = {"jr", "la"}
ALL_OPCODES = (
    THREE_REGISTER_OPCODES
    | SHIFT_OPCODES
    | SIGNED_IMMEDIATE_OPCODES
    | UNSIGNED_IMMEDIATE_OPCODES
    | MEMORY_OPCODES
    | BRANCH_OPCODES
    | JUMP_OPCODES
    | SPECIAL_OPCODES
)


@dataclass
class NumberLiteral:
    value: int
    prefer_hex: bool = False
    bit_width: int = 32

    def render(self) -> str:
        if self.prefer_hex:
            mask = (1 << self.bit_width) - 1
            width = max(1, (self.bit_width + 3) // 4)
            return f"0x{(self.value & mask):0{width}x}"
        return str(self.value)


@dataclass
class DataLabel:
    name: str
    words: list[NumberLiteral]
    word_groups: tuple[int, ...] = ()

    def grouped_words(self) -> list[list[NumberLiteral]]:
        if not self.words:
            return []
        if not self.word_groups:
            return [[word] for word in self.words]
        groups: list[list[NumberLiteral]] = []
        index = 0
        for group_size in self.word_groups:
            groups.append(self.words[index : index + group_size])
            index += group_size
        return groups


@dataclass
class Instruction:
    opcode: str
    operands: tuple[object, ...]

    def render(self) -> str:
        if self.opcode in THREE_REGISTER_OPCODES:
            rd, rs, rt = self.operands
            return f"{self.opcode} {_reg(rd)}, {_reg(rs)}, {_reg(rt)}"
        if self.opcode in SHIFT_OPCODES:
            rd, rt, shamt = self.operands
            return f"{self.opcode} {_reg(rd)}, {_reg(rt)}, {_num(shamt)}"
        if self.opcode in SIGNED_IMMEDIATE_OPCODES:
            rt, rs, immediate = self.operands
            return f"{self.opcode} {_reg(rt)}, {_reg(rs)}, {_num(immediate)}"
        if self.opcode in {"andi", "ori"}:
            rt, rs, immediate = self.operands
            return f"{self.opcode} {_reg(rt)}, {_reg(rs)}, {_num(immediate)}"
        if self.opcode == "lui":
            rt, immediate = self.operands
            return f"{self.opcode} {_reg(rt)}, {_num(immediate)}"
        if self.opcode in MEMORY_OPCODES:
            rt, offset, base = self.operands
            return f"{self.opcode} {_reg(rt)}, {_num(offset)}({_reg(base)})"
        if self.opcode in BRANCH_OPCODES:
            rs, rt, label = self.operands
            return f"{self.opcode} {_reg(rs)}, {_reg(rt)}, {label}"
        if self.opcode in JUMP_OPCODES:
            (label,) = self.operands
            return f"{self.opcode} {label}"
        if self.opcode == "jr":
            (rs,) = self.operands
            return f"{self.opcode} {_reg(rs)}"
        if self.opcode == "la":
            rd, label = self.operands
            return f"{self.opcode} {_reg(rd)}, {label}"
        raise ValueError(f"unsupported opcode: {self.opcode}")

    def referenced_text_labels(self) -> set[str]:
        if self.opcode in BRANCH_OPCODES or self.opcode in JUMP_OPCODES:
            return {str(self.operands[-1])}
        return set()

    def referenced_data_labels(self) -> set[str]:
        if self.opcode == "la":
            return {str(self.operands[1])}
        return set()

    def written_registers(self) -> tuple[int, ...]:
        if self.opcode in THREE_REGISTER_OPCODES or self.opcode in SHIFT_OPCODES:
            return (int(self.operands[0]),)
        if self.opcode in SIGNED_IMMEDIATE_OPCODES or self.opcode in {"andi", "ori"}:
            return (int(self.operands[0]),)
        if self.opcode == "lui":
            return (int(self.operands[0]),)
        if self.opcode == "lw":
            return (int(self.operands[0]),)
        if self.opcode == "la":
            return (int(self.operands[0]),)
        if self.opcode == "jal":
            return (31,)
        return ()

    def numeric_operand_indexes(self) -> list[int]:
        return [index for index, operand in enumerate(self.operands) if isinstance(operand, NumberLiteral)]

    def replace_operand(self, index: int, operand: object) -> "Instruction":
        mutable = list(self.operands)
        mutable[index] = operand
        return replace(self, operands=tuple(mutable))


@dataclass
class TextLine:
    labels: list[str] = field(default_factory=list)
    instruction: Instruction | None = None


@dataclass
class Program:
    data_labels: list[DataLabel]
    text_lines: list[TextLine]

    def clone(self) -> "Program":
        return copy.deepcopy(self)

    def has_instructions(self) -> bool:
        return any(line.instruction is not None for line in self.text_lines)

    def data_addresses(self) -> dict[str, int]:
        address = DATA_BASE_ADDRESS
        result: dict[str, int] = {}
        for data_label in self.data_labels:
            result[data_label.name] = address
            address += len(data_label.words) * 4
        return result

    def data_label_sizes(self) -> dict[str, int]:
        return {data_label.name: len(data_label.words) for data_label in self.data_labels}

    def text_labels(self) -> set[str]:
        labels: set[str] = set()
        for line in self.text_lines:
            labels.update(line.labels)
        return labels

    def referenced_data_labels(self) -> set[str]:
        refs: set[str] = set()
        for line in self.text_lines:
            if line.instruction is not None:
                refs.update(line.instruction.referenced_data_labels())
        return refs

    def referenced_text_labels(self) -> set[str]:
        refs: set[str] = set()
        for line in self.text_lines:
            if line.instruction is not None:
                refs.update(line.instruction.referenced_text_labels())
        return refs

    def expanded_text_word_count(self) -> int:
        data_addresses = self.data_addresses()
        count = 0
        for line in self.text_lines:
            if line.instruction is None:
                continue
            if line.instruction.opcode != "la":
                count += 1
                continue
            _, label = line.instruction.operands
            address = data_addresses[str(label)]
            count += 1 if (address & 0xFFFF) == 0 else 2
        return count

    def validate(self) -> list[str]:
        issues: list[str] = []
        if not self.text_lines:
            issues.append("program must contain a text section")
        if not self.has_instructions():
            issues.append("program must contain at least one instruction")

        all_labels: set[str] = set()
        for data_label in self.data_labels:
            if not data_label.words:
                issues.append(f"data label {data_label.name} must contain at least one word")
            if data_label.word_groups:
                if any(group_size <= 0 for group_size in data_label.word_groups):
                    issues.append(f"data label {data_label.name} has non-positive .word group size")
                if sum(data_label.word_groups) != len(data_label.words):
                    issues.append(
                        f"data label {data_label.name} .word groups do not cover all words"
                    )
            if data_label.name in all_labels:
                issues.append(f"duplicate label name: {data_label.name}")
            all_labels.add(data_label.name)
            for word in data_label.words:
                if not -(1 << 31) <= word.value <= (1 << 32) - 1:
                    issues.append(f"data word out of range for label {data_label.name}: {word.value}")

        text_labels = self.text_labels()
        duplicates = all_labels & text_labels
        if duplicates:
            for name in sorted(duplicates):
                issues.append(f"label reused across sections: {name}")

        seen_text_labels: set[str] = set()
        for line in self.text_lines:
            for label in line.labels:
                if label in seen_text_labels:
                    issues.append(f"duplicate text label: {label}")
                seen_text_labels.add(label)
            if line.instruction is not None:
                issues.extend(self._validate_instruction(line.instruction, text_labels))

        data_label_names = {label.name for label in self.data_labels}
        for missing in sorted(self.referenced_data_labels() - data_label_names):
            issues.append(f"missing data label reference: {missing}")
        for missing in sorted(self.referenced_text_labels() - text_labels):
            issues.append(f"missing text label reference: {missing}")
        return issues

    def assert_valid(self) -> None:
        issues = self.validate()
        if issues:
            raise ValueError("; ".join(issues))

    def render(self) -> str:
        lines = [".data"]
        for data_label in self.data_labels:
            lines.append(f"{data_label.name}:")
            for group in data_label.grouped_words():
                rendered_words = ", ".join(word.render() for word in group)
                lines.append(f".word {rendered_words}")
        lines.append(".text")
        for text_line in self.text_lines:
            for label in text_line.labels:
                lines.append(f"{label}:")
            if text_line.instruction is not None:
                lines.append(text_line.instruction.render())
        return "\n".join(lines) + "\n"

    def _validate_instruction(self, instruction: Instruction, text_labels: set[str]) -> list[str]:
        issues: list[str] = []
        opcode = instruction.opcode
        if opcode not in ALL_OPCODES:
            return [f"unsupported opcode: {opcode}"]

        try:
            if opcode in THREE_REGISTER_OPCODES:
                rd, rs, rt = instruction.operands
                issues.extend(_validate_registers(rd, rs, rt))
            elif opcode in SHIFT_OPCODES:
                rd, rt, shamt = instruction.operands
                issues.extend(_validate_registers(rd, rt))
                issues.extend(_validate_range(shamt, 0, 31, "shift amount"))
            elif opcode in SIGNED_IMMEDIATE_OPCODES:
                rt, rs, immediate = instruction.operands
                issues.extend(_validate_registers(rt, rs))
                issues.extend(_validate_range(immediate, -(1 << 15), (1 << 15) - 1, f"{opcode} immediate"))
            elif opcode in {"andi", "ori"}:
                rt, rs, immediate = instruction.operands
                issues.extend(_validate_registers(rt, rs))
                issues.extend(_validate_range(immediate, 0, (1 << 16) - 1, f"{opcode} immediate"))
            elif opcode == "lui":
                rt, immediate = instruction.operands
                issues.extend(_validate_registers(rt))
                issues.extend(_validate_range(immediate, 0, (1 << 16) - 1, "lui immediate"))
            elif opcode in MEMORY_OPCODES:
                rt, offset, base = instruction.operands
                issues.extend(_validate_registers(rt, base))
                issues.extend(_validate_range(offset, -(1 << 15), (1 << 15) - 1, f"{opcode} offset"))
                if int(offset.value) % 4 != 0:
                    issues.append(f"{opcode} offset must be word-aligned: {offset.value}")
            elif opcode in BRANCH_OPCODES:
                rs, rt, label = instruction.operands
                issues.extend(_validate_registers(rs, rt))
                if str(label) not in text_labels:
                    issues.append(f"unknown branch label: {label}")
            elif opcode in JUMP_OPCODES:
                (label,) = instruction.operands
                if str(label) not in text_labels:
                    issues.append(f"unknown jump label: {label}")
            elif opcode == "jr":
                (rs,) = instruction.operands
                issues.extend(_validate_registers(rs))
            elif opcode == "la":
                rd, label = instruction.operands
                issues.extend(_validate_registers(rd))
                if not isinstance(label, str):
                    issues.append("la target must be a data label string")
        except (TypeError, ValueError) as exc:
            issues.append(f"invalid operands for {opcode}: {exc}")
        return issues


def _reg(value: object) -> str:
    return f"${int(value)}"


def _num(value: object) -> str:
    if isinstance(value, NumberLiteral):
        return value.render()
    return str(value)


def _validate_registers(*registers: object) -> list[str]:
    issues: list[str] = []
    for register in registers:
        register_value = int(register)
        if not 0 <= register_value <= 31:
            issues.append(f"register out of range: {register_value}")
    return issues


def _validate_range(literal: object, minimum: int, maximum: int, label: str) -> list[str]:
    value = literal.value if isinstance(literal, NumberLiteral) else int(literal)
    if minimum <= value <= maximum:
        return []
    return [f"{label} out of range: {value}"]
