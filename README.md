# MIPS Fuzzer

- Generate MIPS input (based on project of CS.30101 @ KAIST) at random.
- Compare two outputs of generated input, run by `sample/main.c(pp)` and `user/main.c(pp)`.

## How to use

1. Put your `main.c(pp)` file in `user/`.
2. Put other's `main.c(pp)` file in `sample/`.

> `./fuzz.py --preset pdf_full`.

(You may need python3 to run this code)

Other details in `fuzz.py`, `mips_fuzzer/*`, and `tests/`. (Ask to LLMs)
