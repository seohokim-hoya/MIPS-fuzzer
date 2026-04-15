# MIPS Fuzzer

CS.30101 Architecture (KAIST) 과제 제출물을 자동으로 검증하는 differential fuzzer.

랜덤 MIPS 프로그램을 생성해 `ref`와 `user` 두 구현체의 실행 결과를 비교하고, 차이가 발생하면 해당 입력을 저장한다.

---

## 디렉토리 구조

```
runfiles/Project-N/
├── ref/    ← 레퍼런스 구현 파일
└── user/   ← 테스트할 제출 파일

shared/Project-N/   ← 공통 프레임워크 파일 (제출하지 않는 파일)
artifacts/          ← 차이가 발생한 테스트 케이스 저장
```

### 프로젝트별 파일 위치

| 프로젝트              | ref/                   | user/                  | shared/                    |
| --------------------- | ---------------------- | ---------------------- | -------------------------- |
| **P1** MIPS Assembler | `main.c` or `main.cpp` | `main.c` or `main.cpp` | (없음)                     |
| **P2** MIPS Simulator | `run.c`, `parse.c`     | `run.c`, `parse.c`     | `cs311.c`, `util.c`, `*.h` |

---

## 빠른 시작

### Project 1 — MIPS Assembler

```bash
# 1. 테스트할 제출물을 user/ 에 배치
cp student_main.cpp runfiles/Project-1/user/main.cpp

# 2. 실행
./fuzz.py --project 1
```

### Project 2 — MIPS Simulator

```bash
# 1. 테스트할 제출물을 user/ 에 배치
cp student_run.c   runfiles/Project-2/user/run.c
cp student_parse.c runfiles/Project-2/user/parse.c

# 2. 실행
./fuzz.py --project 2
```

다른 학생 제출물로 교체하려면 `user/` 안의 파일만 바꾸고 다시 실행하면 된다.

---

## 주요 옵션

```
--project N       테스트할 프로젝트 번호 (1 또는 2, 기본값: 1)
--iters N         반복 횟수 (0 = 무한, 기본값: 0)
--preset pdf_full 강의 채점 기준에 맞는 확장 설정
--seed N          재현 가능한 테스트를 위한 시드 고정
--timeout N       실행 제한 시간(초) (기본값: 2.0)
```

---

## 실행 결과

차이가 감지되면 `artifacts/` 폴더에 저장된다.

```
artifacts/
├── last_run/                              ← 가장 최근 테스트
└── iter-000042-seed-1234567-mismatch/     ← 차이가 발생한 케이스
    ├── input.s       ← 차이를 유발한 입력 프로그램
    ├── diff.txt      ← ref vs user 비교 요약
    ├── ref.stdout    ← 레퍼런스 출력
    ├── user.stdout   ← 제출물 출력
    └── meta.json     ← 상세 메타데이터
```
