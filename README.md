# Python Self-Test App (Topics 3–6)

## What it does
- Has **two banks** (no JSON fallback):
  - **Labs** (~300): `question_bank.py`
  - **Theory** (~300): `theory_bank.py`
- By default, runs an **EXAM simulation**: **30 questions**, **70 minutes**, teacher scoring rules.
- Supports **multi-answer** questions (explicitly marked) with input like `A,C`.
- Allows leaving a question **blank** (press Enter).

---

## Exam rules implemented (from teacher email)
- **Duration:** 70 minutes (configurable).
- **Single-answer questions:** +1 correct, **−0.2** wrong, 0 blank.
- **Multi-answer questions:** explicitly stated; +1 only if exact match, otherwise **−0.3 per wrong selection**, 0 blank.
- Total: **30 points**.

---

## How to run (PC)
Recommended (from the project root `Parcial2`):

```bash
python -m quiz_app.quiz
```

Optional:
- Choose what to test:

```bash
python -m quiz_app.quiz --bank labs
python -m quiz_app.quiz --bank theory
python -m quiz_app.quiz --bank both
```

- Practice mode (10 random, no timer):

```bash
python -m quiz_app.quiz --practice
```

- Fixed seed (repeatable random quiz):

```bash
python -m quiz_app.quiz --seed 123
```

- Custom exam duration:

```bash
python -m quiz_app.quiz --minutes 70
```

- Rotation (avoid repeats across runs until pool cycles) is ON by default.
- Reset rotation history:

```bash
python -m quiz_app.quiz --reset-rotation
```

- Disable rotation (pure random each run):

```bash
python -m quiz_app.quiz --no-rotate
```

- Choose number of questions:

```bash
python -m quiz_app.quiz --count 30
python -m quiz_app.quiz --practice --count 20
```

If you prefer running from inside `quiz_app`:

```bash
cd quiz_app
python quiz.py --bank labs
```

---

## How to run (phone)
Any Python runner works (examples: **Pydroid 3** on Android, or **Termux** with Python).
1. Copy the `quiz_app` folder to your phone.
2. Run:
   - `python quiz.py`


