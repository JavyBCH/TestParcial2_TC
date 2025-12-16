# Python Self-Test App (Topics 3–6)

## What it does
- Has **two banks** (hardcoded question files):
  - **Labs** (~300): `banks/labs.json`
  - **Theory** (~300): `banks/theory.json`
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
Menu (recommended, no parameters):

```bash
python -m quiz_app
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
python main.py
```

---

## How to run (phone)
Any Python runner works (examples: **Pydroid 3** on Android, or **Termux** with Python).
1. Copy the `quiz_app` folder to your phone.
2. Run:
   - `python quiz.py`

---

## Editing / adding questions
- Edit `quiz_app/banks/labs.json` and/or `quiz_app/banks/theory.json`.
- Each question is an object with:
  - `question`, `options` (A-D), `correct` (e.g. `["B"]`), `multi` (`true`/`false`), optional `explanation`
- **Multi-answer** questions should say so in the `question` text and `correct` should include multiple letters (e.g. `["A","C"]`).


