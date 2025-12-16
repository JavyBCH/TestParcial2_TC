# Python Self-Test App (Topics 3–6)

## What it does
- Uses a **large generated pool (~300 questions)** from `question_bank.py` (**no JSON fallback**).
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
From this folder:

```bash
python quiz.py
```

Optional:
- Practice mode (10 random, no timer):

```bash
python quiz.py --practice
```

- Fixed seed (repeatable random quiz):

```bash
python quiz.py --seed 123
```

- Custom exam duration:

```bash
python quiz.py --minutes 70
```

- Rotation (avoid repeats across runs until pool cycles) is ON by default.
- Reset rotation history:

```bash
python quiz.py --reset-rotation
```

- Disable rotation (pure random each run):

```bash
python quiz.py --no-rotate
```

- Choose number of questions:

```bash
python quiz.py --count 30
python quiz.py --practice --count 20
```

---

## How to run (phone)
Any Python runner works (examples: **Pydroid 3** on Android, or **Termux** with Python).
1. Copy the `quiz_app` folder to your phone.
2. Run:
   - `python quiz.py`


