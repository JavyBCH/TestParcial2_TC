import argparse
import json
import os
import random
import sys
import time
from typing import Any
from typing import Dict, List, Optional, Set, Tuple


def _reindex_questions(questions: List[dict]) -> List[dict]:
    for i, q in enumerate(questions, start=1):
        q["id"] = i
    return questions


def _load_questions(bank: str) -> List[dict]:
    bank = bank.lower().strip()

    if bank == "labs":
        try:
            # Works when run from project root (package import)
            from quiz_app.question_bank import get_questions as get_labs  # type: ignore
        except ModuleNotFoundError:
            # Works when run from inside quiz_app (local import)
            from question_bank import get_questions as get_labs  # type: ignore

        qs = get_labs()
        if not isinstance(qs, list) or len(qs) < 30:
            raise ValueError("Labs question bank must return a list with at least 30 questions.")
        return qs

    if bank == "theory":
        try:
            from quiz_app.theory_bank import get_questions as get_theory  # type: ignore
        except ModuleNotFoundError:
            from theory_bank import get_questions as get_theory  # type: ignore

        qs = get_theory()
        if not isinstance(qs, list) or len(qs) < 30:
            raise ValueError("Theory question bank must return a list with at least 30 questions.")
        return qs

    if bank == "both":
        try:
            from quiz_app.question_bank import get_questions as get_labs  # type: ignore
            from quiz_app.theory_bank import get_questions as get_theory  # type: ignore
        except ModuleNotFoundError:
            from question_bank import get_questions as get_labs  # type: ignore
            from theory_bank import get_questions as get_theory  # type: ignore

        labs = get_labs()
        theory = get_theory()
        if not isinstance(labs, list) or not isinstance(theory, list):
            raise ValueError("Banks must return lists.")
        merged = list(labs) + list(theory)
        if len(merged) < 30:
            raise ValueError("Combined bank must have at least 30 questions.")
        return _reindex_questions(merged)

    raise ValueError("Invalid bank. Use: labs, theory, or both.")


def _rotation_state_path(base_dir: str) -> str:
    return os.path.join(base_dir, ".rotation_state.json")


def _load_rotation_state(base_dir: str) -> dict:
    p = _rotation_state_path(base_dir)
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_rotation_state(base_dir: str, state: dict) -> None:
    p = _rotation_state_path(base_dir)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def _select_with_rotation(
    questions: List[dict],
    count: int,
    rng: random.Random,
    base_dir: str,
    rotate: bool,
    reset_rotation: bool,
    rotation_key: str,
) -> List[dict]:
    if not rotate:
        quiz = list(questions)
        rng.shuffle(quiz)
        return quiz[:count]

    all_ids = [int(q.get("id")) for q in questions]
    id_to_q: Dict[int, dict] = {int(q.get("id")): q for q in questions}

    if reset_rotation:
        state: Dict[str, Any] = {}
    else:
        state = _load_rotation_state(base_dir)

    remaining_by_bank = state.get("remaining_by_bank")
    if not isinstance(remaining_by_bank, dict):
        remaining_by_bank = {}

    remaining = remaining_by_bank.get(rotation_key)
    if not isinstance(remaining, list) or not remaining:
        remaining_ids = list(all_ids)
    else:
        # keep only IDs still present
        remaining_ids = [i for i in remaining if i in id_to_q]
        if not remaining_ids:
            remaining_ids = list(all_ids)

    # If not enough remaining, reset cycle.
    if len(remaining_ids) < count:
        remaining_ids = list(all_ids)

    picked = rng.sample(remaining_ids, count)
    remaining_ids = [i for i in remaining_ids if i not in set(picked)]

    remaining_by_bank[rotation_key] = remaining_ids
    _save_rotation_state(base_dir, {"remaining_by_bank": remaining_by_bank})
    return [id_to_q[i] for i in picked]


def _normalize_answer(raw: str) -> Set[str]:
    raw = raw.strip().upper()
    if not raw:
        return set()
    if raw in {"S", "SKIP", "-"}:
        return set()
    parts = []
    for chunk in raw.replace(" ", "").split(","):
        if chunk:
            parts.append(chunk)
    # allow input like "AC" (no comma) for multi-select
    if len(parts) == 1 and len(parts[0]) > 1:
        parts = list(parts[0])
    return set(parts)


def _format_options(options: Dict[str, str]) -> str:
    letters = sorted(options.keys())
    lines = []
    for k in letters:
        lines.append(f"  {k}. {options[k]}")
    return "\n".join(lines)


def _ask_question(q: dict, idx: int, total: int, time_left_s: Optional[float]) -> Tuple[Set[str], Set[str], Set[str]]:
    multi = bool(q.get("multi", False))
    prompt_suffix = " [Multi-answer: select ALL that apply]" if multi else " [Single-answer]"

    print()
    if time_left_s is not None:
        mins = max(0, int(time_left_s // 60))
        secs = max(0, int(time_left_s % 60))
        print(f"Time left: {mins:02d}:{secs:02d}")
    print(f"Q{idx}/{total}{prompt_suffix}")
    print(q["question"])
    print(_format_options(q["options"]))

    valid = set(k.upper() for k in q["options"].keys())
    correct = set(x.upper() for x in q["correct"])

    while True:
        raw = input("Your answer (Enter=skip, e.g. A or A,C): ").strip()
        if raw == "":
            return set(), correct, valid
        ans = _normalize_answer(raw)
        if not ans:
            # explicit skip with S/SKIP/-
            return set(), correct, valid
        if not ans.issubset(valid):
            bad = sorted(ans - valid)
            print(f"Invalid option(s): {', '.join(bad)}. Valid: {', '.join(sorted(valid))}")
            continue
        if not multi and len(ans) != 1:
            print("This is a single-answer question. Enter exactly one option (e.g., B).")
            continue
        return ans, correct, valid


def _score_single(selected: Set[str], correct: Set[str]) -> float:
    # +1 correct, -0.2 wrong, 0 skipped
    if not selected:
        return 0.0
    return 1.0 if selected == correct else -0.2


def _score_multi(selected: Set[str], correct: Set[str]) -> Tuple[float, int]:
    """
    Teacher rule: multi-answer questions explicitly say so; penalty is -0.3 per wrong selection.
    We interpret “wrong selection” as selecting an option that is not part of the correct set.
    - Exact match => +1.
    - Otherwise => 0 minus 0.3 * (#wrong selected).
    - Skipped => 0.
    Score is capped at minimum -1.0 (can't lose more than 1 point on a question).
    """
    if not selected:
        return 0.0, 0
    if selected == correct:
        return 1.0, 0
    wrong_selected = len(selected - correct)
    score = 0.0 - 0.3 * wrong_selected
    if score < -1.0:
        score = -1.0
    return score, wrong_selected


def main() -> int:
    ap = argparse.ArgumentParser(description="Self-test quiz (Topics 3–6).")
    ap.add_argument("--practice", action="store_true", help="Practice mode: 10 random questions (no timer).")
    ap.add_argument("--exam", action="store_true", help="Exam mode: 30 questions, 70 minutes, teacher scoring (default).")
    ap.add_argument("--seed", type=int, default=None, help="Random seed (repeatable quizzes).")
    ap.add_argument("--minutes", type=int, default=70, help="Exam duration in minutes (default: 70).")
    ap.add_argument("--count", type=int, default=None, help="Number of questions (default: 30 exam / 10 practice).")
    ap.add_argument("--rotate", action="store_true", help="Rotate questions across runs (avoid repeats until pool cycles).")
    ap.add_argument("--no-rotate", action="store_true", help="Disable rotation across runs (pure random each run).")
    ap.add_argument("--reset-rotation", action="store_true", help="Reset rotation history (start a fresh cycle).")
    ap.add_argument("--bank", choices=["labs", "theory", "both"], default="labs", help="Question bank to use.")
    args = ap.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    questions = _load_questions(args.bank)

    if len(questions) < 30:
        print("Question bank must have at least 30 questions.", file=sys.stderr)
        return 2

    rng = random.Random(args.seed)
    exam_mode = args.exam or (not args.practice)

    if exam_mode:
        total = args.count if args.count is not None else 30
        time_limit_s = max(1, int(args.minutes * 60))
    else:
        total = args.count if args.count is not None else 10
        time_limit_s = None

    rotate = args.rotate or (not args.no_rotate)
    quiz = _select_with_rotation(
        questions=questions,
        count=total,
        rng=rng,
        base_dir=base_dir,
        rotate=rotate,
        reset_rotation=bool(args.reset_rotation),
        rotation_key=args.bank,
    )

    print(f"=== Cybersecurity Quiz ({args.bank.upper()}) ===")
    if args.seed is not None:
        print(f"(seed={args.seed})")
    if exam_mode:
        print(
            f"Mode: EXAM | Questions: {total} | Time limit: {args.minutes} min | Rotation: {'ON' if rotate else 'OFF'}"
        )
        print("Scoring:")
        print("- Single-answer: +1 correct, -0.2 wrong, 0 blank")
        print("- Multi-answer (explicit): +1 only if exact; otherwise -0.3 per WRONG selection; 0 blank")
        print()
        print("Tip: press Enter to leave a question blank.")
    else:
        print(f"Mode: PRACTICE | Questions: {total} | No timer | Rotation: {'ON' if rotate else 'OFF'}")
        print("Scoring uses the same rules as the exam.")

    start = time.monotonic()
    score = 0.0
    correct_count = 0
    wrong_count = 0
    skipped_count = 0

    for i, q in enumerate(quiz, start=1):
        if time_limit_s is not None:
            elapsed = time.monotonic() - start
            left = time_limit_s - elapsed
            if left <= 0:
                print()
                print("=== Time is up. Auto-submitting. ===")
                break
        else:
            left = None

        selected, correct, _valid = _ask_question(q, i, total, left)
        multi = bool(q.get("multi", False))

        if not selected:
            skipped_count += 1
            print("Blank (0 points).")
            continue

        if multi:
            delta, wrong_sel = _score_multi(selected, correct)
            score += delta
            if delta == 1.0:
                correct_count += 1
                print("Correct. (+1)")
            else:
                wrong_count += 1
                print(f"Incorrect. ({delta:+.1f}) | Correct: {','.join(sorted(correct))} | Wrong selections: {wrong_sel}")
        else:
            delta = _score_single(selected, correct)
            score += delta
            if delta == 1.0:
                correct_count += 1
                print("Correct. (+1)")
            else:
                wrong_count += 1
                print(f"Incorrect. ({delta:+.1f}) | Correct: {','.join(sorted(correct))}")

        expl = q.get("explanation")
        if expl:
            print(f"Note: {expl}")

    print()
    print("=== Result ===")
    if time_limit_s is not None:
        elapsed = min(time_limit_s, time.monotonic() - start)
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)
        print(f"Time used: {mins:02d}:{secs:02d}")
    print(f"Answered: {correct_count + wrong_count} | Correct: {correct_count} | Wrong: {wrong_count} | Blank: {skipped_count}")
    print(f"Total score: {score:.1f} / {float(total):.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


