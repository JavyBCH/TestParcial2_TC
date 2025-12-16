from __future__ import annotations

from typing import List, Optional


def _import_quiz():
    # Works from project root (package) or inside quiz_app (local).
    try:
        from quiz_app import quiz  # type: ignore

        return quiz
    except ModuleNotFoundError:
        import quiz  # type: ignore

        return quiz


def _import_ui():
    try:
        from quiz_app.ui import C, clear_screen, color, hr  # type: ignore

        return C, clear_screen, color, hr
    except ModuleNotFoundError:
        from ui import C, clear_screen, color, hr  # type: ignore

        return C, clear_screen, color, hr


def _ask_choice(prompt: str, choices: List[str], default: Optional[str] = None) -> str:
    choices_l = [c.lower() for c in choices]
    default_l = default.lower() if default else None
    while True:
        raw = input(prompt).strip()
        if raw == "" and default_l:
            return default_l
        raw_l = raw.lower()
        if raw_l in choices_l:
            return raw_l
        print(f"Invalid. Options: {', '.join(choices)}")


def _ask_int(prompt: str, default: int, min_v: int, max_v: int) -> int:
    while True:
        raw = input(prompt).strip()
        if raw == "":
            return default
        try:
            v = int(raw)
        except ValueError:
            print("Enter a number.")
            continue
        if v < min_v or v > max_v:
            print(f"Enter a value between {min_v} and {max_v}.")
            continue
        return v


def _ask_yesno(prompt: str, default_yes: bool) -> bool:
    d = "y" if default_yes else "n"
    while True:
        raw = input(f"{prompt} [y/n] (default {d}): ").strip().lower()
        if raw == "":
            return default_yes
        if raw in {"y", "yes"}:
            return True
        if raw in {"n", "no"}:
            return False
        print("Enter y or n.")


def main() -> int:
    quiz = _import_quiz()
    C, clear_screen, color, hr = _import_ui()

    while True:
        clear_screen()
        print(color("Cybersecurity Quiz", C.CYAN, C.BOLD))
        print(color("Labs 3–6 + Theory | 30Q exam rules", C.DIM))
        print(hr())
        print(color("1) Start EXAM (30 questions, timed)", C.YELLOW))
        print(color("2) Start PRACTICE (no timer)", C.YELLOW))
        print(color("3) Exit", C.YELLOW))
        print(hr())

        mode = _ask_choice("Choose (1/2/3): ", ["1", "2", "3"])
        if mode == "3":
            return 0

        bank = _ask_choice("Bank (labs/theory/both) [labs]: ", ["labs", "theory", "both"], default="labs")

        if mode == "1":
            minutes = _ask_int("Minutes [70]: ", default=70, min_v=1, max_v=300)
            count = _ask_int("Number of questions [30]: ", default=30, min_v=1, max_v=200)
            practice = False
        else:
            minutes = 70  # unused
            count = _ask_int("Number of questions [10]: ", default=10, min_v=1, max_v=200)
            practice = True

        rotate = _ask_yesno("Rotation (avoid repeats across runs)?", default_yes=True)
        reset_rotation = False
        if rotate:
            reset_rotation = _ask_yesno("Reset rotation history before starting?", default_yes=False)

        seed_raw = input("Seed (blank=random): ").strip()
        seed: Optional[int]
        if seed_raw == "":
            seed = None
        else:
            try:
                seed = int(seed_raw)
            except ValueError:
                print("Seed must be a number. Using random.")
                seed = None

        argv: List[str] = ["--bank", bank, "--count", str(count)]
        if practice:
            argv.append("--practice")
        else:
            argv.extend(["--minutes", str(minutes), "--exam"])

        if rotate:
            argv.append("--rotate")
        else:
            argv.append("--no-rotate")

        if reset_rotation:
            argv.append("--reset-rotation")

        if seed is not None:
            argv.extend(["--seed", str(seed)])

        print()
        input(color("Press Enter to start...", C.GREEN))
        clear_screen()
        rc = quiz.main(argv)
        print()
        input(color("Press Enter to return to menu...", C.GREEN))
        if rc != 0:
            # keep menu running even if quiz returns non-zero
            continue


if __name__ == "__main__":
    raise SystemExit(main())


