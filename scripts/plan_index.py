#!/usr/bin/env python3
"""Generate the task index in plan/README.md and check plan consistency.

A hand maintained table drifts from the files it describes, and once it drifts
nobody trusts it again. This reads the task files and writes the table between
two markers, leaving the rest of the document alone.

plan/ is not tracked by git (ADR-0047), so this only ever runs locally.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TASKS = ROOT / "plan" / "tasks"
DECISIONS = ROOT / "plan" / "decisions"
README = ROOT / "plan" / "README.md"

START = "<!-- GOREV-INDEKSI-BASLANGIC -->"
END = "<!-- GOREV-INDEKSI-BITIS -->"

VALID_STATES = ("todo", "devam", "bloke", "bitti")
HEADERS = ("ID", "Görev", "Milestone", "Durum", "Bağımlılık")

TASK_ID = re.compile(r"^T-\d{3}$")
ADR_ID = re.compile(r"^ADR-\d{4}$")


class PlanError(Exception):
    """A problem that must stop the run rather than be reported and ignored."""


def parse_front_matter(path: Path) -> dict[str, object]:
    """Read the leading --- block. Deliberately simple: no YAML dependency."""
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        raise PlanError(f"{path.name}: no front matter")

    fields: dict[str, object] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if ":" not in line:
            continue
        key, _, raw = line.partition(":")
        key = key.strip()
        raw = raw.strip()
        if raw.startswith("[") and raw.endswith("]"):
            inner = raw[1:-1].strip()
            fields[key] = [v.strip() for v in inner.split(",") if v.strip()]
        else:
            fields[key] = raw
    else:
        raise PlanError(f"{path.name}: front matter is not closed")

    for required in ("id", "baslik", "durum", "milestone"):
        if required not in fields:
            raise PlanError(f"{path.name}: missing field '{required}'")
    return fields


def load_tasks() -> list[dict[str, object]]:
    if not TASKS.is_dir():
        raise PlanError(f"{TASKS} does not exist")
    tasks = [parse_front_matter(p) | {"path": p} for p in sorted(TASKS.glob("T-*.md"))]
    if not tasks:
        raise PlanError(f"no task files under {TASKS}")
    return tasks


def known_adrs() -> set[str]:
    if not DECISIONS.is_dir():
        return set()
    return {p.name.split("-")[0] + "-" + p.name.split("-")[1] for p in DECISIONS.glob("ADR-*.md")}


def check(tasks: list[dict[str, object]]) -> list[str]:
    """Return every problem found, so one run shows all of them."""
    problems: list[str] = []
    ids: dict[str, str] = {}
    adrs = known_adrs()

    for task in tasks:
        name = task["path"].name
        tid = str(task["id"])

        if not TASK_ID.match(tid):
            problems.append(f"{name}: id '{tid}' is not in T-XXX form")
        if tid in ids:
            problems.append(f"{name}: id '{tid}' is already used by {ids[tid]}")
        else:
            ids[tid] = name
        if not name.startswith(tid + "-"):
            problems.append(f"{name}: file name does not start with its id '{tid}'")
        if task["durum"] not in VALID_STATES:
            problems.append(
                f"{name}: durum '{task['durum']}' is not one of {', '.join(VALID_STATES)}"
            )

    for task in tasks:
        name = task["path"].name
        for dep in task.get("bagimlilik", []):
            if dep not in ids:
                problems.append(f"{name}: depends on '{dep}', which has no task file")
        for adr in task.get("kararlar", []):
            if not ADR_ID.match(adr):
                problems.append(f"{name}: karar '{adr}' is not in ADR-XXXX form")
            elif adrs and adr not in adrs:
                problems.append(f"{name}: references '{adr}', which has no decision file")

    # A task cannot be finished while something it depends on is not.
    for task in tasks:
        if task["durum"] != "bitti":
            continue
        for dep in task.get("bagimlilik", []):
            dep_task = next((t for t in tasks if t["id"] == dep), None)
            if dep_task is not None and dep_task["durum"] != "bitti":
                problems.append(
                    f"{task['path'].name}: marked bitti but {dep} is '{dep_task['durum']}'"
                )

    problems.extend(check_milestone_order(tasks))

    return problems


def milestone_number(task: dict[str, object]) -> int:
    """M7 -> 7. An unparseable milestone sorts last rather than crashing."""
    raw = str(task["milestone"]).strip()
    return int(raw[1:]) if raw[:1] == "M" and raw[1:].isdigit() else 999


def check_milestone_order(tasks: list[dict[str, object]]) -> list[str]:
    """No milestone may be started while an earlier one still has open work.

    The dependency check does not catch this. A task nothing depends on blocks
    nobody, so it drifts across milestones without ever failing anything.

    M1 is exempt: the roadmap runs the risk spikes early on purpose.
    """
    problems: list[str] = []
    open_before: dict[int, list[str]] = {}

    for task in sorted(tasks, key=milestone_number):
        number = milestone_number(task)
        if task["durum"] != "bitti":
            open_before.setdefault(number, []).append(str(task["id"]))

    for task in tasks:
        if task["durum"] != "bitti":
            continue
        number = milestone_number(task)
        if number == 1:
            continue
        blocking = [
            f"{tid} (M{earlier})"
            for earlier, ids in sorted(open_before.items())
            if earlier < number and earlier != 1
            for tid in ids
        ]
        if blocking:
            problems.append(
                f"{task['path'].name}: bitti in M{number} while an earlier "
                f"milestone is still open: {', '.join(blocking)}"
            )
    return problems


def milestone_gaps(tasks: list[dict[str, object]]) -> list[str]:
    """Report a task scheduled long after everything it needs is ready.

    A gap is not automatically wrong, so this warns instead of failing. It
    exists because nothing else surfaces the question at all.
    """
    by_id = {str(t["id"]): t for t in tasks}
    notes: list[str] = []
    for task in sorted(tasks, key=lambda t: str(t["id"])):
        deps = [by_id[d] for d in task.get("bagimlilik", []) if d in by_id]
        if not deps:
            continue
        ready = max(milestone_number(d) for d in deps)
        gap = milestone_number(task) - ready
        if gap >= 4:
            notes.append(
                f"{task['id']} sits in M{milestone_number(task)} but everything "
                f"it needs is ready by M{ready} (gap {gap}): {task['baslik']}"
            )
    return notes


def execution_order(tasks: list[dict[str, object]]) -> list[dict[str, object]]:
    """Milestone first, then dependencies, then id.

    Sorting by id alone produced an index whose last rows were M3 and M2 tasks,
    which is not an order anyone executes.
    """
    remaining = sorted(tasks, key=lambda t: (milestone_number(t), str(t["id"])))
    placed: set[str] = set()
    ordered: list[dict[str, object]] = []

    while remaining:
        ready = [
            t
            for t in remaining
            if all(d in placed for d in t.get("bagimlilik", []) if any(str(x["id"]) == d for x in tasks))
        ]
        # A cycle would leave nothing ready. The graph is checked elsewhere, so
        # fall back to the head rather than looping forever.
        chosen = ready[0] if ready else remaining[0]
        ordered.append(chosen)
        placed.add(str(chosen["id"]))
        remaining.remove(chosen)
    return ordered


def render(tasks: list[dict[str, object]]) -> str:
    rows = [
        [
            str(t["id"]),
            str(t["baslik"]),
            str(t["milestone"]),
            str(t["durum"]),
            ", ".join(t.get("bagimlilik", [])),
        ]
        for t in execution_order(tasks)
    ]

    widths = [
        max(len(HEADERS[i]), max((len(r[i]) for r in rows), default=0))
        for i in range(len(HEADERS))
    ]

    def line(cells: list[str]) -> str:
        return "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells)) + " |"

    out = [line(list(HEADERS)), "|" + "|".join("-" * (w + 2) for w in widths) + "|"]
    out += [line(r) for r in rows]
    return "\n".join(out)


def write_index(table: str) -> bool:
    """Replace the block between the markers. Returns True if the file changed."""
    text = README.read_text(encoding="utf-8")
    if START not in text or END not in text:
        raise PlanError(f"{README.name}: index markers not found")

    head, _, rest = text.partition(START)
    _, _, tail = rest.partition(END)
    new = f"{head}{START}\n\n{table}\n\n{END}{tail}"

    if new == text:
        return False
    README.write_text(new, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="only report problems; do not write the index",
    )
    args = parser.parse_args()

    try:
        tasks = load_tasks()
        problems = check(tasks)

        if problems:
            for problem in problems:
                print(f"plan: {problem}")
            print(f"plan check failed: {len(problems)} problem(s)")
            return 1

        # Warnings, not failures: a long gap can be deliberate. Printing it is
        # the only way the question gets asked at all.
        for note in milestone_gaps(tasks):
            print(f"plan warning: {note}")

        if args.check:
            print(f"plan check passed: {len(tasks)} task(s)")
            return 0

        changed = write_index(render(tasks))
        state = "updated" if changed else "already current"
        print(f"plan index {state}: {len(tasks)} task(s)")
        return 0
    except PlanError as exc:
        print(f"plan: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
