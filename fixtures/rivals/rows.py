"""Turn what a diff tool writes into the rows of fixtures/rivals.sh.

Usage: rows.py radare2|ghidra TOOL_OUTPUT ROWS_JSON

Each tool reports in its own form. This writes the rows each one shows as
changed, gone or new, the lowest score first, as a reader of that tool sorts
them. A row that is gone or new has no score and comes last.
"""

import json
import sys


def radare2_rows(report):
    """The functions `radiff2 -C` shows as not the same.

    radiff2 lists each function of the first file with the function of the
    second it pairs it with. It labels a row MATCH or UNMATCH, but a MATCH
    row can still have a similarity below 1, so either one counts. A
    function it pairs with nothing has no `diff_addr`.
    """
    rows = []
    for function in report:
        if function["match"] == "MATCH" and function["dist"] >= 1.0:
            continue
        after = function.get("diff_addr") or None
        score = function["dist"] if after is not None else None
        rows.append({"before": function["addr"], "after": after, "score": score})
    return rows


def ghidra_rows(report):
    """The pairs Version Tracking found changed, then the gone and new."""
    changed = [dict(pair) for pair in report["changed"]]
    gone = [{"before": entry, "after": None, "score": None} for entry in report["gone"]]
    new = [{"before": None, "after": entry, "score": None} for entry in report["new"]]
    return changed + gone + new


def by_score(row):
    """Sort the lowest score first, and the rows with no score last."""
    unscored = row["score"] is None
    return (unscored, row["score"] or 0.0, row["before"] or 0, row["after"] or 0)


def main():
    tool, source, target = sys.argv[1:]
    with open(source, encoding="utf-8") as file:
        report = json.load(file)
    rows = {"radare2": radare2_rows, "ghidra": ghidra_rows}[tool](report)
    rows.sort(key=by_score)
    with open(target, "w", encoding="utf-8") as file:
        json.dump({"rows": rows}, file, indent=1)
        file.write("\n")


if __name__ == "__main__":
    main()
