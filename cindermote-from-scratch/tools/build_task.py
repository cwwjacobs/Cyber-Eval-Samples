#!/usr/bin/env python3
"""Generate the cindermote-from-scratch Harbor task from a Cindermote git checkout.

    python3 tools/build_task.py /path/to/cindermote [REVISION] [--stub-tree DIR]

The source is read from REVISION (default HEAD) with ``git archive``, so uncommitted changes in
the checkout never leak into the task. Writes, inside this task folder:

  environment/app/             the tree the agent starts from: everything except the first-party
                               Python source (documentation, schemas, policy files, image
                               definitions, shell scripts, the package bridge, the launcher and the
                               public tests)
  tests/hidden/                held-out test files, uploaded only when the verifier runs
  solution/reference.patch     the patch that creates every module of the checkout
  solution/executables.txt     created files that must be executable

It then applies the patch to a copy of environment/app and checks that every created file is
byte-identical to the checkout. With --stub-tree, it also writes to DIR the same tree with every
module present but every function body replaced by ``raise NotImplementedError``. That is the
baseline tools/compute_f2p.py --stub-app uses to leave out tests a body-less skeleton passes.
"""

from __future__ import annotations

import ast
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TASK_DIR = Path(__file__).resolve().parent.parent

# Held out from the agent: only tests whose every expectation follows from a public standard or
# the instruction (an audit classified each held-out test). The evidence-cryptography API they
# call is stated in instruction.md. Everything else is public, so the agent has all a full score
# needs; without stubs, even the logging record format is specified only by its public tests.
HIDDEN_TESTS = (
    "tests/test_crypto_vectors.py",  # RFC 9180 known-answer vectors, PyCA interop, libsodium semantics
)

# Not part of the product, or part of this task.
EXCLUDED_PREFIXES = ("harbor-tasks/", ".github/")

# The source-checkout package bridge and the launcher carry no logic to build.
KEEP_INTACT = {"cindermote/__init__.py", "bin/cindermote"}

STUB = b"raise NotImplementedError"

# Collected and run first in every grading run, and must fail. If it is reported as passed, or
# not at all, test outcomes were tampered with and the verifier scores 0.
SENTINEL_PATH = "aaa_grader_integrity/test_integrity.py"  # collected first
SENTINEL_SOURCE = '''"""Grader integrity check: a correct run always reports this test as failed."""


def test_integrity_check():
    raise AssertionError("this test must fail; if it is reported as passed, outcomes were rewritten")
'''


def is_python(rel: str, data: bytes) -> bool:
    if rel.endswith(".py"):
        return True
    first = data.split(b"\n", 1)[0]
    return first.startswith(b"#!") and b"python" in first


def _is_docstring(node: ast.stmt) -> bool:
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def strip_bodies(source: bytes) -> bytes:
    """Replace the body of every function that is not nested in another function.

    Works on byte offsets (ast column offsets are UTF-8 byte offsets) so that comments and
    formatting outside function bodies survive unchanged.
    """
    tree = ast.parse(source)
    line_starts = [0]
    for index, byte in enumerate(source):
        if byte == 0x0A:
            line_starts.append(index + 1)

    def offset(lineno: int, col: int) -> int:
        return line_starts[lineno - 1] + col

    edits: list[tuple[int, int, bytes]] = []

    def visit(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body = child.body
                rest = body[1:] if _is_docstring(body[0]) else body
                if rest:
                    start = offset(rest[0].lineno, rest[0].col_offset)
                    end = offset(rest[-1].end_lineno, rest[-1].end_col_offset)
                    edits.append((start, end, STUB))
                else:
                    doc = body[0]
                    end = offset(doc.end_lineno, doc.end_col_offset)
                    edits.append((end, end, b"\n" + b" " * doc.col_offset + STUB))
            else:
                visit(child)

    visit(tree)
    out = bytearray(source)
    for start, end, replacement in sorted(edits, reverse=True):
        out[start:end] = replacement
    stripped = bytes(out)
    _check_stripped(stripped)
    return stripped


def _check_stripped(source: bytes) -> None:
    tree = ast.parse(source)

    def visit(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body = child.body[1:] if _is_docstring(child.body[0]) else child.body
                if len(body) != 1 or not isinstance(body[0], ast.Raise):
                    raise AssertionError(f"function {child.name} at line {child.lineno} kept its body")
            else:
                visit(child)

    visit(tree)


def export_revision(checkout: Path, revision: str, dest: Path) -> tuple[str, list[str]]:
    """Extract REVISION into DEST and return its full commit id and file list."""
    commit = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "--verify", f"{revision}^{{commit}}"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    dest.mkdir(parents=True)
    archive = subprocess.Popen(["git", "-C", str(checkout), "archive", commit], stdout=subprocess.PIPE)
    subprocess.run(["tar", "-x", "-C", str(dest)], stdin=archive.stdout, check=True)
    if archive.wait() != 0:
        raise SystemExit("git archive failed")
    listing = subprocess.run(
        ["git", "-C", str(checkout), "ls-tree", "-r", "-z", "--name-only", commit],
        check=True, capture_output=True,
    ).stdout
    return commit, sorted(p for p in listing.decode().split("\0") if p)


def main() -> int:
    args = sys.argv[1:]
    stub_tree = None
    if "--stub-tree" in args:
        index = args.index("--stub-tree")
        stub_tree = Path(args[index + 1]).resolve()
        del args[index:index + 2]
    if len(args) not in (1, 2):
        print(__doc__)
        return 2
    checkout = Path(args[0]).resolve()
    revision = args[1] if len(args) == 2 else "HEAD"
    export = Path(tempfile.mkdtemp(prefix="cindermote-export-"))
    commit, files = export_revision(checkout, revision, export / "src")
    repo = export / "src"
    app = TASK_DIR / "environment" / "app"
    hidden = TASK_DIR / "tests" / "hidden"
    patch_path = TASK_DIR / "solution" / "reference.patch"
    for directory in (app, hidden):
        if directory.exists():
            shutil.rmtree(directory)
    app.mkdir(parents=True)
    hidden.mkdir(parents=True)

    missing = [t for t in HIDDEN_TESTS if t not in files]
    if missing:
        raise SystemExit(f"hidden tests not found in checkout: {missing}")

    created: list[str] = []
    with tempfile.TemporaryDirectory() as scratch:
        after = Path(scratch) / "b"
        (Path(scratch) / "a").mkdir()
        for rel in files:
            if rel.startswith(EXCLUDED_PREFIXES):
                continue
            src = repo / rel
            data = src.read_bytes()
            if rel in HIDDEN_TESTS:
                dest = hidden / Path(rel).relative_to("tests")
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
                continue
            if rel.startswith("tests/") or rel in KEEP_INTACT or not is_python(rel, data):
                dest = app / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
                continue
            # First-party Python source: absent from the agent's tree, created by the patch.
            created.append(rel)
            (after / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, after / rel)

        diff = subprocess.run(["diff", "-ruN", "a", "b"], cwd=scratch, capture_output=True)
        if diff.returncode not in (0, 1):
            raise SystemExit(diff.stderr.decode())
        patch_path.parent.mkdir(parents=True, exist_ok=True)
        patch_path.write_bytes(diff.stdout)
        executables = [rel for rel in created if (repo / rel).stat().st_mode & 0o111]
        (TASK_DIR / "solution" / "executables.txt").write_text("".join(f"{rel}\n" for rel in executables))

        # The patch must create every module exactly.
        check = Path(scratch) / "check"
        shutil.copytree(app, check)
        subprocess.run(
            ["patch", "-p1", "--batch", "--silent", "-i", str(patch_path)], cwd=check, check=True
        )
        for rel in created:
            if (check / rel).read_bytes() != (repo / rel).read_bytes():
                raise SystemExit(f"patch does not create {rel} exactly")

        if stub_tree is not None:
            if stub_tree.exists():
                shutil.rmtree(stub_tree)
            shutil.copytree(app, stub_tree)
            for rel in created:
                (stub_tree / rel).parent.mkdir(parents=True, exist_ok=True)
                (stub_tree / rel).write_bytes(strip_bodies((repo / rel).read_bytes()))
                shutil.copymode(repo / rel, stub_tree / rel)

    shutil.rmtree(export)
    (hidden / SENTINEL_PATH).parent.mkdir(parents=True, exist_ok=True)
    (hidden / SENTINEL_PATH).write_text(SENTINEL_SOURCE)
    # Only these top-level entries of /app are carried into grading, so a planted top-level
    # module (pytest.py, sitecustomize.py, a *.dist-info) never reaches the grader.
    toplevel = sorted({rel.split("/", 1)[0] for rel in files if not rel.startswith(EXCLUDED_PREFIXES)}
                      - {"tests"})
    (TASK_DIR / "tests" / "toplevel.txt").write_text("\n".join(toplevel) + "\n")
    (TASK_DIR / "tools" / "SOURCE_COMMIT").write_text(commit + "\n")
    print(f"source {commit}: {len(created)} modules to build; hidden tests: {len(HIDDEN_TESTS)}; "
          f"patch: {patch_path.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
