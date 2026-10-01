import ast
from pathlib import Path

import pytest

import erislite

PACKAGE_ROOT = Path(erislite.__file__).resolve().parent


def _uses_pep604_annotation(tree: ast.AST) -> bool:
    """Return True when an annotation contains a PEP 604 ``|`` union."""

    def contains_union(annotation: ast.AST | None) -> bool:
        if annotation is None:
            return False

        return any(
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.BitOr)
            for node in ast.walk(annotation)
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.arg):
            if contains_union(node.annotation):
                return True

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if contains_union(node.returns):
                return True

        elif isinstance(node, ast.AnnAssign):
            if contains_union(node.annotation):
                return True

    return False


def _postpones_annotations(tree: ast.AST) -> bool:
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    )


@pytest.mark.parametrize(
    "path",
    sorted(PACKAGE_ROOT.rglob("*.py")),
    ids=lambda path: str(path.relative_to(PACKAGE_ROOT)),
)
def test_pep604_annotations_are_postponed(path):
    """
    Python 3.9 cannot evaluate PEP 604 unions such as ``str | None``
    at import time.

    Modules using that syntax must postpone annotation evaluation.
    """
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    if not _uses_pep604_annotation(tree):
        pytest.skip("no PEP 604 annotations in module")

    assert _postpones_annotations(tree)