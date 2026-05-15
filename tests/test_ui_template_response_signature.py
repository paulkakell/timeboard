from __future__ import annotations

import ast
from pathlib import Path


def test_ui_template_responses_use_request_first_signature() -> None:
    """Guard against Starlette versions that require request as first arg."""

    source_path = Path(__file__).resolve().parents[1] / "app" / "routers" / "ui.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))

    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "TemplateResponse"):
            continue
        if not (isinstance(func.value, ast.Name) and func.value.id == "templates"):
            continue
        first_arg = node.args[0] if node.args else None
        if not (isinstance(first_arg, ast.Name) and first_arg.id == "request"):
            offenders.append(f"line {node.lineno}")

    assert offenders == []
