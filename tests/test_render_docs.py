"""The doc renderer: output blocks and code excerpts."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("render_docs", ROOT / "scripts/render_docs.py")
rd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rd)


def test_output_block_from_cli():
    out = rd.render("<!-- output: version -->\nstale\n<!-- /output -->\n")
    assert "0.1.0" in out and "stale" not in out


def test_python_excerpt():
    lang, body = rd.excerpt("src/aauth/jwt_tokens.py::verify")
    assert lang == "python" and body.startswith("def verify")


def test_constant_excerpt():
    _, body = rd.excerpt("src/aauth/jwt_tokens.py::ALLOWED_ALGS")
    assert "RS256" in body


def test_unknown_name_fails():
    with pytest.raises(SystemExit):
        rd.excerpt("src/aauth/jwt_tokens.py::nope")
