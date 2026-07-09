"""Only built-in fictional content is accepted by the cards demo CLI."""

import json
from pathlib import Path

import pytest

from health_analyzer.cards.demo import DEMO_NOTICE, demo_card
from health_analyzer.cli import main
from health_analyzer.cards.rendering import render_card_html


@pytest.mark.parametrize("kind", ["patient", "decision"])
def test_demo_cards_are_fictional_and_repeatable(kind):
    first = demo_card(kind)
    assert first == demo_card(kind)
    assert DEMO_NOTICE in first["limitations"]
    assert first["review_required"] is True


@pytest.mark.parametrize("format", ["json", "markdown", "html"])
def test_cards_cli_writes_only_new_demo_file(tmp_path, format):
    target = tmp_path / f"synthetic.{format}"
    args = ["cards-demo", "--card", "decision", "--format", format, "--output", str(target)]
    main(args)
    before = target.read_text()
    assert "ДЕМОНСТРАЦИЯ" in before
    if format == "json":
        assert json.loads(before)["status"] == "blocked_clinician_confirmation"
    with pytest.raises(FileExistsError):
        main(args)
    assert target.read_text() == before


def test_cards_cli_never_follows_existing_output_symlink(tmp_path):
    existing = tmp_path / "existing.txt"
    existing.write_text("Keep this synthetic file")
    link = tmp_path / "demo.html"
    link.symlink_to(existing)
    with pytest.raises(FileExistsError):
        main(["cards-demo", "--format", "html", "--output", str(link)])
    assert existing.read_text() == "Keep this synthetic file"


def test_cards_cli_stdout_and_no_private_input(capsys):
    main(["cards-demo", "--format", "json"])
    assert json.loads(capsys.readouterr().out)["card_type"] == "patient"
    with pytest.raises(SystemExit):
        main(["cards-demo", "--case-packet", "arbitrary.json"])


@pytest.mark.parametrize("kind", ["patient", "decision"])
def test_committed_fictional_preview_matches_actual_builder(kind):
    path = Path(__file__).resolve().parents[1] / "examples" / f"cards-{kind}-demo.html"
    assert path.read_text(encoding="utf-8") == render_card_html(demo_card(kind)) + "\n"
