from pathlib import Path

import pytest

from health_analyzer.v2.common import V2Error
from health_analyzer.v2.configuration import initialize, load_config, config_from_dict


def test_explicit_pubmed_survives_public_handoff(tmp_path):
    config = initialize(tmp_path / "deployment.json", tmp_path / "data",
                        isolation="host", research_provider={"name": "pubmed"})
    restored = load_config(config.path)
    public = restored.to_dict(domain="public-research")
    assert public["research_provider"] == {"name": "pubmed"}
    assert public["archive_roots"] == {}
    assert config_from_dict(public, path=Path("/runtime-config.json")).research_provider == {"name": "pubmed"}


@pytest.mark.parametrize("provider", [{"name": "custom", "url": "https://example.org"},
                                      {"name": "pubmed", "api_key": "not-allowed"}, "pubmed"])
def test_unreviewed_provider_and_credentials_are_rejected(tmp_path, provider):
    with pytest.raises(V2Error, match="PubMed"):
        initialize(tmp_path / "deployment.json", tmp_path / "data",
                   isolation="host", research_provider=provider)
    assert not (tmp_path / "data").exists()
