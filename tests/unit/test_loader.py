from pathlib import Path
import pytest
from aicomply.cli import get_default_rules_dir
from aicomply.rules.loader import RuleCatalog, load_rules_from_dir


def test_load_official_rules():
    rules_path = get_default_rules_dir()
    catalog = load_rules_from_dir(rules_path)
    
    assert len(catalog.rules) > 0
    assert catalog.get_by_id("EUAIA-ART05-001") is not None


def test_filter_by_articles():
    rules_path = get_default_rules_dir()
    catalog = load_rules_from_dir(rules_path)
    
    filtered = catalog.filter_by_articles({"5"})
    assert all("ART05" in r.id for r in filtered)