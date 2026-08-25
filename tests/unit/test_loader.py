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


def test_filter_by_article_50_transparency():
    rules_path = get_default_rules_dir()
    catalog = load_rules_from_dir(rules_path)
    
    filtered = catalog.filter_by_articles({"50"})
    assert len(filtered) > 0
    assert any("50" in r.article for r in filtered)


def test_filter_by_multiple_articles():
    rules_path = get_default_rules_dir()
    catalog = load_rules_from_dir(rules_path)
    
    filtered = catalog.filter_by_articles({"Art. 5", "12", "50"})
    articles_found = {r.id.split("-")[1] for r in filtered}
    assert "ART05" in articles_found
    assert "ART12" in articles_found


def test_load_gdpr_rules():
    rules_path = get_default_rules_dir()
    catalog = load_rules_from_dir(rules_path)
    
    gdpr_rules = [r for r in catalog.rules if r.id.startswith("GDPR-")]
    assert len(gdpr_rules) >= 3
    assert catalog.get_by_id("GDPR-ART05-001") is not None
    assert catalog.get_by_id("GDPR-ART09-001") is not None
    assert catalog.get_by_id("GDPR-ART22-001") is not None