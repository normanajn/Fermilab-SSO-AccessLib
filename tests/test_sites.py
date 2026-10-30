"""
Tests for fermi_sso_sites: entry normalization and validation, catalog
merging and overriding across files, the user-file add/remove helpers, and
agreement between the built-in catalog and config/sites.yaml.
"""

import json
import os

import pytest

import fermi_sso_sites as sites

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------
# normalization
# --------------------------------------------------------------------------


def test_normalize_fills_defaults_from_the_url():
    site = sites.normalize_site("x", {"url": "https://Host.FNAL.gov/sso"})
    assert site["name"] == "x"
    assert site["domains"] == ["host.fnal.gov"]
    assert site["auth"] == list(sites.AUTH_METHODS)
    assert site["connection"] is None and site["js_redirect"] is False
    assert site["enabled"] and site["key"] == "x" and site["source"] == "builtin"


def test_normalize_accepts_scalar_domains_and_auth_and_strips_dots():
    site = sites.normalize_site("x", {"url": "https://a/b", "domains": ".A.example", "auth": "kerberos"})
    assert site["domains"] == ["a.example"] and site["auth"] == ["kerberos"]


@pytest.mark.parametrize(
    "key, raw, message",
    [
        ("Bad Key", {"url": "https://a/"}, "site key"),
        ("x", {"url": "http://a/"}, "https://"),
        ("x", {}, "https://"),
        ("x", {"url": "https://a/", "bogus": 1}, "unknown fields"),
        ("x", {"url": "https://a/", "connection": "ldap"}, "connection"),
        ("x", {"url": "https://a/", "auth": ["magic"]}, "auth methods"),
        ("x", {"url": "https://a/", "domains": []}, "no cookie domains"),
        ("x", {"url": "https://a/", "expect": 5}, "expect"),
        ("x", "not a mapping", "must be a mapping"),
    ],
)
def test_normalize_rejects_bad_entries(key, raw, message):
    with pytest.raises(sites.SiteError, match=message):
        sites.normalize_site(key, raw, "test")


def test_disabled_entry_skips_validation():
    site = sites.normalize_site("x", {"enabled": False})
    assert site["enabled"] is False


# --------------------------------------------------------------------------
# the built-in catalog
# --------------------------------------------------------------------------


def test_builtin_sites_are_valid_and_use_entry_urls():
    cat = sites.load_catalog(environ={}, builtin=True)
    # environ={} means no $FERMI_SSO_SITES_FILE; the user file may still
    # exist on a developer machine, so only check the built-in keys
    for key in sites.BUILTIN_SITES:
        site = sites.normalize_site(key, sites.BUILTIN_SITES[key])
        assert site["url"].startswith("https://")
        assert site["connection"] in sites.CONNECTIONS
        # roots are landing pages or login menus; every entry must have a path
        from urllib.parse import urlsplit

        assert urlsplit(site["url"]).path not in ("", "/"), site["url"]
    assert set(sites.BUILTIN_SITES) <= set(cat.sites)


def test_config_sites_yaml_matches_the_builtin_catalog():
    """The shipped file is the schema reference; it must not drift."""
    yaml = pytest.importorskip("yaml")
    with open(os.path.join(ROOT, "config", "sites.yaml"), encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    assert set(doc["sites"]) == set(sites.BUILTIN_SITES)
    for key, raw in doc["sites"].items():
        from_file = sites.normalize_site(key, raw, "config")
        builtin = sites.normalize_site(key, sites.BUILTIN_SITES[key])
        for field in ("url", "expect", "domains", "connection", "auth", "js_redirect", "name"):
            assert from_file[field] == builtin[field], (key, field)


def test_for_domain_finds_the_owning_site_and_subdomains():
    cat = sites.load_catalog(environ={})
    assert cat.for_domain("mu2e-docdb.fnal.gov")["key"] == "docdb"
    assert cat.for_domain(".mu2e-docdb.fnal.gov")["key"] == "docdb"
    assert cat.for_domain("x.mu2e-docdb.fnal.gov")["key"] == "docdb"
    assert cat.for_domain("pingprod.fnal.gov") is None


def test_get_unknown_key_lists_the_known_ones():
    cat = sites.load_catalog(environ={})
    with pytest.raises(sites.SiteError, match="docdb"):
        cat.get("nope")


# --------------------------------------------------------------------------
# merging files
# --------------------------------------------------------------------------


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_later_file_overrides_fields_and_disables(tmp_path, monkeypatch):
    monkeypatch.setattr(sites, "USER_SITES_FILE", str(tmp_path / "absent.yaml"))
    first = _write(
        tmp_path / "a.json",
        json.dumps({"sites": {"docdb": {"expect": "Welcome"}, "new": {"url": "https://n.example/sso"}}}),
    )
    second = _write(tmp_path / "b.json", json.dumps({"sites": {"servicenow": {"enabled": False}}}))
    cat = sites.load_catalog([first, second], environ={})
    assert cat.get("docdb")["expect"] == "Welcome"
    assert cat.get("docdb")["url"] == sites.BUILTIN_SITES["docdb"]["url"]  # untouched fields kept
    assert cat.get("docdb")["source"] == first
    assert cat.get("new")["domains"] == ["n.example"]
    assert "servicenow" not in cat.sites
    assert cat.files == [first, second]


def test_null_entry_disables_and_a_later_file_can_reenable(tmp_path, monkeypatch):
    monkeypatch.setattr(sites, "USER_SITES_FILE", str(tmp_path / "absent.yaml"))
    a = _write(tmp_path / "a.json", json.dumps({"sites": {"docdb": None}}))
    b = _write(tmp_path / "b.json", json.dumps({"sites": {"docdb": {"notes": "back"}}}))
    assert "docdb" not in sites.load_catalog([a], environ={}).sites
    cat = sites.load_catalog([a, b], environ={})
    assert cat.get("docdb")["notes"] == "back"
    assert cat.get("docdb")["url"] == sites.BUILTIN_SITES["docdb"]["url"]


def test_environment_variable_names_files_and_explicit_beats_it(tmp_path, monkeypatch):
    monkeypatch.setattr(sites, "USER_SITES_FILE", str(tmp_path / "absent.yaml"))
    env_file = _write(tmp_path / "env.json", json.dumps({"sites": {"docdb": {"expect": "FromEnv"}}}))
    cli_file = _write(tmp_path / "cli.json", json.dumps({"sites": {"docdb": {"expect": "FromCli"}}}))
    environ = {sites.ENV_SITES_FILE: env_file + os.pathsep + str(tmp_path / "missing.json")}
    assert sites.load_catalog(environ=environ).get("docdb")["expect"] == "FromEnv"
    assert sites.load_catalog([cli_file], environ=environ).get("docdb")["expect"] == "FromCli"


def test_explicit_missing_file_is_an_error(tmp_path):
    with pytest.raises(sites.SiteError, match="not found"):
        sites.load_catalog([str(tmp_path / "nope.yaml")], environ={})


def test_settings_merge_with_later_files_winning(tmp_path, monkeypatch):
    monkeypatch.setattr(sites, "USER_SITES_FILE", str(tmp_path / "absent.yaml"))
    a = _write(tmp_path / "a.json", json.dumps({"settings": {"margin": 60, "user": "a"}}))
    b = _write(tmp_path / "b.json", json.dumps({"settings": {"user": "b"}}))
    cat = sites.load_catalog([a, b], environ={})
    assert cat.settings == {"margin": 60, "user": "b"}


def test_no_builtin_gives_an_empty_catalog(tmp_path, monkeypatch):
    monkeypatch.setattr(sites, "USER_SITES_FILE", str(tmp_path / "absent.yaml"))
    assert sites.load_catalog(environ={}, builtin=False).sites == {}


@pytest.mark.parametrize(
    "text, message",
    [
        ("- a\n- b\n", "top level must be a mapping"),
        ('{"sites": [1]}', "'sites' must be a mapping"),
        ('{"settings": 3}', "'settings' must be a mapping"),
        ("{not json", "Expecting"),
    ],
)
def test_malformed_documents(text, message):
    with pytest.raises(sites.SiteError, match=message):
        sites.parse_sites_text(text, "t")


def test_empty_document_is_empty():
    assert sites.parse_sites_text("") == ({}, {})
    assert sites.parse_sites_text("# only a comment\n") == ({}, {})


def test_yaml_documents_parse_when_pyyaml_is_present():
    pytest.importorskip("yaml")
    settings, raw = sites.parse_sites_text("sites:\n  x:\n    url: https://x/sso\n")
    assert raw == {"x": {"url": "https://x/sso"}} and settings == {}


# --------------------------------------------------------------------------
# the user file
# --------------------------------------------------------------------------


def test_add_and_remove_user_site_round_trip(tmp_path):
    path = str(tmp_path / "sub" / "sites.yaml")
    entry = sites.user_entry("mine", "https://mine.example/sso", expect="Hi", domains=["mine.example", "api.mine.example"])
    assert entry == {"url": "https://mine.example/sso", "expect": "Hi", "domains": ["mine.example", "api.mine.example"]}
    assert sites.add_user_site("mine", entry, path) == path
    if os.name != "nt":
        assert (os.stat(path).st_mode & 0o777) == 0o600
    _, raw = sites.read_sites_file(path)
    assert raw == {"mine": entry}

    # removing a built-in key writes a disabling stub rather than deleting
    sites.remove_user_site("docdb", path)
    _, raw = sites.read_sites_file(path)
    assert raw["docdb"] == {"enabled": False} and "mine" in raw

    sites.remove_user_site("mine", path)
    _, raw = sites.read_sites_file(path)
    assert "mine" not in raw

    with pytest.raises(sites.SiteError, match="not in"):
        sites.remove_user_site("mine", path)


def test_user_entry_validates_before_writing():
    with pytest.raises(sites.SiteError):
        sites.user_entry("bad key", "https://x/")
    with pytest.raises(sites.SiteError):
        sites.user_entry("ok", "ftp://x/")


def test_describe_mentions_every_field():
    text = sites.describe(sites.load_catalog(environ={}).get("servicenow"))
    for needle in ("url", "expect", "domains", "connection", "auth", "js_redirect", "notes", "source"):
        assert needle in text
