import pytest

from sqlitewatch.analysis.normalization import fingerprint_sql, normalize_sql


@pytest.mark.parametrize(("source", "expected"), [
    (" SELECT  a\nFROM users ", "SELECT a FROM users"),
    ("SELECT\t?\r\nFROM\u2003users", "SELECT ? FROM users"),
    ("SELECT café FROM users", "SELECT café FROM users"),
    ("SELECT 'a   b' /* x   y */", "SELECT 'a   b' /* x   y */"),
    ("SELECT '-- not a comment' -- x   y\n FROM t", "SELECT '-- not a comment' -- x   y\n FROM t"),
    ('SELECT "a   b" `c   d` [e   f]', 'SELECT "a   b" `c   d` [e   f]'),
    ("SELECT 'it''s   safe'", "SELECT 'it''s   safe'"),
    ('SELECT "a""  b"', 'SELECT "a""  b"'),
    (" SELECT 'unterminated   literal ", "SELECT 'unterminated   literal"),
    (" SELECT /* unterminated   comment ", "SELECT /* unterminated   comment"),
])
def test_normalize_sql_is_conservative(source, expected):
    assert normalize_sql(source) == expected


def test_fingerprint_uses_normalized_utf8_sql_without_literal_rewriting():
    assert fingerprint_sql("SELECT  café\nFROM users") == fingerprint_sql(" SELECT café FROM   users ")
    assert fingerprint_sql("SELECT 1") != fingerprint_sql("SELECT 2")
    assert fingerprint_sql("SELECT 1 -- one") != fingerprint_sql("SELECT 1 -- two")
    assert len(fingerprint_sql("SELECT ?")) == 64


def test_normalize_sql_requires_text():
    with pytest.raises(TypeError):
        normalize_sql(None)  # type: ignore[arg-type]
