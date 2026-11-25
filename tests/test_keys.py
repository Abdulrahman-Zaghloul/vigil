import re

import pytest

from vigil.keys import KEY_PATTERN, Scope, generate_key, hash_secret, parse_key


def test_generated_keys_have_a_recognizable_format() -> None:
    key = generate_key()
    assert re.fullmatch(KEY_PATTERN, key.token)
    assert key.token == f"vigil_{key.key_id}_{key.secret}"


def test_every_generated_key_is_different() -> None:
    assert len({generate_key().token for _ in range(1_000)}) == 1_000


def test_a_key_splits_back_into_its_public_id_and_its_secret() -> None:
    key = generate_key()
    assert parse_key(key.token) == (key.key_id, key.secret)


def test_secrets_may_contain_underscores() -> None:
    token = "vigil_0123456789ab_" + "a_b-" * 10 + "xyz"
    assert parse_key(token) == ("0123456789ab", "a_b-" * 10 + "xyz")


@pytest.mark.parametrize(
    "token",
    [
        "",
        "password123",
        "vigil_",
        "ghp_0123456789ab_" + "x" * 43,  # someone else's prefix
        "vigil_XYZ_" + "x" * 43,  # key id is not 12 lowercase hex characters
        "vigil_0123456789ab_" + "x" * 42,  # secret one character short
        "vigil_0123456789ab_" + "x" * 43 + " ",
        "vigil_0123456789ab_" + "x" * 42 + "!",
    ],
    ids=["empty", "plain", "prefix-only", "foreign", "bad-id", "short", "trailing-space", "symbol"],
)
def test_anything_else_is_not_a_key(token: str) -> None:
    assert parse_key(token) is None


def test_hashes_are_stable_and_never_equal_the_secret() -> None:
    secret = generate_key().secret
    assert hash_secret(secret) == hash_secret(secret)
    assert hash_secret(secret) != secret
    assert len(hash_secret(secret)) == 64


def test_scopes() -> None:
    assert {s.value for s in Scope} == {"ingest", "read"}
