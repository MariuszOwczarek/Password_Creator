import pytest
from policy.policy import PasswordPolicy
from policy.errors import PolicyError


def test_length_min_greater_than_length_max():
    # length_min > length_max powinno wywołać błąd
    with pytest.raises(PolicyError):
        PasswordPolicy(length_min=15, length_max=12)


def test_require_specials_with_empty_allowed_specials():
    with pytest.raises(PolicyError):
        PasswordPolicy(require_specials=True, allowed_specials=[])


def test_allowed_specials_multichar_element():
    with pytest.raises(PolicyError):
        PasswordPolicy(require_specials=True, allowed_specials=["!!"])


def test_deny_substrings_empty_string_not_allowed():
    with pytest.raises(PolicyError):
        PasswordPolicy(deny_substrings=["admin", ""])


def test_required_categories_more_than_length_max():
    with pytest.raises(PolicyError):
        PasswordPolicy(require_upper=True, require_lower=True,
                       require_digits=True, require_specials=True,
                       length_max=3)


def test_max_consecutive_same_must_be_ge_1():
    with pytest.raises(PolicyError):
        PasswordPolicy(max_consecutive_same=0)


def test_serialization_roundtrip():
    policy = PasswordPolicy(length_min=10, length_max=20,
                            require_upper=True, require_lower=True,
                            require_digits=True, require_specials=True,
                            allowed_specials=["!", "@", "#"],
                            deny_substrings=["admin"],
                            max_consecutive_same=2,
                            no_whitespace=True)
    data = policy.to_dict()
    policy2 = PasswordPolicy.from_dict(data)
    assert policy2.to_dict() == data
