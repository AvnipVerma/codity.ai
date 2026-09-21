import math

import pytest

from scanner.entropy import shannon_entropy


@pytest.mark.parametrize(
    "text, expected",
    [
        ("", 0.0),
        ("aaaa", 0.0),
        ("ab", 1.0),
        ("aabb", 1.0),
        ("abcd", 2.0),
        ("abcdefgh", 3.0),
        ("0123456789abcdef", 4.0),
        ("password", 2.75),  # 6 letters once, 's' twice
    ],
)
def test_known_values(text, expected):
    assert math.isclose(shannon_entropy(text), expected, abs_tol=1e-12)


def test_order_does_not_matter():
    assert shannon_entropy("abcabc") == shannon_entropy("cbacba")


def test_random_looking_key_is_high():
    assert shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") > 4.5
