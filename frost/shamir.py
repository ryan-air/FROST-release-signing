"""Shamir secret sharing over Z_L, Lagrange interpolation, and Feldman VSS."""

from __future__ import annotations

from .ciphersuite import random_scalar
from .ed25519 import IDENTITY, L, Point, base_mul


def polynomial_evaluate(x: int, coeffs: list[int]) -> int:
    """Evaluate f(x) = coeffs[0] + coeffs[1] x + ... mod L (Horner)."""
    value = 0
    for c in reversed(coeffs):
        value = (value * x + c) % L
    return value


def random_polynomial(secret: int, threshold: int) -> list[int]:
    """Degree t-1 polynomial with f(0) = secret."""
    return [secret % L] + [random_scalar() for _ in range(threshold - 1)]


def split(secret: int, threshold: int, n: int, coeffs: list[int] | None = None):
    """Return (shares, coeffs) where shares is a list of (i, f(i)) for i = 1..n."""
    if not 2 <= threshold <= n:
        raise ValueError("need 2 <= threshold <= n")
    if coeffs is None:
        coeffs = random_polynomial(secret, threshold)
    shares = [(i, polynomial_evaluate(i, coeffs)) for i in range(1, n + 1)]
    return shares, coeffs


def derive_interpolating_value(participants: list[int], x_i: int) -> int:
    """Lagrange coefficient for x_i evaluated at 0 (RFC 9591 Section 4.2)."""
    if x_i not in participants:
        raise ValueError("invalid parameters: x_i not in participant list")
    if len(set(participants)) != len(participants):
        raise ValueError("invalid parameters: duplicate participant")
    num, den = 1, 1
    for x_j in participants:
        if x_j == x_i:
            continue
        num = num * x_j % L
        den = den * (x_j - x_i) % L
    return num * pow(den, -1, L) % L


def combine(shares: list[tuple[int, int]]) -> int:
    """Reconstruct f(0) from t shares. Used only in tests/attacks: FROST never does this."""
    ids = [i for i, _ in shares]
    return sum(derive_interpolating_value(ids, i) * y for i, y in shares) % L


# --- Feldman verifiable secret sharing ---------------------------------------

def feldman_commit(coeffs: list[int]) -> list[Point]:
    """Public commitments C_k = a_k * G to each coefficient."""
    return [base_mul(a) for a in coeffs]


def feldman_verify(i: int, share: int, commitments: list[Point]) -> bool:
    """Check share * G == sum_k i^k * C_k."""
    expected = IDENTITY
    power = 1
    for C in commitments:
        expected = expected + C * power
        power = power * i % L
    return base_mul(share) == expected


def public_share_from_commitments(i: int, commitments: list[Point]) -> Point:
    """Y_i = f(i) * G computed only from public commitments."""
    acc = IDENTITY
    power = 1
    for C in commitments:
        acc = acc + C * power
        power = power * i % L
    return acc
