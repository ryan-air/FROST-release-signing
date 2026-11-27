"""edwards25519 group arithmetic (RFC 8032), implemented from scratch.

Points use extended twisted-Edwards coordinates (X, Y, Z, T) with
x = X/Z, y = Y/Z, x*y = T/Z.

Educational prototype: Python integers are NOT constant time.
"""

from __future__ import annotations

# Field prime and curve constants (RFC 8032, Section 5.1)
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493  # prime order of the base point
D = (-121665 * pow(121666, -1, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)  # sqrt(-1) mod p


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


class Point:
    __slots__ = ("X", "Y", "Z", "T")

    def __init__(self, X: int, Y: int, Z: int, T: int):
        self.X, self.Y, self.Z, self.T = X, Y, Z, T

    # --- group law -------------------------------------------------------
    def __add__(self, other: "Point") -> "Point":
        # RFC 8032 Section 5.1.4 (add-2008-hwcd-3)
        A = (self.Y - self.X) * (other.Y - other.X) % P
        B = (self.Y + self.X) * (other.Y + other.X) % P
        C = 2 * self.T * other.T * D % P
        Dd = 2 * self.Z * other.Z % P
        E, F, G, H = B - A, Dd - C, Dd + C, B + A
        return Point(E * F % P, G * H % P, F * G % P, E * H % P)

    def __neg__(self) -> "Point":
        return Point((-self.X) % P, self.Y, self.Z, (-self.T) % P)

    def __sub__(self, other: "Point") -> "Point":
        return self + (-other)

    def __mul__(self, k: int) -> "Point":
        """Scalar multiplication (double-and-add). k must be non-negative."""
        if k < 0:
            raise ValueError("negative scalar")
        result = IDENTITY
        addend = self
        while k > 0:
            if k & 1:
                result = result + addend
            addend = addend + addend
            k >>= 1
        return result

    __rmul__ = __mul__

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return NotImplemented
        # cross-multiply to compare projective points
        return (self.X * other.Z - other.X * self.Z) % P == 0 and (
            self.Y * other.Z - other.Y * self.Z
        ) % P == 0

    def __hash__(self) -> int:
        return hash(self.encode())

    def is_identity(self) -> bool:
        return self == IDENTITY

    def in_prime_subgroup(self) -> bool:
        return (self * L).is_identity()

    def mul_by_cofactor(self) -> "Point":
        p2 = self + self
        p4 = p2 + p2
        return p4 + p4

    # --- encoding (RFC 8032 Sections 5.1.2 / 5.1.3) ------------------------
    def encode(self) -> bytes:
        zi = _inv(self.Z)
        x = self.X * zi % P
        y = self.Y * zi % P
        return int.to_bytes(y | ((x & 1) << 255), 32, "little")

    @staticmethod
    def decode(b: bytes) -> "Point":
        if len(b) != 32:
            raise ValueError("point encoding must be 32 bytes")
        y = int.from_bytes(b, "little")
        sign = y >> 255
        y &= (1 << 255) - 1
        if y >= P:
            raise ValueError("non-canonical y coordinate")
        x = _recover_x(y, sign)
        return Point(x, y, 1, x * y % P)

    def __repr__(self) -> str:
        return f"Point({self.encode().hex()})"


def _recover_x(y: int, sign: int) -> int:
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0:
        if sign:
            raise ValueError("invalid point encoding")
        return 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        raise ValueError("point not on curve")
    if (x & 1) != sign:
        x = P - x
    return x


IDENTITY = Point(0, 1, 1, 0)

_gy = 4 * _inv(5) % P
_gx = _recover_x(_gy, 0)
G = Point(_gx, _gy, 1, _gx * _gy % P)


def base_mul(k: int) -> Point:
    """k * G."""
    return G * (k % L)
