"""Task 4 – ElGamal decryption walk-through.

Recreates the numerical example from the assignment:
    p = 23, g = 5, private key x = 6, ciphertext C = (20, 22).
Outputs every required intermediate quantity: public key y,
shared secret C1^x mod p, its inverse, and the recovered M.
Also prints the step-by-step table for the extended Euclidean
algorithm used to compute the modular inverse.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class EuclidStep:
    quotient: int | None
    remainder: int
    s: int
    t: int

    def render(self) -> str:
        q = "-" if self.quotient is None else str(self.quotient)
        return f"q={q:>3} | r={self.remainder:>3} | s={self.s:>3} | t={self.t:>3}"


def extended_euclid(a: int, b: int) -> tuple[int, int, int, List[EuclidStep]]:
    """Return gcd, Bézout coefficients, and trace steps."""
    steps: List[EuclidStep] = []
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        steps.append(EuclidStep(q, r, s, t))
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    steps.append(EuclidStep(None, old_r, old_s, old_t))
    return old_r, old_s, old_t, steps


def mod_inverse(a: int, modulus: int) -> tuple[int, List[EuclidStep]]:
    gcd, x, _, steps = extended_euclid(a % modulus, modulus)
    if gcd != 1:
        raise ValueError(f"Inverse does not exist for a={a} mod {modulus}")
    return x % modulus, steps


def main() -> None:
    p = 23
    g = 5
    x = 6
    c1, c2 = 20, 22

    public_y = pow(g, x, p)
    print("Given parameters:")
    print(f"  Prime p        = {p}")
    print(f"  Generator g    = {g}")
    print(f"  Private key x  = {x}")
    print(f"  Public key y   = g^x mod p = {public_y}")
    print(f"  Ciphertext C   = ({c1}, {c2})")

    shared_secret = pow(c1, x, p)
    print("\nStep (a): compute C1^x mod p")
    print(f"  C1^x mod p = {shared_secret}")

    inverse, trace = mod_inverse(shared_secret, p)
    print("\nStep (b): multiplicative inverse of C1^x mod p")
    print(f"  (C1^x)^(-1) mod p = {inverse}")

    print("\nExtended Euclidean trace (Step c):")
    print("  Each row shows the quotient, remainder, and Bézout coefficients (s, t)")
    for row in trace:
        print("  " + row.render())

    plaintext = (c2 * inverse) % p
    print("\nRecovered plaintext")
    print(f"  M = C2 * (C1^x)^(-1) mod p = {plaintext}")


if __name__ == "__main__":
    main()
