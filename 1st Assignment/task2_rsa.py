"""Task 2: RSA end-to-end example with square-and-multiply trace."""

from dataclasses import dataclass
import argparse


def parse_args() -> argparse.Namespace:
    """Allow the user to override p, q, e, and plaintext m from CLI."""
    parser = argparse.ArgumentParser(
        description="RSA Task 2 helper that shows encryption/decryption details",
    )
    parser.add_argument("--p", type=int, default=197, help="First prime (default 197)")
    parser.add_argument("--q", type=int, default=211, help="Second prime (default 211)")
    parser.add_argument(
        "--e", type=int, default=24377, help="Public exponent (default 24377)",
    )
    parser.add_argument(
        "--message", "-m", type=int, default=1234, help="Plaintext integer (default 1234)",
    )
    return parser.parse_args()


@dataclass
class SquareMultiplyStep:
    bit_index: int
    bit_value: str
    value_after_square: int
    value_after_multiply: int | None


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (g, x, y) such that ax + by = g = gcd(a, b)."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def mod_inverse(a: int, modulus: int) -> int:
    """Return the multiplicative inverse of a modulo modulus."""
    g, x, _ = extended_gcd(a, modulus)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % modulus


def square_and_multiply(base: int, exponent: int, modulus: int) -> tuple[int, list[SquareMultiplyStep]]:
    """Classic left-to-right square-and-multiply that also records every step."""
    result = 1
    steps: list[SquareMultiplyStep] = []
    binary = bin(exponent)[2:]
    for idx, bit in enumerate(binary):
        squared = (result * result) % modulus
        result = squared
        multiplied: int | None = None
        if bit == "1":
            result = (result * base) % modulus
            multiplied = result
        steps.append(
            SquareMultiplyStep(
                bit_index=idx,
                bit_value=bit,
                value_after_square=squared,
                value_after_multiply=multiplied,
            )
        )
    return result, steps


def main() -> None:
    args = parse_args()

    # --- Problem parameters from Task 2 (overridable via CLI) ---
    p = args.p
    q = args.q
    e = args.e
    message = args.message

    # --- RSA key generation steps ---
    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)

    # --- Encryption and decryption with traced exponentiation ---
    ciphertext, e_steps = square_and_multiply(message, e, n)
    decrypted, d_steps = square_and_multiply(ciphertext, d, n)

    # --- Present the numeric results ---
    print(f"n = p * q = {n}")
    print(f"phi(n) = {phi}")
    print(f"Public exponent e = {e}")
    print(f"Private exponent d = {d}")
    print(f"Plaintext m = {message}")
    print(f"Ciphertext c = m^e mod n = {ciphertext}")
    print(f"Decrypted plaintext = c^d mod n = {decrypted}")

    # --- Show the square-and-multiply trace for exponent e ---
    print("\nSquare-and-multiply trace for e during encryption:")
    print(f"e in binary: {bin(e)[2:]}")
    for step in e_steps:
        square_part = (
            f"Step {step.bit_index}: bit={step.bit_value}, "
            f"square -> {step.value_after_square}"
        )
        if step.value_after_multiply is not None:
            square_part += f", multiply -> {step.value_after_multiply}"
        print(square_part)

    # --- Show the square-and-multiply trace for exponent d ---
    print("\nSquare-and-multiply trace for d during decryption:")
    print(f"d in binary: {bin(d)[2:]}")
    for step in d_steps:
        square_part = (
            f"Step {step.bit_index}: bit={step.bit_value}, "
            f"square -> {step.value_after_square}"
        )
        if step.value_after_multiply is not None:
            square_part += f", multiply -> {step.value_after_multiply}"
        print(square_part)


if __name__ == "__main__":
    main()
