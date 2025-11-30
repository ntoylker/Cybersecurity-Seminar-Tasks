"""Task 3 – CBC & CFB error propagation demo.

The script simulates a single-bit corruption on C1 for CBC and CFB
(two-block messages, 128-bit blocks) and reports how many bits of the
resulting plaintext blocks P1' and P2' are altered as a consequence.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

BLOCK_SIZE = 128
HALF_BLOCK = BLOCK_SIZE // 2
HALF_MASK = (1 << HALF_BLOCK) - 1
ROUNDS = 8
BIT_TO_FLIP = 17  # 0-indexed from LSB


def derive_subkeys(key: int, rounds: int = ROUNDS) -> list[int]:
    """Expand the 128-bit key into per-round subkeys via BLAKE2s."""
    seed = key.to_bytes(16, "big")
    subkeys: list[int] = []
    for counter in range(rounds):
        counter_bytes = counter.to_bytes(2, "big")
        digest = hashlib.blake2s(seed + counter_bytes, digest_size=8).digest()
        subkeys.append(int.from_bytes(digest, "big"))
    return subkeys


def round_function(half_block: int, subkey: int) -> int:
    """Non-linear mixing used inside the Feistel structure."""
    data = half_block.to_bytes(8, "big") + subkey.to_bytes(8, "big")
    digest = hashlib.blake2s(data, digest_size=8).digest()
    return int.from_bytes(digest, "big")


def encrypt_block(block: int, key: int) -> int:
    """Feistel network encryption producing a 128-bit permutation."""
    left = (block >> HALF_BLOCK) & HALF_MASK
    right = block & HALF_MASK
    for subkey in derive_subkeys(key):
        left, right = right, (left ^ round_function(right, subkey)) & HALF_MASK
    return ((left & HALF_MASK) << HALF_BLOCK) | (right & HALF_MASK)


def decrypt_block(block: int, key: int) -> int:
    """Inverse of encrypt_block."""
    left = (block >> HALF_BLOCK) & HALF_MASK
    right = block & HALF_MASK
    for subkey in reversed(derive_subkeys(key)):
        left, right = (right ^ round_function(left, subkey)) & HALF_MASK, left
    return ((left & HALF_MASK) << HALF_BLOCK) | (right & HALF_MASK)


def to_block(text: str) -> int:
    data = text.encode("utf-8")
    if len(data) > 16:
        raise ValueError("Plaintext block must be <= 16 bytes")
    return int.from_bytes(data.ljust(16, b"\x00"), "big")


def int_to_hex(block: int) -> str:
    return f"0x{block:032x}"


def flip_bit(value: int, bit_index: int) -> int:
    return value ^ (1 << bit_index)


def bit_diff(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def cbc_encrypt(blocks: list[int], key: int, iv: int) -> list[int]:
    ciphertext: list[int] = []
    prev = iv
    for block in blocks:
        c = encrypt_block(block ^ prev, key)
        ciphertext.append(c)
        prev = c
    return ciphertext


def cbc_decrypt(blocks: list[int], key: int, iv: int) -> list[int]:
    plaintext: list[int] = []
    prev = iv
    for block in blocks:
        p = decrypt_block(block, key) ^ prev
        plaintext.append(p)
        prev = block
    return plaintext


def cfb_encrypt(blocks: list[int], key: int, iv: int) -> list[int]:
    ciphertext: list[int] = []
    feedback = iv
    for block in blocks:
        keystream = encrypt_block(feedback, key)
        c = block ^ keystream
        ciphertext.append(c)
        feedback = c
    return ciphertext


def cfb_decrypt(blocks: list[int], key: int, iv: int) -> list[int]:
    plaintext: list[int] = []
    feedback = iv
    for block in blocks:
        keystream = encrypt_block(feedback, key)
        p = block ^ keystream
        plaintext.append(p)
        feedback = block
    return plaintext


@dataclass
class ModeReport:
    mode: str
    bit_flip_index: int
    p1_diff: int
    p2_diff: int
    explanation: str

    def render(self) -> str:
        return (
            f"{self.mode} (bit flip at position {self.bit_flip_index}):\n"
            f"  P1' differs in {self.p1_diff}/{BLOCK_SIZE} bits – {self.explanation.splitlines()[0]}\n"
            f"  P2' differs in {self.p2_diff}/{BLOCK_SIZE} bits – {self.explanation.splitlines()[1]}\n"
        )


def analyze_cbc(key: int, iv: int, p_blocks: list[int]) -> ModeReport:
    c_blocks = cbc_encrypt(p_blocks, key, iv)
    clean_plain = cbc_decrypt(c_blocks, key, iv)
    corrupted_c1 = flip_bit(c_blocks[0], BIT_TO_FLIP)
    corrupted_plain = cbc_decrypt([corrupted_c1, c_blocks[1]], key, iv)
    p1_diff = bit_diff(clean_plain[0], corrupted_plain[0])
    p2_diff = bit_diff(clean_plain[1], corrupted_plain[1])
    explanation = (
        "flip sits inside Dk(C1), so diffusion destroys essentially the whole block."
        "\n"
        "only the XOR with C1 handles P2, so a single bit error leaks straight through."
    )
    return ModeReport("CBC mode", BIT_TO_FLIP, p1_diff, p2_diff, explanation)


def analyze_cfb(key: int, iv: int, p_blocks: list[int]) -> ModeReport:
    c_blocks = cfb_encrypt(p_blocks, key, iv)
    clean_plain = cfb_decrypt(c_blocks, key, iv)
    corrupted_c1 = flip_bit(c_blocks[0], BIT_TO_FLIP)
    corrupted_plain = cfb_decrypt([corrupted_c1, c_blocks[1]], key, iv)
    p1_diff = bit_diff(clean_plain[0], corrupted_plain[0])
    p2_diff = bit_diff(clean_plain[1], corrupted_plain[1])
    explanation = (
        "C1 feeds P1' via XOR only, so the corruption remains confined to that bit."
        "\n"
        "C1 is the feedback input to Ek for block 2, so the keystream changes everywhere."
    )
    return ModeReport("CFB mode", BIT_TO_FLIP, p1_diff, p2_diff, explanation)


def main() -> None:
    key = int.from_bytes(b"task3_demo_key!!", "big")
    iv = int.from_bytes(b"task3_demo_iv__", "big")
    p1 = to_block("Plaintext block1")
    p2 = to_block("Plaintext block2")
    reports = [
        analyze_cbc(key, iv, [p1, p2]),
        analyze_cfb(key, iv, [p1, p2]),
    ]
    print("Original blocks:")
    print(f"  P1 = {int_to_hex(p1)}")
    print(f"  P2 = {int_to_hex(p2)}")
    print("\nError propagation summary:")
    for report in reports:
        print(report.render())
    print("Interpretation:")
    print("- CBC: P1' is unusable, but only one bit leaks into P2'.")
    print("- CFB: P1' keeps the error local, but P2' becomes garbage because the keystream changed.")


if __name__ == "__main__":
    main()
