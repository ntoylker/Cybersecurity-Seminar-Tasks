from collections import Counter
from pathlib import Path
import string

# Expected English letter frequencies (sums to 1.0)
ENGLISH_FREQ = {
    "A": 0.08167, "B": 0.01492, "C": 0.02782, "D": 0.04253, "E": 0.12702,
    "F": 0.02228, "G": 0.02015, "H": 0.06094, "I": 0.06966, "J": 0.00153,
    "K": 0.00772, "L": 0.04025, "M": 0.02406, "N": 0.06749, "O": 0.07507,
    "P": 0.01929, "Q": 0.00095, "R": 0.05987, "S": 0.06327, "T": 0.09056,
    "U": 0.02758, "V": 0.00978, "W": 0.02360, "X": 0.00150, "Y": 0.01974,
    "Z": 0.00074,
}


# --- Basic helpers to clean input and decrypt with a candidate key ---
def normalize_ciphertext(text: str) -> str:
    """Keep only alphabetic characters and map to uppercase."""
    return "".join(ch for ch in text.upper() if ch in string.ascii_uppercase)


def decrypt_vigenere(ciphertext: str, key: str) -> str:
    plaintext_chars: list[str] = []
    for idx, char in enumerate(ciphertext):
        c_val = ord(char) - ord("A")
        k_val = ord(key[idx % len(key)]) - ord("A")
        plaintext_chars.append(chr(((c_val - k_val) % 26) + ord("A")))
    return "".join(plaintext_chars)


def chi_square_score(text: str) -> float:
    """Score how well the text matches English using the chi-square test."""
    if not text:
        return float("inf")
    counts = Counter(text)
    total = len(text)
    score = 0.0
    for letter, expected_freq in ENGLISH_FREQ.items():
        observed = counts.get(letter, 0)
        expected = expected_freq * total
        if expected > 0:
            score += ((observed - expected) ** 2) / expected
    return score


# --- Load only real English five-letter words to serve as candidate keys ---
def load_candidate_keys(wordlist_path: Path, key_length: int) -> list[str]:
    if not wordlist_path.exists():
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")
    candidates: list[str] = []
    with wordlist_path.open("r", encoding="ascii") as handle:
        for raw_line in handle:
            word = raw_line.strip()
            if len(word) == key_length and word.isalpha():
                candidates.append(word.upper())
    if not candidates:
        raise ValueError("No suitable candidate words were loaded.")
    return candidates


# --- Score every English word as a key and return the best-scoring plaintexts ---
def rank_keys_by_plaintext(ciphertext: str, keys: list[str], top_k: int = 5):
    scored: list[tuple[str, str, float]] = []
    for key in keys:
        plaintext = decrypt_vigenere(ciphertext, key)
        score = chi_square_score(plaintext)
        scored.append((key, plaintext, score))
    scored.sort(key=lambda item: item[2])
    return scored[:top_k]


if __name__ == "__main__":
    # --- Input setup for Task 1 ---
    ciphertext = "LXFOPVEFRNHR"
    normalized = normalize_ciphertext(ciphertext)
    key_length = 5
    wordlist_path = Path(__file__).with_name("wordlist_5_letter.txt")

    # --- Enumerate real English words and use chi-square statistics to score them ---
    candidate_keys = load_candidate_keys(wordlist_path, key_length)
    top_matches = rank_keys_by_plaintext(normalized, candidate_keys, top_k=5)

    # --- Report the best guess and show a few close alternatives for transparency ---
    best_key, best_plaintext, best_score = top_matches[0]
    print(f"Best keyword: {best_key} (score={best_score:.2f})")
    print(f"Decrypted plaintext: {best_plaintext}")
    if len(top_matches) > 1:
        print("\nOther close matches:")
        for key, text, score in top_matches[1:]:
            print(f"  {key}: score={score:.2f}, plaintext={text}")
