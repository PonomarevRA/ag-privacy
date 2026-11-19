"""Train a bounded character classifier using an external surname corpus.

Usage: train.py surnames.txt negative-words.txt output.bin
Inputs are UTF-8 with one lowercase or uppercase word per line.
"""

import argparse
from pathlib import Path
import struct

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.linear_model import LogisticRegression


BUCKETS = 1 << 14
CYRILLIC = "абвгдежзийклмнопрстуфхцчшщъыьэюя"
SCHEMES = (
    "a b v g d e zh z i y k l m n o p r s t u f kh ts ch sh shch _ y _ e yu ya",
    "a b v g d e zh z i i k l m n o p r s t u f kh ts ch sh shch _ y _ e iu ia",
    "a b v g d e zh z i j k l m n o p r s t u f h c ch sh sch _ y _ e ju ja",
    "a b v g d e zh z i y k l m n o p r s t u f kh ts ch sh shch _ y _ e yu ia",
    "a b v g d e zh z i i k l m n o p r s t u f kh tc ch sh shch _ y _ e iu ia",
)


def read_words(path):
    """Read normalized, bounded single words from the given input."""
    words = {word.strip().lower().replace("ё", "е") for word in path.read_text(encoding="utf-8").splitlines()}
    return {word for word in words if 3 <= len(word) <= 40 and word.isalpha() and word.isascii()} | {
        word for word in words if 3 <= len(word) <= 40 and all(letter in CYRILLIC for letter in word)
    }


def expand(words):
    """Train on both scripts and common transliteration variants."""
    forms = set(words)
    for scheme in SCHEMES:
        table = {key: val.replace("_", "") for key, val in zip(CYRILLIC, scheme.split())}
        for word in words:
            if word.isascii():
                continue
            for source in (word, word.replace("ье", "ие")):
                spelling = "".join(table[letter] for letter in source)
                forms.add(spelling)
                forms.add(spelling.replace("ov", "off") if spelling.endswith("ov") else spelling)
    return {word for word in forms if 3 <= len(word) <= 40}


def indices(word):
    """Hash boundary-aware 2–4 character features using the runtime's bucket mapping."""
    word = "^" + word + "$"
    for start in range(len(word) - 1):
        key = 2166136261
        for offset, character in enumerate(word[start : start + 4]):
            key = ((key ^ ord(character)) * 16777619) & 0xFFFFFFFF
            if offset:
                yield key & (BUCKETS - 1)


def train(positive, negative):
    """Fit one logistic coefficient per feature bucket and an intercept."""
    rows = sorted(positive) + sorted(negative)
    columns = []
    pointers = [0]
    for word in rows:
        columns.extend(indices(word))
        pointers.append(len(columns))
    if not positive or not negative:
        raise ValueError("training requires both surname and negative examples")
    matrix = csr_matrix((np.ones(len(columns)), columns, pointers), shape=(len(rows), BUCKETS))
    labels = [1] * len(positive) + [0] * len(negative)
    model = LogisticRegression(C=0.7, class_weight="balanced", max_iter=300)
    model.fit(matrix, labels)
    return model.intercept_[0], model.coef_[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("surnames", type=Path)
    parser.add_argument("negatives", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    positive = expand(read_words(args.surnames))
    negative = expand(read_words(args.negatives)) - positive
    intercept, weights = train(positive, negative)
    args.output.write_bytes(struct.pack("<4sf", b"AGS1", intercept) + weights.astype("<f4").tobytes())


if __name__ == "__main__":
    main()
