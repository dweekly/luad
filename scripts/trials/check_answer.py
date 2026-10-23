"""Score an outside-trial answer without revealing the answer key.

An answer is canonicalized to its sorted, lower-case token set (tokens split on commas
and whitespace) and compared with the SHA-256 recorded in docs/TRIALS.md.
Usage: python3 -I scripts/trials/check_answer.py TASK "ANSWER"
"""

import hashlib
import re
import sys

KEY = {
    "T1a": "2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3",
    "T1b": "7c8f5059290305cec8323d79521f0353c9ac308b60cb4c1976340d0ce4a121d5",
    "T2": "7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451",
    "T3": "d70234e8123d7df995888ba78e13c4b7853df6bfd16f23abfd11324e324488dc",
    "T4": "bba56d8bfc9faccbad33a8ede0eeda29da8e40a703101b8e9f71476c64135091",
}


def canonical(answer):
    return " ".join(sorted({t for t in re.split(r"[\s,]+", answer.lower()) if t}))


def main():
    task, answer = sys.argv[1], sys.argv[2]
    digest = hashlib.sha256(canonical(answer).encode()).hexdigest()
    print("correct" if KEY.get(task) == digest else "not matching")
    return 0 if KEY.get(task) == digest else 1


if __name__ == "__main__":
    raise SystemExit(main())
