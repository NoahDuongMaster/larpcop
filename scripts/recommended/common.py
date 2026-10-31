"""Shared names for the rule specs."""

import pathlib

JS = ["TypeScript", "Tsx", "JavaScript"]
TS = ["TypeScript", "Tsx"]
WORKFLOWS = [".github/workflows/*.yml", ".github/workflows/*.yaml"]
UNTRUSTED = ("\\$\\{\\{\\s*(github\\.event\\.(issue|pull_request|comment|review|review_comment|discussion|"
             "discussion_comment|pages|head_commit|commits|workflow_run|release)\\b[^}]*|github\\.head_ref)\\s*\\}\\}")


# Test code signs and compares throwaway values on purpose.
TESTS = ["**/test/**", "**/tests/**", "**/__tests__/**", "**/*.test.*", "**/*.spec.*"]

# A group holding an unbounded quantifier, itself repeated: `(a+)+`, `(\w+\s?)*`,
# `((x)?(y+))*`. One level of inner groups; character classes are atoms.
_ATOM = r"(?:\[(?:[^\]\\]|\\.)*\]|\\.|[^()\\\[\]+*?{])"
_ANY_Q = r"(?:(?:[+*?]|\{\d+(?:,\d*)?\})\??)"
_UNBOUNDED_Q = r"(?:[+*]|\{\d+,\d*\})"
_OPEN = r"\((?:\?:)?"
_GROUP = _OPEN + f"(?:{_ATOM}{_ANY_Q}?)*" + r"\)"
_GROUP_UNBOUNDED = _OPEN + f"(?:{_ATOM}{_ANY_Q}?)*{_ATOM}{_UNBOUNDED_Q}(?:{_ATOM}{_ANY_Q}?)*" + r"\)"
_UNIT = f"(?:{_ATOM}|{_GROUP})"
NESTED_QUANTIFIER = (_OPEN + f"(?:{_UNIT}{_ANY_Q}?)*(?:{_UNIT}{_UNBOUNDED_Q}|{_GROUP_UNBOUNDED}{_ANY_Q}?)"
                     + f"(?:{_UNIT}{_ANY_Q}?)*" + r"\)" + _UNBOUNDED_Q)

# String literal text that starts like a SQL statement (optionally with a Python
# string prefix): uppercase keywords, or lowercase ones in shapes UI text lacks.
SQL_TEXT = (r"(?s)^[rRbBuUfF]*[`'\"]{1,3}\s*("
            r"SELECT\s.+?\sFROM\s|INSERT\s+INTO\s|UPDATE\s+\S+\s+SET\s|DELETE\s+FROM\s|"
            r"(?i:insert\s+into\s|delete\s+from\s|update\s+[\w.\"`]+\s+set\s|"
            r"select\s+[\w.*,\s\"`()]+?\s+from\s+[\w.\"`]))")
