"""
fence.py - a byte-faithful Python mirror of dcr/transform-fencing.kql.

The whole point of the harness is that what you measure is what the DCR does.
So this function reproduces the transformKql steps exactly, in the same order:

  1. forgery prevention: downgrade any pre-existing fence token in the value
  2. structure collapse:  fold runs of CR / LF / TAB into a single space
  3. fence:               wrap in the rare untrusted-data markers

If you change the KQL, change this, and vice versa. The selftest checks they
stay in lock-step on the same corpus.
"""

import re

OPEN = "⟦U⟧"      # ⟦U⟧
CLOSE = "⟦/U⟧"    # ⟦/U⟧

_WS = re.compile(r"[\r\n\t]+")


def fence(value: str) -> str:
    """Apply the LogFence transform to one attacker-controllable field value.
    Mirrors the DCR transformKql exactly, which uses the only replacement
    function transformations allow, replace(regex, rewrite, source):
      replace('⟦','[',x) ; replace('⟧',']',x) ; replace('[\\r\\n\\t]+',' ',x)
    Neutralising the two bracket characters removes the attacker's ability to
    forge either fence marker, since neither can survive in the data."""
    if value is None:
        value = ""
    v = str(value)
    # 1. forgery prevention: neutralise the fence bracket characters
    v = v.replace("⟦", "[").replace("⟧", "]")
    # 2. structure collapse: fold CR / LF / TAB runs to a single space
    v = _WS.sub(" ", v)
    # 3. fence
    return f"{OPEN}{v}{CLOSE}"


def is_fenced(value: str) -> bool:
    """True if the value is wrapped in a single, well-formed fence with no
    interior forged markers (the state the transform guarantees)."""
    if not (value.startswith(OPEN) and value.endswith(CLOSE)):
        return False
    interior = value[len(OPEN):len(value) - len(CLOSE)]
    return OPEN not in interior and CLOSE not in interior


def breakout_attempted(raw_value: str) -> bool:
    """True if the raw (pre-transform) value tried to forge a fence token or
    inject CR/LF/TAB structure - i.e. an attempt the transform neutralises."""
    if raw_value is None:
        return False
    return (OPEN in raw_value) or (CLOSE in raw_value) or bool(_WS.search(raw_value))
