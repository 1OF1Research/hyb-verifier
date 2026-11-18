"""Independent JCS (RFC 8785) serializer, written from the RFC text.

No code shared with the counterparty's generator/verifier and none with
any house production canonicalizer. Parsing preserves member order,
duplicate names, and raw number tokens so profile rules can judge them.
"""
import json, math, struct
from decimal import Decimal


class Obj:
    """A JSON object as an ordered list of (name, value) pairs."""
    __slots__ = ("pairs",)

    def __init__(self, pairs):
        self.pairs = pairs

    def get(self, name, default=None):
        for k, v in self.pairs:
            if k == name:
                return v
        return default

    def names(self):
        return [k for k, _ in self.pairs]


class Num:
    """A JSON number keeping its original token text."""
    __slots__ = ("token",)

    def __init__(self, token):
        self.token = token

    def as_float(self):
        return float(self.token)


def parse(text):
    dec = json.JSONDecoder(
        object_pairs_hook=lambda pairs: Obj(pairs),
        parse_int=lambda tok: Num(tok),
        parse_float=lambda tok: Num(tok),
        parse_constant=lambda c: (_ for _ in ()).throw(
            ValueError("non-JSON constant: " + c)),
    )
    return dec.decode(text)


# --- ECMAScript number serialization (ECMA-262 Number::toString) ---

def es_number(x):
    if math.isnan(x) or math.isinf(x):
        raise ValueError("non-finite number cannot be serialized")
    if x == 0:
        return "0"
    neg = x < 0
    r = repr(abs(x))
    if "e" in r:
        mant, ex = r.split("e")
        exp = int(ex)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
        digits = ip + fp
        exp10 = exp - len(fp)
    else:
        digits = mant
        exp10 = exp
    digits = digits.lstrip("0")
    while digits.endswith("0"):
        digits = digits[:-1]
        exp10 += 1
    k = len(digits)
    n = exp10 + k
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        esign = "+" if e >= 0 else "-"
        if k == 1:
            out = digits + "e" + esign + str(abs(e))
        else:
            out = digits[0] + "." + digits[1:] + "e" + esign + str(abs(e))
    return ("-" if neg else "") + out


# --- RFC 8785 serialization ---

_ESCAPES = {
    0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r",
    0x22: '\\"', 0x5C: "\\\\",
}


def jcs_string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if o in _ESCAPES:
            out.append(_ESCAPES[o])
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(name):
    return name.encode("utf-16-be", "surrogatepass")


def serialize(node):
    if node is None:
        return "null"
    if node is True:
        return "true"
    if node is False:
        return "false"
    if isinstance(node, str):
        return jcs_string(node)
    if isinstance(node, Num):
        return es_number(node.as_float())
    if isinstance(node, list):
        return "[" + ",".join(serialize(v) for v in node) + "]"
    if isinstance(node, Obj):
        items = sorted(node.pairs, key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(
            jcs_string(k) + ":" + serialize(v) for k, v in items) + "}"
    raise TypeError("cannot serialize %r" % type(node))


def canonical_bytes(node):
    return serialize(node).encode("utf-8")


# --- RFC 8785 Appendix B gate ---

APPENDIX_B = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("7fffffffffffffff", None),   # NaN: must be refused
    ("7ff0000000000000", None),   # Infinity: must be refused
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]

SORT_SAMPLE_TEXT = (
    '{"\\u20ac":"Euro Sign","\\r":"Carriage Return",'
    '"\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One",'
    '"\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control",'
    '"\\u00f6":"Latin Small Letter O With Diaeresis"}'
)
SORT_SAMPLE_EXPECTED_ORDER = [
    "Carriage Return", "One", "Control",
    "Latin Small Letter O With Diaeresis", "Euro Sign",
    "Emoji: Grinning Face", "Hebrew Letter Dalet With Dagesh",
]

# RFC 8785 section 3.2.4 hexadecimal, transcribed from the RFC text
# itself (rfc-editor.org) during this run. An earlier hand transcription
# carried one extra "33" byte in the first number; the RFC's own printed
# serialization in 3.2.2 (333333333.3333333) settles it.
SAMPLE_324_HEX = (
    "7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c"
    "226e756d62657273223a5b" + "33" * 9 + "2e" + "33" * 7 +
    "2c31652b33302c342e352c302e3030322c31652d32375d2c"
    "22737472696e67223a22e282ac245c75303030665c6e4127425c22"
    "5c5c5c5c5c222f227d"
)


def selfcheck():
    """Returns (ok, lines). Gate: Appendix B + 3.2.3 sort + 3.2.4 bytes."""
    lines = []
    ok = True
    finite_pass = 0
    refused = 0
    for bits, expected in APPENDIX_B:
        val = struct.unpack(">d", bytes.fromhex(bits))[0]
        if expected is None:
            try:
                es_number(val)
                lines.append("APPB %s FAIL: non-finite serialized" % bits)
                ok = False
            except ValueError:
                refused += 1
        else:
            got = es_number(val)
            if got == expected:
                finite_pass += 1
            else:
                lines.append("APPB %s FAIL: got %s want %s"
                             % (bits, got, expected))
                ok = False
    lines.append("APPB finite %d/24, non-finite refused %d/2"
                 % (finite_pass, refused))
    if finite_pass != 24 or refused != 2:
        ok = False
    parsed_sort = parse(SORT_SAMPLE_TEXT)
    ordered_values = [v for _, v in sorted(
        parsed_sort.pairs, key=lambda kv: _utf16_key(kv[0]))]
    if ordered_values == SORT_SAMPLE_EXPECTED_ORDER:
        lines.append("SORT 3.2.3 PASS (value order as the RFC lists it)")
    else:
        lines.append("SORT 3.2.3 FAIL: got %s" % ordered_values)
        ok = False
    sample = Obj([
        ("numbers", [Num("333333333.33333329"), Num("1E30"), Num("4.50"),
                     Num("2e-3"), Num("0.000000000000000000000000001")]),
        ("string", "\u20ac$\x0f\nA'B\"\\\\\"/"),
        ("literals", [None, True, False]),
    ])
    got_hex = canonical_bytes(sample).hex()
    if got_hex == SAMPLE_324_HEX:
        lines.append("BYTES 3.2.4 PASS (hex-identical to the RFC)")
    else:
        lines.append("BYTES 3.2.4 FAIL:\n got  %s\n want %s"
                     % (got_hex, SAMPLE_324_HEX))
        ok = False
    lines.append("GATE: " + ("PASS" if ok else "FAIL"))
    return ok, lines
