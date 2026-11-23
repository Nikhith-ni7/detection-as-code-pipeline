"""Small Sigma evaluator used to replay test events against rules.

Supports the subset of Sigma the rules in this repo use:
- selections written as a map (all fields must match) or a list of maps (any map matches)
- modifiers: contains, startswith, endswith, all, windash
- plain values with * and ? wildcards, compared case-insensitively
- conditions with and / or / not, parentheses, "1 of x*", "all of x*", "1 of them"

Anything else raises ValueError so an unsupported rule fails loudly instead of
silently passing.
"""

import re

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "windash"}
DASHES = ["-", "/", "–", "—", "―"]

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def logsource_filter(logsource):
    """Return a predicate that picks the events a rule applies to in an exported log."""
    category = logsource.get("category")
    service = logsource.get("service")
    if logsource.get("product") != "windows":
        raise ValueError(f"unsupported logsource product: {logsource}")
    if category == "process_creation":
        return lambda e: e.get("Channel") == SYSMON and str(e.get("EventID")) == "1"
    if category == "registry_set":
        return lambda e: e.get("Channel") == SYSMON and str(e.get("EventID")) == "13"
    if service == "security" and not category:
        return lambda e: e.get("Channel") == "Security"
    raise ValueError(f"unsupported logsource: {logsource}")


def wildcard_regex(pattern, prefix_any=False, suffix_any=False):
    """Turn a Sigma value with * and ? wildcards into a full-match regex.

    prefix_any / suffix_any add the implicit wildcards of endswith / startswith /
    contains outside the value, so a value ending in a backslash is not read as
    an escaped wildcard.
    """
    out = [".*"] if prefix_any else []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
        i += 1
    if suffix_any:
        out.append(".*")
    return re.compile("".join(out), re.IGNORECASE | re.DOTALL)


def windash_variants(value):
    """Expand a leading - or / (at the start or after a space) to every dash form."""
    variants = {value}
    if re.search(r"(^|\s)[-/]", value):
        for dash in DASHES:
            variants.add(re.sub(r"(^|\s)[-/]", lambda m: m.group(1) + dash, value))
    return sorted(variants)


def compile_field(expression, values):
    field, *modifiers = expression.split("|")
    unknown = set(modifiers) - SUPPORTED_MODIFIERS
    if unknown:
        raise ValueError(f"unsupported modifier {unknown} on {field}")
    if not isinstance(values, list):
        values = [values]
    if not values or any(v is None or isinstance(v, (dict, list)) for v in values):
        raise ValueError(f"unsupported value for {field}")

    values = [str(v) for v in values]
    if "windash" in modifiers:
        values = [variant for v in values for variant in windash_variants(v)]

    if "all" in modifiers and "windash" in modifiers:
        raise ValueError("all + windash is not supported by this evaluator")
    prefix_any = "contains" in modifiers or "endswith" in modifiers
    suffix_any = "contains" in modifiers or "startswith" in modifiers
    patterns = [wildcard_regex(v, prefix_any, suffix_any) for v in values]
    combine = all if "all" in modifiers else any

    def match(event):
        if field not in event or event[field] is None:
            return False
        text = str(event[field])
        return combine(p.fullmatch(text) for p in patterns)

    return match


def compile_selection(definition):
    maps = definition if isinstance(definition, list) else [definition]
    if not maps or not all(isinstance(m, dict) and m for m in maps):
        raise ValueError("a selection must be a map or a list of maps")
    compiled = [[compile_field(k, v) for k, v in m.items()] for m in maps]
    return lambda event: any(all(f(event) for f in fields) for fields in compiled)


def tokenize(condition):
    tokens = re.findall(r"\(|\)|[A-Za-z0-9_*]+", condition)
    if "".join(tokens) != re.sub(r"\s+", "", condition):
        raise ValueError(f"cannot parse condition: {condition}")
    return tokens


class ConditionParser:
    def __init__(self, condition, selections):
        self.tokens = tokenize(condition)
        self.pos = 0
        self.selections = selections

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self, expected=None):
        token = self.peek()
        if token is None or (expected and token.lower() != expected):
            raise ValueError(f"expected {expected!r}, got {token!r}")
        self.pos += 1
        return token

    def parse(self):
        node = self.expr()
        if self.peek() is not None:
            raise ValueError(f"unexpected token {self.peek()!r}")
        return node

    def expr(self):
        terms = [self.term()]
        while (self.peek() or "").lower() == "or":
            self.take()
            terms.append(self.term())
        return terms[0] if len(terms) == 1 else (lambda e, t=terms: any(x(e) for x in t))

    def term(self):
        factors = [self.factor()]
        while (self.peek() or "").lower() == "and":
            self.take()
            factors.append(self.factor())
        return factors[0] if len(factors) == 1 else (lambda e, f=factors: all(x(e) for x in f))

    def factor(self):
        token = self.peek()
        if token is None:
            raise ValueError("condition ended early")
        if token.lower() == "not":
            self.take()
            inner = self.factor()
            return lambda e: not inner(e)
        if token == "(":
            self.take()
            node = self.expr()
            self.take(")")
            return node
        if token.lower() in {"1", "all"}:
            quantifier = self.take().lower()
            self.take("of")
            target = self.take()
            names = self.resolve(target)
            parts = [self.selections[n] for n in names]
            if quantifier == "1":
                return lambda e: any(p(e) for p in parts)
            return lambda e: all(p(e) for p in parts)
        name = self.take()
        if name not in self.selections:
            raise ValueError(f"unknown selection {name!r}")
        return self.selections[name]

    def resolve(self, target):
        if target.lower() == "them":
            return sorted(self.selections)
        regex = wildcard_regex(target)
        names = sorted(n for n in self.selections if regex.fullmatch(n))
        if not names:
            raise ValueError(f"{target!r} matches no selection")
        return names


def compile_rule(rule):
    """Return a function event -> bool for a parsed Sigma rule."""
    detection = dict(rule["detection"])
    condition = detection.pop("condition")
    if not isinstance(condition, str):
        raise ValueError("only a single condition string is supported")
    detection.pop("timeframe", None)
    selections = {name: compile_selection(body) for name, body in detection.items()}
    return ConditionParser(condition, selections).parse()
