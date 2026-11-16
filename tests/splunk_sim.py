#!/usr/bin/env python3
"""
splunk_sim.py - offline stand-in for Splunk's search-time field processing, enough to test
this add-on without a Splunk instance.

Order, as in Splunk: REPORT (transforms.conf REGEX with named groups, each class in ASCII
order, transforms in listed order) -> EVAL (every EVAL-<field> sees the fields as they were
before the EVAL phase, so one EVAL cannot use another's result) -> event types -> tags.

Stricter than Splunk on purpose:
- a field set by two different transforms on the same event is an error (the add-on is
  designed so that its extractions never overlap);
- an empty capture creates no field;
- every regex must also compile in Perl (close to Splunk's PCRE).
"""
import math
import os
import re
import subprocess


# ---------------------------------------------------------------- .conf files
def read_conf(path):
    out, stanza = {}, None
    if not os.path.exists(path):
        return out
    cont = None
    for line in open(path, encoding="utf-8"):
        raw = line.rstrip("\n")
        if cont:
            out[stanza][cont] += "\n" + raw.rstrip("\\")
            if not raw.endswith("\\"):
                cont = None
            continue
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("[") and s.endswith("]"):
            stanza = s[1:-1]
            out.setdefault(stanza, {})
            continue
        key, value = s.split("=", 1)
        out[stanza][key.strip()] = value.strip().rstrip("\\")
        if s.endswith("\\"):
            cont = key.strip()
    return out


def pcre_to_python(rx):
    """(?<name>...) -> (?P<name>...); lookbehinds (?<= (?<! are left alone."""
    rx = re.sub(r"\(\?\(<([A-Za-z_]\w*)>\)", r"(?(\1)", rx)     # (?(<name>)  -> (?(name)
    return re.sub(r"\(\?<(?=[A-Za-z_])", "(?P<", rx)


_perl_checked = set()


def perl_compiles(rx):
    if rx in _perl_checked:
        return True
    r = subprocess.run(["perl", "-e", "my $r = $ARGV[0]; qr/$r/; print 'ok'", rx],
                       capture_output=True, text=True)
    if r.stdout != "ok":
        raise ValueError(f"regex does not compile in Perl: {rx}\n{r.stderr}")
    _perl_checked.add(rx)
    return True


# ---------------------------------------------------------------- SPL eval
class EvalError(Exception):
    pass


TOKEN = re.compile(r"""\s*(?:
    (?P<num>\d+(?:\.\d+)?)|
    (?P<str>"(?:[^"\\]|\\.)*")|
    (?P<qfield>'[^']*')|
    (?P<op>==|!=|<=|>=|[=<>().,+\-*/%])|
    (?P<ident>[A-Za-z_][A-Za-z0-9_.:]*)
)""", re.X)


def tokenize(text):
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise EvalError(f"cannot tokenize at {text[pos:pos + 30]!r}")
        pos = m.end()
        kind = m.lastgroup
        val = m.group(kind)
        if kind == "ident":
            # identifiers may not end with '.' (concatenation operator)
            while val.endswith("."):
                val = val[:-1]
                pos -= 1
            if val.upper() in ("AND", "OR", "NOT"):
                kind, val = "op", val.upper()
        out.append((kind, val))
    return out


def _num(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return v
    try:
        return int(v)
    except (TypeError, ValueError):
        try:
            return float(v)
        except (TypeError, ValueError):
            return None


def _str(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    if isinstance(v, list):
        return v[0] if v else None
    return str(v)


class Parser:
    def __init__(self, text, fields):
        self.toks = tokenize(text)
        self.i = 0
        self.fields = fields

    def peek(self, val=None):
        if self.i < len(self.toks):
            t = self.toks[self.i]
            if val is None or t[1] == val:
                return t
        return None

    def take(self, val=None):
        t = self.peek(val)
        if t is None:
            raise EvalError(f"expected {val!r} at token {self.i}: {self.toks[self.i:self.i + 3]}")
        self.i += 1
        return t

    def parse(self):
        v = self.expr()
        if self.i != len(self.toks):
            raise EvalError(f"trailing tokens {self.toks[self.i:]}")
        return v

    # lazy evaluation is needed for case()/if(): build thunks
    def expr(self):
        return self.or_()

    def or_(self):
        left = self.and_()
        while self.peek("OR"):
            self.take()
            right = self.and_()
            left = (lambda l, r: lambda: bool(l()) or bool(r()))(left, right)
        return left

    def and_(self):
        left = self.not_()
        while self.peek("AND"):
            self.take()
            right = self.not_()
            left = (lambda l, r: lambda: bool(l()) and bool(r()))(left, right)
        return left

    def not_(self):
        if self.peek("NOT"):
            self.take()
            inner = self.not_()
            return lambda: not bool(inner())
        return self.cmp()

    def cmp(self):
        left = self.concat()
        t = self.peek()
        if t and t[0] == "op" and t[1] in ("==", "=", "!=", "<", ">", "<=", ">="):
            op = self.take()[1]
            right = self.concat()

            def f(l=left, r=right, op=op):
                a, b = l(), r()
                if a is None or b is None:
                    return None
                if op in ("==", "=", "!="):
                    na, nb = _num(a), _num(b)
                    eq = (na == nb) if (na is not None and nb is not None) else (_str(a) == _str(b))
                    return eq if op != "!=" else not eq
                na, nb = _num(a), _num(b)
                if na is None or nb is None:
                    na, nb = _str(a), _str(b)
                return {"<": na < nb, ">": na > nb, "<=": na <= nb, ">=": na >= nb}[op]
            return f
        return left

    def concat(self):
        left = self.add()
        while self.peek("."):
            self.take()
            right = self.add()

            def f(l=left, r=right):
                a, b = l(), r()
                if a is None or b is None:
                    return None
                return _str(a) + _str(b)
            left = f
        return left

    def add(self):
        left = self.mul()
        while self.peek("+") or self.peek("-"):
            op = self.take()[1]
            right = self.mul()

            def f(l=left, r=right, op=op):
                a, b = l(), r()
                if a is None or b is None:
                    return None
                na, nb = _num(a), _num(b)
                if na is None or nb is None:
                    if op == "+":
                        return _str(a) + _str(b)
                    return None
                return na + nb if op == "+" else na - nb
            left = f
        return left

    def mul(self):
        left = self.unary()
        while self.peek("*") or self.peek("/") or self.peek("%"):
            op = self.take()[1]
            right = self.unary()

            def f(l=left, r=right, op=op):
                a, b = _num(l()), _num(r())
                if a is None or b is None:
                    return None
                if op == "*":
                    return a * b
                if op == "/":
                    return a / b
                return a % b
            left = f
        return left

    def unary(self):
        if self.peek("-"):
            self.take()
            inner = self.unary()
            return lambda: None if _num(inner()) is None else -_num(inner())
        return self.primary()

    def primary(self):
        kind, val = self.take()
        if kind == "num":
            v = int(val) if "." not in val else float(val)
            return lambda: v
        if kind == "str":
            s = val[1:-1].replace('\\"', '"').replace("\\\\", "\\")
            return lambda: s
        if kind == "qfield":
            name = val[1:-1]
            return lambda: self.fields.get(name)
        if kind == "op" and val == "(":
            e = self.expr()
            self.take(")")
            return e
        if kind == "ident":
            if self.peek("("):
                self.take("(")
                args = []
                if not self.peek(")"):
                    args.append(self.expr())
                    while self.peek(","):
                        self.take(",")
                        args.append(self.expr())
                self.take(")")
                return self.func(val, args)
            name = val
            return lambda: self.fields.get(name)
        raise EvalError(f"unexpected token {kind} {val}")

    def func(self, name, args):
        n = name.lower()

        def need(k):
            if len(args) != k:
                raise EvalError(f"{name}() takes {k} arguments")
        if n == "case":
            if len(args) % 2:
                raise EvalError("case() needs pairs")

            def f():
                for c, v in zip(args[::2], args[1::2]):
                    if c() is True:
                        return v()
                return None
            return f
        if n == "if":
            need(3)
            return lambda: args[1]() if args[0]() is True else args[2]()
        if n == "coalesce":
            def f():
                for a in args:
                    v = a()
                    if v is not None and v != "":
                        return v
                return None
            return f
        if n == "isnull":
            need(1)
            return lambda: args[0]() is None
        if n == "isnotnull":
            need(1)
            return lambda: args[0]() is not None
        if n == "true":
            return lambda: True
        if n == "false":
            return lambda: False
        if n == "null":
            return lambda: None
        if n == "match":
            need(2)

            def f():
                s, rx = _str(args[0]()), args[1]()
                if s is None:
                    return None
                perl_compiles(rx)
                return re.search(pcre_to_python(rx), s) is not None
            return f
        if n == "lower":
            need(1)
            return lambda: None if args[0]() is None else _str(args[0]()).lower()
        if n == "upper":
            need(1)
            return lambda: None if args[0]() is None else _str(args[0]()).upper()
        if n == "replace":
            need(3)

            def f():
                s, rx, rep = _str(args[0]()), args[1](), args[2]()
                if s is None:
                    return None
                perl_compiles(rx)
                return re.sub(pcre_to_python(rx), rep.replace("\\", "\\"), s)
            return f
        if n == "tonumber":
            need(1)
            return lambda: _num(args[0]())
        if n == "tostring":
            need(1)
            return lambda: _str(args[0]())
        if n == "floor":
            need(1)
            return lambda: None if _num(args[0]()) is None else math.floor(_num(args[0]()))
        if n == "split":
            need(2)
            return lambda: None if args[0]() is None else _str(args[0]()).split(args[1]())
        if n == "mvindex":
            need(2)

            def f():
                mv, i = args[0](), _num(args[1]())
                if mv is None or i is None:
                    return None
                mv = mv if isinstance(mv, list) else [mv]
                i = int(i)
                return mv[i] if -len(mv) <= i < len(mv) else None
            return f
        if n == "len":
            need(1)
            return lambda: None if args[0]() is None else len(_str(args[0]()))
        raise EvalError(f"function {name}() not supported by the simulator")


def spl_eval(expr, fields):
    v = Parser(expr, fields).parse()()
    if isinstance(v, bool):
        return None if v is None else ("true" if v else "false")
    return _str(v) if not isinstance(v, list) else v


# ---------------------------------------------------------------- event type search
ET_TOKEN = re.compile(r"""\s*(?:(?P<lp>\()|(?P<rp>\))|(?P<kw>OR|NOT|AND)(?=[\s(]|$)|
    (?P<cmp>[A-Za-z_][\w.]*\s*(?:!=|=)\s*(?:"[^"]*"|[^\s()]+)))""", re.X)


def et_match(search, fields):
    toks = []
    pos, s = 0, search.strip()
    while pos < len(s):
        m = ET_TOKEN.match(s, pos)
        if not m or m.end() == pos:
            raise EvalError(f"event type search: cannot parse {s[pos:pos + 30]!r}")
        pos = m.end()
        toks.append((m.lastgroup, m.group(m.lastgroup)))
    i = 0

    def term():
        nonlocal i
        kind, val = toks[i]
        i += 1
        if kind == "lp":
            v = expr()
            assert toks[i][0] == "rp"
            i += 1
            return v
        if kind == "kw" and val == "NOT":
            return not term()
        m = re.match(r'([A-Za-z_][\w.]*)\s*(!=|=)\s*(?:"([^"]*)"|(\S+))', val)
        field, op, value = m.group(1), m.group(2), m.group(3) if m.group(3) is not None else m.group(4)
        have = fields.get(field)
        vals = have if isinstance(have, list) else ([] if have is None else [have])
        rx = "^" + ".*".join(re.escape(p) for p in value.split("*")) + "$"
        hit = any(re.match(rx, str(v), re.I) for v in vals)
        return hit if op == "=" else (bool(vals) and not hit)

    def conj():
        nonlocal i
        v = term()
        while i < len(toks) and not (toks[i][0] == "rp" or (toks[i][0] == "kw" and toks[i][1] == "OR")):
            if toks[i][0] == "kw" and toks[i][1] == "AND":
                i += 1
            v = term() and v
        return v

    def expr():
        nonlocal i
        v = conj()
        while i < len(toks) and toks[i][0] == "kw" and toks[i][1] == "OR":
            i += 1
            v = conj() or v
        return v
    return expr()


# ---------------------------------------------------------------- the add-on
class AddOn:
    def __init__(self, app_dir):
        d = os.path.join(app_dir, "default")
        self.props = read_conf(os.path.join(d, "props.conf"))
        self.transforms = read_conf(os.path.join(d, "transforms.conf"))
        self.eventtypes = read_conf(os.path.join(d, "eventtypes.conf"))
        self.tags = read_conf(os.path.join(d, "tags.conf"))
        self.compiled = {}
        for name, t in self.transforms.items():
            if "REGEX" in t:
                perl_compiles(t["REGEX"])
                self.compiled[name] = re.compile(pcre_to_python(t["REGEX"]))

    def process(self, sourcetype, raw, host="esxi01.example.com"):
        fields = {"_raw": raw, "sourcetype": sourcetype, "host": host}
        errors = []
        stanza = self.props.get(sourcetype)
        if stanza is None:
            return fields, [], [f"no props stanza for {sourcetype}"]
        setby = {}
        for key in sorted(k for k in stanza if k.startswith("REPORT-")):
            for tname in [t.strip() for t in stanza[key].split(",")]:
                t = self.transforms[tname]
                src = fields.get(t.get("SOURCE_KEY", "_raw"))
                if src is None:
                    continue
                m = self.compiled[tname].search(src)
                if not m:
                    continue
                for name, val in m.groupdict().items():
                    if val is None or val == "":
                        continue
                    if name in setby:
                        errors.append(f"{name} set by {setby[name]} and {tname}")
                        continue
                    setby[name] = tname
                    fields[name] = val
        before = dict(fields)
        for key in sorted(k for k in stanza if k.startswith("EVAL-")):
            name = key[5:]
            try:
                v = spl_eval(stanza[key], before)
            except EvalError as exc:
                errors.append(f"{key}: {exc}")
                continue
            if v is None:
                fields.pop(name, None)
            else:
                fields[name] = v
        ets = [et for et, s in self.eventtypes.items() if et_match(s["search"], fields)]
        fields["eventtype"] = sorted(ets)
        tags = set()
        for et in ets:
            for tag, state in self.tags.get(f"eventtype={et}", {}).items():
                if state == "enabled":
                    tags.add(tag)
        fields["tag"] = sorted(tags)
        return fields, sorted(tags), errors
