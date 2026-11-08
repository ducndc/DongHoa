#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Style check for docs/CODING_CONVENTION.md rules that the compiler does
not enforce. Usage: style_check.py [files...] (default: src/ and tools/).
Prints <file>:<line>: <rule>: <text> per finding and exits 1 if any.

Checked: line width <= 110 (tab = 8), indentation starts with tabs, no
trailing whitespace, no '/*' comments (5.7.1), no macro besides the include
guard DONGHOA_<FILE>_HPP (19.0.2), braces on every if/else/for/while body
(9.3.1), every 'if ... else if' chain ends with 'else' (9.4.1), every
switch has 'default' (9.4.2), classic for loops compare with '<' (9.5.1),
constexpr constants in UPPER_CASE (4), no function-local 'static' variable
(6.7.1), no new/delete/malloc, allocating std types, NULL, goto, union,
exceptions, throwing library calls (.substr/.at), C stdio outside os.cpp,
and namespace-scope variables only as listed in DEV-05."""
import glob
import os
import re
import sys

LIMIT = 110
# DEV-05: the only namespace-scope variables allowed (CODING_CONVENTION §6.2).
DEV05 = {"sDaemon", "sLevels", "sSyslog", "sCounter", "sStop", "sBpf", "sBpfProg", "sSimPath", "sSim", "sSimText"}


def width(s):
    return len(s.expandtabs(8))


def code_of(line):
    """The line without string/char literal contents and without a // comment."""
    out = []
    i = 0
    quote = None
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
                out.append(ch)
        else:
            if line.startswith("//", i):
                break
            if ch in "\"'":
                quote = ch
            out.append(ch)
        i += 1
    return "".join(out)


def check_file(path, root, findings):
    rel = os.path.relpath(path, root)
    base = os.path.basename(path)
    lines = open(path, encoding="utf-8").read().split("\n")
    code = [code_of(l) for l in lines]

    def add(n, rule, text):
        findings.append("%s:%d: %s: %s" % (rel, n, rule, text.strip()[:100]))

    for n, l in enumerate(lines, 1):
        if width(l) > LIMIT:
            add(n, "4 line wider than %d columns (%d)" % (LIMIT, width(l)), l)
        if re.match(r"^ +\S", l):
            add(n, "4 indentation must start with tabs", l)
        if l != l.rstrip():
            add(n, "4 trailing whitespace", l)
        if "/*" in code[n - 1]:
            add(n, "5.7.1 '/*' comment", l)

    # macros and include guard
    guard = "DONGHOA_" + base.rsplit(".", 1)[0].upper() + "_HPP"
    for n, c in enumerate(code, 1):
        m = re.match(r"^\s*#\s*define\s+(\w+)", c)
        if m and not (path.endswith(".hpp") and m.group(1) == guard):
            add(n, "19.0.2 macro (only the include guard is allowed)", c)
    if path.endswith(".hpp"):
        text = "\n".join(lines)
        if ("#ifndef " + guard) not in text or ("#define " + guard) not in text:
            add(1, "4 include guard must be " + guard, "")

    for n, c in enumerate(code, 1):
        s = c.strip()
        # 9.3.1: a control statement whose condition is complete on this line
        m = re.match(r"^(\} )?(else if|if|for|while)\s*\(", s)
        if m and s.count("(") == s.count(")") and not s.endswith("{") and not s.endswith(";"):
            nxt = code[n].strip() if n < len(code) else ""
            if not nxt.startswith("{"):
                add(n, "9.3.1 body must be in braces", lines[n - 1])
        if re.match(r"^(if|for|while)\s*\(.*\)\s*[^{\s].*;$", s) and s.count("(") == s.count(")") \
                and not s.startswith("for ("):
            add(n, "9.3.1 body must be in braces", lines[n - 1])
        if re.match(r"^(\} )?else$", s) or re.match(r"^(\} )?else\s+[^i{]", s):
            add(n, "9.3.1 else body must be in braces", lines[n - 1])
        # 9.5.1
        m = re.match(r"^for\s*\(([^;]*);([^;]*);", s)
        if m and m.group(2).strip() and not re.search(r"<(?!=)", m.group(2)):
            add(n, "9.5.1 for loop condition must compare with '<'", lines[n - 1])
        # constexpr naming
        m = re.match(r"^(static\s+)?constexpr\s+[^=({]*?\b([A-Za-z_]\w*)\s*(\{|=)", s)
        if m and not re.match(r"^[A-Z][A-Z0-9_]*$", m.group(2)):
            add(n, "4 constant must be UPPER_CASE", lines[n - 1])
        # forbidden constructs
        if re.search(r"\bnew\s+[\w:(]|\bdelete\s+[\w(\[]|\bdelete\[\]", c):
            add(n, "21.6 no new/delete", lines[n - 1])
        if re.search(r"\b(malloc|calloc|realloc|free)\s*\(", c):
            add(n, "21.6 no malloc/free", lines[n - 1])
        if re.search(r"std::(string|vector|function|map|unordered_map|list|deque|unique_ptr|shared_ptr)\b(?!_view)", c):
            add(n, "21.6 no allocating standard type", lines[n - 1])
        if re.search(r"\bNULL\b", c):
            add(n, "7.11 use nullptr", lines[n - 1])
        if re.search(r"\b(goto|union)\b", c):
            add(n, "9.6.1/12.3.1 no goto or union", lines[n - 1])
        if re.search(r"\b(throw|try|catch)\b", c):
            add(n, "18 no exceptions", lines[n - 1])
        if re.search(r"\.(substr|at)\s*\(", c):
            add(n, "18 no throwing library call (use subView / operator[])", lines[n - 1])
        if base != "os.cpp" and re.search(r"\b(std::)?(printf|fprintf|sprintf|snprintf|puts|fopen)\s*\(", c):
            add(n, "30.0.1 no C stdio outside os.cpp", lines[n - 1])
        if re.match(r"^\t+static\s+(?!constexpr\b|const\b|_assert\b)[\w:<>,\s]+\s+\w+\s*(\{|=|;)", c) and "(" not in c:
            add(n, "6.7.1 no function-local static", lines[n - 1])

    # 9.4.1: an 'if ... else if' chain ends with 'else'
    for n, c in enumerate(code, 1):
        if not re.match(r"^\t*\} else if\s*\(", c):
            continue
        ind = len(c) - len(c.lstrip("\t"))
        k = n
        last = None
        while k < len(code):
            ck = code[k]
            if (len(ck) - len(ck.lstrip("\t"))) == ind and ck.strip().startswith("}"):
                last = ck.strip()
                if last.startswith("} else if"):
                    k += 1
                    continue
                break
            k += 1
        if last == "}":
            add(n, "9.4.1 'if ... else if' chain must end with 'else'", lines[n - 1])

    # 9.4.2: every switch has a default
    text = "\n".join(code)
    for m in re.finditer(r"\bswitch\s*\(", text):
        start = text.find("{", m.end())
        depth = 0
        k = start
        while 0 <= k < len(text):
            if text[k] == "{":
                depth += 1
            elif text[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        if "default:" not in text[start:k]:
            add(text.count("\n", 0, m.start()) + 1, "9.4.2 switch must have 'default'", "")

    # DEV-05: namespace-scope variables
    depth = 0
    for n, c in enumerate(code, 1):
        s = c.strip()
        if depth <= 2 and re.match(r"^[A-Za-z]", c) and not s.startswith(("constexpr", "const ", "using", "namespace",
                                                                        "return", "class", "struct", "enum", "template",
                                                                        "#", "typedef", "static_assert", "extern")):
            m = re.match(r"^(volatile\s+)?[\w:<>,\s]+?\s+(\w+)\s*(\{[^}]*\}|=[^;]*)?;$", s)
            head = re.split(r"\s=\s|\{", s)[0]  # declarator part, before the initializer
            if m and "(" not in head and m.group(2) not in DEV05:
                add(n, "6.7.2 namespace-scope variable not listed in DEV-05", lines[n - 1])
        depth += c.count("{") - c.count("}")


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files = sys.argv[1:] or sorted(glob.glob(os.path.join(root, "src", "*.[ch]pp")) +
                                   glob.glob(os.path.join(root, "tools", "*.cpp")))
    findings = []
    for f in files:
        check_file(f, root, findings)
    for x in findings:
        print(x)
    print("style: %d file(s), %d finding(s)" % (len(files), len(findings)))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
