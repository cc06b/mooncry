"""Machine-check the API contracts that the docs only assert in prose.

    python3 .github/scripts/api_contract_check.py            # from the repo root
    python3 .github/scripts/api_contract_check.py --lib lib  # explicit source dir

Three checks, all static, all seconds:

  C1  every `pub fn *_or` returns `Result[...]`.
      The `_or` family is the "never traps, reports as a value" tier; a twin
      that returns Bool/Option silently joins a different tier and the
      README's error-channel table stops being true.

  C2  every aborting twin `foo` whose `foo_or` exists must share ONE guard with
      it: either one reaches the other through the call graph (delegation, at
      any depth, in either direction), or both are thin wrappers over a shared
      private core that owns the checks (the ml_kem family). What fails is a
      pair that each carries its own `abort("...")` / `Err("...")`: two
      independently maintained conditions and strings. Two implementations of
      the same operation drift -- that is how the v0.84.0 SHAKE guard ended up
      on only one of the two squeeze paths. An entry in
      ALLOWED_NON_DELEGATING means the divergence is documented behaviour and
      must carry a reason.

  C3  every API name the README's Public API table documents must exist in the
      source. Four signatures written from memory were caught this way while
      drafting the v0.83.0 rows. Only phantoms are fatal: the reverse list
      (public and never documented) over-reports, because the table uses
      grouped forms like `ml_kem_512/768/1024_encaps_or`.

Exit code is non-zero if any check fails; violations are also emitted as
GitHub workflow annotations.
"""
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

# C2 exceptions: pairs that deliberately do NOT share one guard. Each needs a
# reason, and the reason has to be a documented behavioural difference -- not
# "it was already like that".
ALLOWED_NON_DELEGATING = {
    "aes_decrypt_cbc": (
        "documented divergence, not drift: aes_decrypt_cbc keeps the lenient "
        "PKCS#7 behaviour (pkcs7_unpad returns the input unchanged when the "
        "padding is invalid) and accepts an IV-only 16-byte input, while "
        "aes_decrypt_cbc_or requires >= 32 bytes and reports bad padding as "
        "Err. Making one delegate to the other would change a documented "
        "behaviour; the README steers untrusted ciphertext to the _or twin."
    ),
}


# --------------------------------------------------------------------------
# a small MoonBit scanner: strip comments and string/char literals so that
# brace counting and name matching cannot be fooled by "//" or "{" in a
# message like abort("...")
# --------------------------------------------------------------------------
def strip_noise(src):
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 1
            out.append("  ")
            i += 2
            while i < n and depth:
                if src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    depth += 1
                    i += 2
                elif src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    depth -= 1
                    i += 2
                else:
                    out.append("\n" if src[i] == "\n" else " ")
                    i += 1
            continue
        if c == '"':
            out.append(" ")
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\":
                    out.append("  ")
                    i += 2
                    continue
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            i += 1
            out.append(" ")
            continue
        if c == "'":  # byte/char literal: b'\x7b' must not count as a brace
            out.append(" ")
            i += 1
            while i < n and src[i] != "'":
                if src[i] == "\\":
                    out.append(" ")
                    i += 2
                    continue
                out.append(" ")
                i += 1
            i += 1
            out.append(" ")
            continue
        out.append(c)
        i += 1
    return "".join(out)


def match_delim(s, i, open_ch, close_ch):
    """Index just past the delimiter matching the one at s[i]."""
    depth = 0
    while i < len(s):
        if s[i] == open_ch:
            depth += 1
        elif s[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def parse_functions(clean):
    """Yield (name, signature, return_type, body) for every `pub fn`.

    The return type is taken from *after* the parameter list closes: a
    parameter may itself have a function type (`rand : (Int) -> Bytes`), and
    matching the first `->` in the signature picks that one up instead.
    """
    for m in re.finditer(r"\bpub\s+fn\s+([A-Za-z0-9_]+)", clean):
        name = m.group(1)
        i = m.end()
        after_params = -1
        while i < len(clean) and clean[i] != "{":
            if clean[i] == "(":
                j = match_delim(clean, i, "(", ")")
                if j < 0:
                    break
                after_params = j
                i = j
                continue
            if clean[i] == "[":
                j = match_delim(clean, i, "[", "]")
                if j < 0:
                    break
                i = j
                continue
            i += 1
        sig = " ".join(clean[m.start():i].split())
        tail = clean[after_params:i] if after_params > 0 else clean[m.end():i]
        rm = re.search(r"->\s*(.+)$", " ".join(tail.split()))
        ret = rm.group(1).strip() if rm else ""
        end = match_delim(clean, i, "{", "}")
        body = clean[i:end] if end > 0 else ""
        yield name, sig, ret, body


def all_functions(clean):
    """Same, for every `fn` (public or private) -- used for the call graph."""
    for m in re.finditer(r"\bfn\s+([A-Za-z0-9_]+)", clean):
        i = m.end()
        while i < len(clean) and clean[i] != "{":
            if clean[i] in "([":
                closer = ")" if clean[i] == "(" else "]"
                j = match_delim(clean, i, clean[i], closer)
                if j < 0:
                    break
                i = j
                continue
            i += 1
        end = match_delim(clean, i, "{", "}")
        yield m.group(1), (clean[i:end] if end > 0 else "")


def callees(body):
    """Identifiers that look like a call inside a body."""
    return set(re.findall(r"([A-Za-z0-9_]+)\s*\(", body))


def source_files(*dirs):
    """Non-test sources of every package directory that exists. `internal/` is
    part of the module: its names are not importable downstream, but they are
    still names the README may mention, so C3 has to know them."""
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if f.endswith(".mbt") and not f.endswith("_test.mbt"):
                yield f, io.open(os.path.join(d, f), encoding="utf-8").read()


# --------------------------------------------------------------------------
# C3 helpers (lifted from agent_box/_tools/_check_readme_api.py, whose richer
# report stays the maintainer-side tool)
# --------------------------------------------------------------------------
def expand(tok):
    tok = tok.strip().strip(".,;:")
    if not tok:
        return []
    tok = re.sub(r"\(.*", "", tok)
    out = set()
    brace = re.search(r"\{([^}]*)\}", tok)
    if brace:
        for alt in brace.group(1).split(","):
            out.update(expand(tok[:brace.start()] + alt.strip() + tok[brace.end():]))
        return sorted(out)
    if "/" in tok:
        parts = [x.strip() for x in tok.split("/") if x.strip()]
        first = parts[0]
        out.add(first)
        m = re.match(r"^(.*?)(\d+)(.*)$", first)
        if m and all(re.match(r"^\d+$", p) for p in parts[1:]):
            for p in parts[1:]:
                out.add(m.group(1) + p + m.group(3))
            return sorted(out)
        prefix = first[:first.rfind("_") + 1] if "_" in first else ""
        for p in parts[1:]:
            out.add(p)
            if prefix:
                out.add(prefix + p)
        return sorted(out)
    return [tok]


def documented_tokens(readme):
    start = readme.index("## Public API")
    end = readme.index("## Security & performance boundaries")
    toks = set()
    for row in readme[start:end].split("\n"):
        if not row.startswith("|"):
            continue
        # only the first cell: it holds the signatures. The description cell is
        # prose and backticks parameter names (`digits`, `out_len`, `rand_ps`),
        # which are not API names and would only add noise to the phantom list.
        cells = row.split("|")
        if len(cells) < 2:
            continue
        for m in re.finditer(r"`([^`]+)`", cells[1]):
            cell = m.group(1).split("->")[0]
            if "{" in cell and "}" in cell:
                candidates = [cell]
            else:
                candidates = re.split(r"[,;]| and ", re.sub(r"\([^)]*\)", "", cell))
            for piece in candidates:
                piece = piece.strip()
                if not re.match(r"^[a-z][A-Za-z0-9_/{}… ]*$", piece):
                    continue
                bare = piece.split("/")[0].split("(")[0].strip()
                if "_" in bare or len(bare) >= 6 or "{" in piece:
                    toks.add(piece)
    return toks


def main():
    libdir = ROOT
    if "--lib" in sys.argv:
        libdir = sys.argv[sys.argv.index("--lib") + 1]
    else:
        libdir = os.path.join(ROOT, "lib")
    dirs = [libdir]
    sibling = os.path.join(os.path.dirname(libdir), "internal")
    if os.path.isdir(sibling):
        dirs.append(sibling)
    problems = []

    funcs = {}          # name -> (file, sig, ret, body)
    graph = {}          # every fn name -> set(callees), for transitive delegation
    public_names = set()
    for fname, text in source_files(*dirs):
        clean = strip_noise(text)
        for name, sig, ret, body in parse_functions(clean):
            funcs.setdefault(name, (fname, sig, ret, body))
        for name, body in all_functions(clean):
            graph.setdefault(name, set()).update(callees(body))
        for m in re.finditer(r"^pub\s+(?:fn|let|struct|enum|type)\s+([A-Za-z0-9_]+)",
                             clean, re.M):
            public_names.add(m.group(1))

    def reaches(start, depth=6):
        """Names transitively called from `start` (bounded, cycle-safe)."""
        seen, frontier = set(), [start]
        for _ in range(depth):
            nxt = []
            for f in frontier:
                for c in graph.get(f, ()):
                    if c not in seen:
                        seen.add(c)
                        nxt.append(c)
            frontier = nxt
            if not frontier:
                break
        return seen

    # ---- C1: every _or returns Result ----
    ors = sorted(n for n in funcs if n.endswith("_or"))
    c1 = 0
    for n in ors:
        fname, sig, ret, _ = funcs[n]
        if not ret.startswith("Result["):
            c1 += 1
            problems.append("C1 %s (%s) returns %r, not Result[_]"
                            % (n, fname, ret or "<nothing>"))
    print("C1  %d `_or` entry points, all returning Result: %s"
          % (len(ors), "yes" if not c1 else "NO (%d)" % c1))

    # ---- C2: one guard, one message ----
    # The invariant that matters is not "foo calls foo_or" but "the validation
    # is written once". Two shapes satisfy it:
    #   * delegation, transitively, in either direction (foo -> foo_or, or the
    #     _or twin wraps the aborting primitive);
    #   * both bodies are thin wrappers over a shared private core that holds
    #     the guard (the ml_kem family: kem_encaps_or owns the checks, and
    #     kem_encaps_internal aborts on its Err).
    # What fails is a pair that each carries its own guard: an `abort("...")`
    # on one side and an `Err("...")` on the other, with no path between them.
    # That is two independently maintained conditions and two independently
    # maintained strings -- exactly the drift that put the v0.84.0 SHAKE
    # out_len guard on only one of the two squeeze paths.
    c2 = checked = 0
    for n in ors:
        base = n[:-3]
        if base not in funcs:
            continue
        checked += 1
        fname = funcs[base][0]
        if n in reaches(base) or base in reaches(n):
            continue
        if base in ALLOWED_NON_DELEGATING:
            print("    (allowed) %s: %s" % (base, ALLOWED_NON_DELEGATING[base]))
            continue
        base_body, or_body = funcs[base][3], funcs[n][3]
        if "abort(" in base_body and re.search(r"\bErr\(", or_body):
            c2 += 1
            problems.append(
                "C2 %s (%s) aborts on its own guard while %s returns its own "
                "Err, and neither reaches the other -- the condition and the "
                "message are maintained twice" % (base, fname, n))
    print("C2  %d aborting/`_or` pairs, one guard each: %s"
          % (checked, "yes" if not c2 else "NO (%d)" % c2))

    # ---- C3: README documents only names that exist ----
    readme_path = os.path.join(ROOT, "README.md")
    c3 = 0
    if os.path.exists(readme_path):
        readme = io.open(readme_path, encoding="utf-8").read()
        try:
            toks = documented_tokens(readme)
        except ValueError as e:
            toks = set()
            problems.append("C3 README section markers not found: %s" % e)
        for t in sorted(toks):
            if not [c for c in expand(t) if c in public_names]:
                c3 += 1
                problems.append("C3 README documents `%s`, no such public name "
                                "in lib/" % t)
        print("C3  %d documented tokens, %d public names in %s, phantoms: %d"
              % (len(toks), len(public_names),
                 "+".join(os.path.basename(d) for d in dirs), c3))
    else:
        print("C3  skipped (no README.md at %s)" % ROOT)

    for p in problems:
        print("::error::%s" % p)
        print("    %s" % p)
    print("\n%d problem(s)" % len(problems))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
