#!/usr/bin/env python3
"""SHA-1 dependency boundary and compatibility-crate architecture checks.

Usage: scripts/check-sha1-boundary.py [--self-test]

Run by scripts/check-workspace.sh (python3 standard library only). Rules:

Resolved application graphs (`cargo tree -p tatami_ssh --no-default-features
--features F -e normal --target all --no-dedupe`, package names as resolved,
never dependency alias text):

  G1  Compatibility builds (COMPAT_ON): every normal-dependency path from the
      facade to a dedicated SHA-1 package (SHA1_PACKAGES) passes through
      tatami_ssh_openssh_compat; the compatibility crate is reached, and only
      from tatami_ssh_keys; at least one SHA-1 package is reached through it
      (so the rule is not vacuous).
  G2  Compatibility disabled (COMPAT_OFF): neither tatami_ssh_openssh_compat
      nor any dedicated SHA-1 package is reachable.

Architecture (`cargo metadata --format-version 1 --all-features`: resolved
edges by package id, plus declared dependencies by package name, so a
`package = "..."` rename cannot hide an edge):

  A1  Only tatami_ssh_keys may depend (any kind) on tatami_ssh_openssh_compat.
  A2  No workspace package other than tatami_ssh_openssh_compat may depend
      (any kind) directly on `hmac` or a dedicated SHA-1 package.
  A3  The compatibility crate is the single file src/lib.rs whose public
      items are exactly `pub fn matches_hashed_hostname` and
      `pub enum HashedHostnameError`: no other `pub` item (restricted
      visibility included), no `pub use` re-export, no `#[macro_export]`.
  A4  Inside tatami_ssh_keys only src/known_hosts.rs mentions the
      compatibility crate, by its crate name or any rename declared in the
      manifest (comments and string literals are ignored), and it does not
      re-export it.

--self-test feeds synthetic graphs, metadata and sources containing each
forbidden construct and asserts that it is reported, and that a clean
fixture passes.
"""

import json
import os
import re
import subprocess
import sys

COMPAT = "tatami_ssh_openssh_compat"
KEYS = "tatami_ssh_keys"
FACADE = "tatami_ssh"
SHA1_PACKAGES = {"sha1", "sha-1", "sha1_smol", "sha1-asm", "sha1-checked"}
HMAC_PACKAGES = {"hmac"}
COMPAT_API = [("enum", "HashedHostnameError"), ("fn", "matches_hashed_hostname")]
ALLOWED_CALL_SITE = "src/known_hosts.rs"

COMPAT_ON = [
    "std,tcp,kex,quic-diag,openssh-hashed-hosts",
    "kex,openssh-hashed-hosts",
]
COMPAT_OFF = ["std,tcp,kex,quic-diag", "std,tcp,kex", "kex", "std,tcp", "quic-diag", ""]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---- graph rules (G1, G2) -------------------------------------------------

TREE_LINE = re.compile(r"^(\d+)(\S+) v(\S+)")


def parse_tree(text):
    """`cargo tree --prefix depth --format '{p}'` → [(depth, name)]."""
    nodes = []
    for line in text.splitlines():
        m = TREE_LINE.match(line)
        if m:
            nodes.append((int(m.group(1)), m.group(2)))
    return nodes


def check_graph(nodes, compat_enabled, label):
    """Returns violation messages for one resolved facade graph."""
    out = []
    stack = []
    saw_compat = saw_sha1_via_compat = False
    for depth, name in nodes:
        del stack[depth:]
        stack.append(name)
        path = " -> ".join(stack)
        if compat_enabled:
            if name == COMPAT:
                saw_compat = True
                parent = stack[-2] if len(stack) > 1 else None
                if parent != KEYS:
                    out.append(f"G1 [{label}] {COMPAT} reached from {parent}, not {KEYS}: {path}")
            if name in SHA1_PACKAGES:
                if COMPAT in stack[:-1]:
                    saw_sha1_via_compat = True
                else:
                    out.append(f"G1 [{label}] SHA-1 package {name} reachable outside {COMPAT}: {path}")
        elif name == COMPAT or name in SHA1_PACKAGES:
            out.append(f"G2 [{label}] {name} reachable with compatibility disabled: {path}")
    if compat_enabled and not saw_compat:
        out.append(f"G1 [{label}] {COMPAT} not reachable in a compatibility build")
    if compat_enabled and saw_compat and not saw_sha1_via_compat:
        out.append(f"G1 [{label}] no SHA-1 package reached through {COMPAT}; rule would be vacuous")
    return out


def cargo_tree(features):
    cmd = ["cargo", "tree", "-p", FACADE, "--no-default-features"]
    if features:
        cmd += ["--features", features]
    cmd += ["-e", "normal", "--target", "all", "--no-dedupe", "--prefix", "depth",
            "--format", "{p}", "--charset", "ascii"]
    return subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True, text=True).stdout


# ---- metadata rules (A1, A2) ------------------------------------------------

def norm(name):
    return name.replace("-", "_")


def check_metadata(meta):
    """Returns (violations, compat identifiers usable inside tatami_ssh_keys)."""
    out = []
    pkgs = {p["id"]: p for p in meta["packages"]}
    members = set(meta["workspace_members"])
    idents = {COMPAT}

    def edge(owner, dep_pkg, how):
        if dep_pkg == COMPAT and owner != KEYS:
            out.append(f"A1 {owner} depends on {COMPAT} ({how}); only {KEYS} may")
        if (dep_pkg in SHA1_PACKAGES or dep_pkg in HMAC_PACKAGES) and owner != COMPAT:
            out.append(f"A2 {owner} depends directly on {dep_pkg} ({how}); only {COMPAT} may")

    for mid in sorted(members):
        pkg = pkgs[mid]
        for d in pkg.get("dependencies", []):
            alias = d.get("rename")
            how = f"declared{' as ' + alias if alias else ''}, kind {d.get('kind') or 'normal'}"
            edge(pkg["name"], d["name"], how)
            if pkg["name"] == KEYS and d["name"] == COMPAT and alias:
                idents.add(norm(alias))
    for node in (meta.get("resolve") or {}).get("nodes", []):
        if node["id"] not in members:
            continue
        owner = pkgs[node["id"]]["name"]
        for d in node.get("deps", []):
            dep_pkg = pkgs[d["pkg"]]["name"]
            kinds = ",".join(sorted({k.get("kind") or "normal" for k in d.get("dep_kinds", [])}))
            edge(owner, dep_pkg, f"resolved as extern `{d['name']}`, kind {kinds or 'normal'}")
            if owner == KEYS and dep_pkg == COMPAT:
                idents.add(norm(d["name"]))
    return out, idents


# ---- source rules (A3, A4) ----------------------------------------------------

def strip_comments_and_strings(src):
    """Blanks comments, string and char literals; keeps newlines and code."""
    out = []
    i, n = 0, len(src)

    def blank(text):
        out.append("".join("\n" if c == "\n" else " " for c in text))

    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            blank(src[i:j])
            i = j
        elif src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif src.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(src[i:j])
            i = j
        elif (m := re.compile(r'b?r(#*)"').match(src, i)) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            end = src.find('"' + m.group(1), m.end())
            j = n if end < 0 else end + 1 + len(m.group(1))
            blank(src[i:j])
            i = j
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            blank(src[i:j + 1])
            i = j + 1
        elif c == "'":
            m = re.compile(r"'(\\(u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^\\'])'", re.S).match(src, i)
            if m:
                blank(m.group(0))
                i = m.end()
            else:  # lifetime or label
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


PUB_ITEM = re.compile(
    r"\bpub\b(\s*\([^)]*\))?\s*"
    r"((?:(?:const|async|unsafe|default)\s+|extern\s+(?:\"[^\"]*\"\s+)?)*)"
    r"(fn|enum|struct|union|trait|type|const|static|mod|use|macro|crate|extern\s+crate)?\s*([A-Za-z_][A-Za-z0-9_]*)?"
)


def check_compat_sources(files):
    """`files`: {relative path under the compat crate: text}."""
    out = []
    extra = sorted(p for p in files if p.endswith(".rs") and p != "src/lib.rs")
    for p in extra:
        out.append(f"A3 {COMPAT} must be the single file src/lib.rs; found {p}")
    lib = files.get("src/lib.rs")
    if lib is None:
        return out + [f"A3 {COMPAT}/src/lib.rs missing"]
    code = strip_comments_and_strings(lib)
    found = []
    for m in PUB_ITEM.finditer(code):
        line = code.count("\n", 0, m.start()) + 1
        restricted, kw, ident = m.group(1), m.group(3), m.group(4)
        kw = re.sub(r"\s+", " ", kw) if kw else None
        if kw == "use":
            out.append(f"A3 {COMPAT}/src/lib.rs:{line}: re-export `pub use` is forbidden")
        elif restricted:
            out.append(f"A3 {COMPAT}/src/lib.rs:{line}: `pub{restricted.strip()}` item is forbidden")
        elif (kw, ident) in COMPAT_API:
            found.append((kw, ident))
        else:
            out.append(f"A3 {COMPAT}/src/lib.rs:{line}: extra public item `pub {kw or ''} {ident or ''}`")
    if sorted(found) != sorted(COMPAT_API):
        out.append(f"A3 {COMPAT} public API is {sorted(found)}, expected exactly {sorted(COMPAT_API)}")
    if re.search(r"macro_export", code):
        out.append(f"A3 {COMPAT}/src/lib.rs: #[macro_export] is forbidden")
    return out


def check_keys_call_sites(files, idents):
    """`files`: {relative path under tatami_ssh_keys: text}."""
    out = []
    pattern = re.compile(r"\b(" + "|".join(sorted(map(re.escape, idents))) + r")\b")
    reexport = re.compile(r"\bpub\b(\s*\([^)]*\))?\s*(use|extern\s+crate)\b[^;]*\b(" +
                          "|".join(sorted(map(re.escape, idents))) + r")\b")
    for path in sorted(files):
        code = strip_comments_and_strings(files[path])
        for m in pattern.finditer(code):
            line = code.count("\n", 0, m.start()) + 1
            if path != ALLOWED_CALL_SITE:
                out.append(f"A4 {KEYS}/{path}:{line}: references `{m.group(1)}`; only {ALLOWED_CALL_SITE} may")
        for m in reexport.finditer(code):
            line = code.count("\n", 0, m.start()) + 1
            out.append(f"A4 {KEYS}/{path}:{line}: re-exports the compatibility crate")
    return out


def read_tree(base, suffix=".rs"):
    files = {}
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d != "target"]
        for f in filenames:
            if f.endswith(suffix):
                full = os.path.join(dirpath, f)
                with open(full, encoding="utf-8") as fh:
                    files[os.path.relpath(full, base).replace(os.sep, "/")] = fh.read()
    return files


# ---- driver -----------------------------------------------------------------------

def run_checks():
    violations = []
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--all-features"],
        cwd=ROOT, check=True, capture_output=True, text=True).stdout)
    names = {p["name"]: p for p in meta["packages"] if p["id"] in set(meta["workspace_members"])}
    for required in (COMPAT, KEYS, FACADE):
        if required not in names:
            violations.append(f"workspace package {required} not found")
    if violations:
        return violations
    v, idents = check_metadata(meta)
    violations += v
    print(f"check-sha1-boundary: A1/A2 over {len(names)} workspace packages; "
          f"compat identifiers in {KEYS}: {sorted(idents)}")

    compat_dir = os.path.dirname(names[COMPAT]["manifest_path"])
    keys_dir = os.path.dirname(names[KEYS]["manifest_path"])
    violations += check_compat_sources(read_tree(compat_dir))
    violations += check_keys_call_sites(read_tree(keys_dir), idents)
    print("check-sha1-boundary: A3 compat public API, A4 call sites checked")

    for features, enabled in [(f, True) for f in COMPAT_ON] + [(f, False) for f in COMPAT_OFF]:
        label = features or "no features"
        nodes = parse_tree(cargo_tree(features))
        if not nodes or nodes[0] != (0, FACADE):
            violations.append(f"[{label}] unexpected cargo tree output")
            continue
        v = check_graph(nodes, enabled, label)
        violations += v
        print(f"check-sha1-boundary: {'G1' if enabled else 'G2'} [{label}]: "
              f"{len(nodes)} graph nodes, {'ok' if not v else 'VIOLATION'}")
    return violations


def self_test():
    failures = []

    def expect(what, violations, needle):
        if not any(needle in v for v in violations):
            failures.append(f"{what}: expected a violation containing {needle!r}, got {violations}")

    def clean(what, violations):
        if violations:
            failures.append(f"{what}: clean fixture reported {violations}")

    # G1/G2 over synthetic resolved graphs.
    good_on = """0tatami_ssh v0.1.0 (/w/crates/tatami_ssh)
1tatami_ssh_keys v0.1.0 (/w/crates/tatami_ssh_keys)
2tatami_ssh_openssh_compat v0.1.0 (/w/crates/tatami_ssh_openssh_compat)
3hmac v0.12.1
4digest v0.10.7
3sha1 v0.10.7
4cpufeatures v0.2.17
1tatami_ssh_tcp v0.1.0 (/w/crates/tatami_ssh_tcp)
2sha2 v0.10.9
"""
    good_off = """0tatami_ssh v0.1.0 (/w/crates/tatami_ssh)
1tatami_ssh_keys v0.1.0 (/w/crates/tatami_ssh_keys)
2sha2 v0.10.9
1tatami_ssh_tcp v0.1.0 (/w/crates/tatami_ssh_tcp)
"""
    clean("G1 clean", check_graph(parse_tree(good_on), True, "t"))
    clean("G2 clean", check_graph(parse_tree(good_off), False, "t"))
    bypass = good_on + "2sha1 v0.10.7\n"  # tatami_ssh_tcp -> sha1
    expect("G1 forbidden edge", check_graph(parse_tree(bypass), True, "t"),
           "SHA-1 package sha1 reachable outside")
    via_tcp = good_on + "2tatami_ssh_openssh_compat v0.1.0 (/w)\n3sha1 v0.10.7\n"
    expect("G1 compat from another crate", check_graph(parse_tree(via_tcp), True, "t"),
           "reached from tatami_ssh_tcp")
    expect("G1 vacuous", check_graph(parse_tree(good_off), True, "t"), "not reachable")
    expect("G2 compat present", check_graph(parse_tree(good_on), False, "t"),
           "tatami_ssh_openssh_compat reachable with compatibility disabled")
    expect("G2 sha-1 present", check_graph(parse_tree(good_off + "2sha-1 v0.10.1\n"), False, "t"),
           "sha-1 reachable")

    # A1/A2 over synthetic metadata, with resolved ids and renames.
    def pkg(name, deps=()):
        return {"id": f"path+file:///w/{name}#0.1.0", "name": name,
                "manifest_path": f"/w/{name}/Cargo.toml",
                "dependencies": [{"name": d, "rename": r, "kind": None} for d, r in deps]}

    def meta_of(packages, edges):
        ids = {p["name"]: p["id"] for p in packages}
        for ext in ("hmac", "sha1", "digest"):
            if ext not in ids:
                packages.append({"id": f"registry+x#{ext}@1", "name": ext, "dependencies": []})
                ids[ext] = f"registry+x#{ext}@1"
        members = [p["id"] for p in packages if p["id"].startswith("path+")]
        nodes = {}
        for owner, dep, extern in edges:
            nodes.setdefault(owner, []).append(
                {"name": extern, "pkg": ids[dep], "dep_kinds": [{"kind": None, "target": None}]})
        return {"packages": packages, "workspace_members": members,
                "resolve": {"nodes": [{"id": ids[o], "deps": d} for o, d in nodes.items()]}}

    clean_pkgs = [pkg(KEYS, [(COMPAT, None)]), pkg(COMPAT, [("hmac", None), ("sha1", None)]),
                  pkg(FACADE, [(KEYS, None)]), pkg("tatami_ssh_tcp", [(KEYS, None)])]
    clean_edges = [(KEYS, COMPAT, COMPAT), (COMPAT, "hmac", "hmac"), (COMPAT, "sha1", "sha1"),
                   (FACADE, KEYS, KEYS)]
    v, idents = check_metadata(meta_of([dict(p) for p in clean_pkgs], clean_edges))
    clean("A1/A2 clean", v)
    if idents != {COMPAT}:
        failures.append(f"A4 identifiers: {idents}")

    renamed_sha1 = [dict(p) for p in clean_pkgs]
    renamed_sha1[3] = pkg("tatami_ssh_tcp", [(KEYS, None), ("sha1", "digest_alias")])
    v, _ = check_metadata(meta_of(renamed_sha1, clean_edges + [("tatami_ssh_tcp", "sha1", "digest_alias")]))
    expect("A2 renamed sha1 (declared)", v, "A2 tatami_ssh_tcp depends directly on sha1 (declared as digest_alias")
    expect("A2 renamed sha1 (resolved)", v, "A2 tatami_ssh_tcp depends directly on sha1 (resolved as extern `digest_alias`")
    # The same edge present only in the resolved graph is still caught.
    v, _ = check_metadata(meta_of([dict(p) for p in clean_pkgs],
                                  clean_edges + [("tatami_ssh_tcp", "sha1", "digest_alias")]))
    expect("A2 renamed sha1 (resolved only)", v, "resolved as extern `digest_alias`")
    v, _ = check_metadata(meta_of([dict(p) for p in clean_pkgs], clean_edges + [(FACADE, "hmac", "hmac")]))
    expect("A2 hmac", v, "A2 tatami_ssh depends directly on hmac")
    renamed_compat = [dict(p) for p in clean_pkgs]
    renamed_compat[3] = pkg("tatami_ssh_tcp", [(KEYS, None), (COMPAT, "legacy")])
    v, _ = check_metadata(meta_of(renamed_compat, clean_edges + [("tatami_ssh_tcp", COMPAT, "legacy")]))
    expect("A1 renamed compat", v, "A1 tatami_ssh_tcp depends on tatami_ssh_openssh_compat")
    keys_rename = [dict(p) for p in clean_pkgs]
    keys_rename[0] = pkg(KEYS, [(COMPAT, "legacy-compat")])
    _, idents_renamed = check_metadata(meta_of(keys_rename, [(KEYS, COMPAT, "legacy_compat")]))
    if idents_renamed != {COMPAT, "legacy_compat"}:
        failures.append(f"A4 rename not collected: {idents_renamed}")

    # A3 over synthetic compat sources.
    lib = '''//! Docs mentioning `pub fn fake()` and pub use hmac; in a comment.
#![no_std]
use hmac::Mac as _;
/* block: pub fn hidden() {} /* nested pub struct X; */ */
const NOTE: &str = "pub fn not_code() {}";
const RAW: &str = r#"pub use sha1::Sha1;"#;
const Q: char = '"';
/// The error.
pub enum HashedHostnameError { Grammar }
impl core::fmt::Display for HashedHostnameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { f.write_str("x") }
}
/// Matches.
pub fn matches_hashed_hostname(a: &[u8], b: &[u8]) -> Result<bool, HashedHostnameError> { Ok(a == b) }
#[cfg(test)]
mod tests { fn helper() {} }
'''
    clean("A3 clean", check_compat_sources({"src/lib.rs": lib}))
    expect("A3 extra pub fn", check_compat_sources({"src/lib.rs": lib + "pub fn digest_sha1() {}\n"}),
           "extra public item `pub fn digest_sha1`")
    expect("A3 pub use hmac", check_compat_sources({"src/lib.rs": lib + "pub use hmac;\n"}),
           "re-export `pub use`")
    expect("A3 pub(crate)", check_compat_sources({"src/lib.rs": lib + "pub(crate) const K: u8 = 1;\n"}),
           "`pub(crate)` item")
    expect("A3 extra module file", check_compat_sources({"src/lib.rs": lib, "src/extra.rs": ""}),
           "single file")
    expect("A3 missing item", check_compat_sources({"src/lib.rs": lib.replace("pub enum", "enum")}),
           "public API is")
    expect("A3 macro_export", check_compat_sources({"src/lib.rs": lib + "#[macro_export]\nmacro_rules! m { () => {} }\n"}),
           "macro_export")

    # A4 over synthetic tatami_ssh_keys sources.
    keys_files = {
        "src/known_hosts.rs": "fn f(x: &[u8]) -> bool {\n"
                              "    tatami_ssh_openssh_compat::matches_hashed_hostname(x, b\"\").is_ok()\n}\n",
        "src/trust.rs": "// tatami_ssh_openssh_compat is used only by known_hosts.\n"
                        "const S: &str = \"tatami_ssh_openssh_compat\";\n",
        "src/lib.rs": "pub mod known_hosts;\n",
    }
    clean("A4 clean", check_keys_call_sites(keys_files, {COMPAT}))
    bad_call = dict(keys_files)
    bad_call["src/trust.rs"] += "fn g() { let _ = tatami_ssh_openssh_compat::matches_hashed_hostname(b\"\", b\"\"); }\n"
    expect("A4 forbidden call site", check_keys_call_sites(bad_call, {COMPAT}),
           "src/trust.rs:3: references `tatami_ssh_openssh_compat`")
    aliased = dict(keys_files)
    aliased["src/blob.rs"] = "use legacy_compat::matches_hashed_hostname as m;\n"
    expect("A4 renamed call site", check_keys_call_sites(aliased, {COMPAT, "legacy_compat"}),
           "src/blob.rs:1: references `legacy_compat`")
    reexp = dict(keys_files)
    reexp["src/known_hosts.rs"] += "pub use tatami_ssh_openssh_compat::matches_hashed_hostname;\n"
    expect("A4 re-export", check_keys_call_sites(reexp, {COMPAT}), "re-exports the compatibility crate")
    build = dict(keys_files)
    build["build.rs"] = "extern crate tatami_ssh_openssh_compat;\n"
    expect("A4 build script", check_keys_call_sites(build, {COMPAT}), "build.rs:1")

    if failures:
        for f in failures:
            print(f"check-sha1-boundary self-test FAILED: {f}", file=sys.stderr)
        return 1
    print("check-sha1-boundary self-test: every forbidden fixture reported; clean fixtures pass")
    return 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    if argv:
        print(__doc__, file=sys.stderr)
        return 2
    violations = run_checks()
    if violations:
        for v in violations:
            print(f"error: {v}", file=sys.stderr)
        return 1
    print("check-sha1-boundary: SHA-1 boundary holds")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
