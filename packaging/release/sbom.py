#!/usr/bin/env python3
"""Generate and validate an SPDX 2.3 SBOM for the seagent workspace.

Why this exists: `deny.toml` proves that the *set* of dependencies is acceptable at build time,
but a release needs a machine-readable inventory that ships next to the artifacts. A user who
downloads `seagent` should be able to answer "which crate at which version, under which license, with
which checksum?" without this git checkout and without a network connection.

Design decisions, and the reason behind each:

* **stdlib only, no network.** The release engineer must be able to run this on an air-gapped
  or freshly provisioned machine. `urllib` is not even imported.
* **`Cargo.lock` is the source of truth** for the package set, versions, checksums and dependency
  edges; `cargo metadata` only enriches licenses and tells us which crates are workspace members.
  That keeps the script working on a machine without cargo (it then emits `NOASSERTION` for the
  licenses it cannot see) instead of failing the release.
* **Deterministic output.** Packages and relationships are sorted, `creationInfo.created` comes
  from `SOURCE_DATE_EPOCH` (default: the Unix epoch, never "now"), the document namespace is
  derived from a hash of the package list, and no hostname, username or absolute path is written.
  Two runs on two machines must produce byte-identical files, otherwise the release `SHA256SUMS`
  is not reproducible.
* **One SPDX package per crate**, not per file: `filesAnalyzed` is false and the document
  describes the dependency graph, which is what a supply-chain reviewer actually reads.

Usage:
    sbom.py [--out FILE] [--check] [--root DIR]

    --out FILE   write the document to FILE ("-" for stdout; default stdout)
    --check      validate a document: an existing file at --out/-, else the freshly built one
    --root DIR   workspace root (default: two directories above this script)
    --help       show this help

Exit status: 0 = ok, 1 = document invalid, 2 = usage error.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time

SPDX_VERSION = "SPDX-2.3"
DATA_LICENSE = "CC0-1.0"
DOCUMENT_ID = "SPDXRef-DOCUMENT"
NOASSERTION = "NOASSERTION"
CREATOR = "Tool: seagent-sbom-1.0"
CRATES_IO_DOWNLOAD = "https://crates.io/api/v1/crates/{name}/{version}/download"

# Crate names/versions are already tame, but a version may carry build metadata (`1.0.0+abc`) and
# an SPDX identifier may only use [A-Za-z0-9.-]. Sanitising keeps the id stable and legal.
_ID_UNSAFE = re.compile(r"[^A-Za-z0-9.\-]+")


def sanitize(text):
    """Make `text` usable inside an SPDX identifier."""
    return _ID_UNSAFE.sub("-", str(text)).strip("-") or "unknown"


def default_root():
    """`<repo>/packaging/release/sbom.py` -> `<repo>`."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(os.path.dirname(here))


# --------------------------------------------------------------------------------------------
# Inputs: Cargo.lock (always) and cargo metadata (when cargo is installed)
# --------------------------------------------------------------------------------------------

def cargo_metadata(root, no_deps):
    """Run `cargo metadata` and return the parsed JSON, or None if cargo cannot answer.

    Failures are expected and non-fatal (no cargo, no registry cache, `--offline` with an
    unclean lockfile): the lockfile parser covers every field the document strictly needs.
    """
    cmd = ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"]
    if no_deps:
        cmd.append("--no-deps")
    try:
        proc = subprocess.run(
            cmd,
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=180,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    try:
        return json.loads(proc.stdout.decode("utf-8", "replace"))
    except ValueError:
        return None


def _unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return value


def parse_lockfile(path):
    """Parse the subset of TOML that Cargo writes: `[[package]]` tables with 4 scalar keys and
    one (possibly multi-line) string array.

    Hand-written on purpose: `tomllib` only exists from Python 3.11, and a release script that
    refuses to start on the LTS distro of the day is worse than 40 lines of parsing.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise SystemExit("sbom: cannot read %s: %s" % (path, exc))

    packages = []
    current = None
    in_deps = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[[package]]":
            current = {
                "name": None,
                "version": None,
                "source": None,
                "checksum": None,
                "dependencies": [],
            }
            packages.append(current)
            in_deps = False
            continue
        if current is None:
            continue  # the `version = 4` header, before the first package
        if in_deps:
            if line == "]":
                in_deps = False
                continue
            current["dependencies"].append(_unquote(line.rstrip(",")))
            continue
        if line.startswith("dependencies = ["):
            in_deps = True
            rest = line[len("dependencies = ["):].strip()
            if rest == "]":
                in_deps = False
            elif rest:
                current["dependencies"].append(_unquote(rest.rstrip(",")))
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        if key in ("name", "version", "source", "checksum"):
            current[key] = _unquote(value)

    return [p for p in packages if p["name"] and p["version"]]


def metadata_licenses(metas):
    """(name, version) -> license expression, from every metadata blob we managed to get."""
    licenses = {}
    for meta in metas:
        if not meta:
            continue
        for pkg in meta.get("packages") or []:
            license_id = pkg.get("license") or NOASSERTION
            licenses.setdefault((pkg["name"], pkg["version"]), license_id)
    return licenses


def metadata_members(meta):
    """Workspace member (name, version) pairs, or None when metadata is unavailable."""
    if not meta:
        return None
    wanted = set(meta.get("workspace_members") or [])
    members = set()
    for pkg in meta.get("packages") or []:
        if pkg.get("id") in wanted:
            members.add((pkg["name"], pkg["version"]))
    return members or None


# --------------------------------------------------------------------------------------------
# Document construction
# --------------------------------------------------------------------------------------------

def _download_location(pkg):
    source = pkg.get("source")
    if not source:
        # A path dependency: it ships inside this document, there is nothing to download.
        return NOASSERTION
    if source.startswith("registry+") or "crates.io" in source:
        return CRATES_IO_DOWNLOAD.format(name=pkg["name"], version=pkg["version"])
    if source.startswith("git+"):
        return source[len("git+"):]
    return NOASSERTION


_DEP_SPEC = re.compile(r"^([A-Za-z0-9_.\-]+)(?:\s+([^\s(]+))?(?:\s+\((.+)\))?$")


def _resolve_dep(spec, by_name):
    """Resolve one `Cargo.lock` dependency string ("name", "name 1.2.3" or "name 1.2.3 (src)")
    to a package entry. Cargo writes the version whenever the name is ambiguous."""
    match = _DEP_SPEC.match(spec.strip())
    if not match:
        return None
    name, version, source = match.groups()
    candidates = by_name.get(name, [])
    if version:
        candidates = [p for p in candidates if p["version"] == version]
    if source:
        candidates = [p for p in candidates if p["source"] == source]
    return candidates[0] if candidates else None


def _created_timestamp():
    """`SOURCE_DATE_EPOCH` when set, else 0. Never the wall clock: the document is an artifact
    that has to hash the same on every rebuild."""
    raw = os.environ.get("SOURCE_DATE_EPOCH", "0").strip() or "0"
    try:
        epoch = int(raw)
    except ValueError:
        raise SystemExit("sbom: SOURCE_DATE_EPOCH must be an integer, got %r" % raw)
    if epoch < 0:
        raise SystemExit("sbom: SOURCE_DATE_EPOCH must not be negative")
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def build_document(root):
    """Build the SPDX document for the workspace at `root`."""
    lock_path = os.path.join(root, "Cargo.lock")
    locked = parse_lockfile(lock_path)

    member_meta = cargo_metadata(root, no_deps=True)
    full_meta = cargo_metadata(root, no_deps=False)
    licenses = metadata_licenses([member_meta, full_meta])

    members = metadata_members(member_meta)
    if members is None:
        # No cargo: the lockfile still marks workspace crates by their missing `source`.
        members = {(p["name"], p["version"]) for p in locked if not p.get("source")}
    if not members:
        raise SystemExit("sbom: no workspace crates found in %s" % lock_path)

    # Deterministic order, and a stable dedup key: the same crate cannot appear twice in a lock.
    locked.sort(key=lambda p: (p["name"], p["version"], p.get("source") or ""))
    by_name = {}
    for pkg in locked:
        by_name.setdefault(pkg["name"], []).append(pkg)

    # `seagent` is the binary crate this release ships; everything else in the workspace is a library
    # it links. Falling back to the alphabetically first member keeps the document valid for a
    # renamed or hypothetical workspace instead of crashing.
    root_key = ("seagent", None) if any(n == "seagent" for n, _ in members) else sorted(members)[0]
    root_pkg = _resolve_dep(root_key[0], by_name)
    if root_pkg is None:
        raise SystemExit("sbom: root crate %r missing from Cargo.lock" % (root_key[0],))
    root_id = "SPDXRef-Package-%s-%s" % (sanitize(root_pkg["name"]), sanitize(root_pkg["version"]))

    entries = []
    ids = {}
    for pkg in locked:
        spdx_id = "SPDXRef-Package-%s-%s" % (sanitize(pkg["name"]), sanitize(pkg["version"]))
        if spdx_id in ids:  # two sources, same name+version (a git fork next to the registry one)
            spdx_id = "%s-%d" % (spdx_id, len([i for i in ids if i.startswith(spdx_id)]))
        ids[spdx_id] = pkg

        license_id = licenses.get((pkg["name"], pkg["version"]), NOASSERTION)
        refs = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": "pkg:cargo/%s@%s" % (pkg["name"], pkg["version"]),
            }
        ]
        entry = {
            "name": pkg["name"],
            "SPDXID": spdx_id,
            "versionInfo": pkg["version"],
            "downloadLocation": _download_location(pkg),
            "filesAnalyzed": False,
            "licenseConcluded": license_id,
            "licenseDeclared": license_id,
            "copyrightText": NOASSERTION,
            "externalRefs": refs,
        }
        if (pkg.get("source") or "").startswith("registry+") and pkg.get("checksum"):
            # `checksums` is the proper SPDX slot; the externalRef mirrors it for tooling that
            # only reads the reference list.
            entry["checksums"] = [{"algorithm": "SHA256", "checksumValue": pkg["checksum"]}]
            refs.append(
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "checksum",
                    "referenceLocator": "sha256:" + pkg["checksum"],
                }
            )
        entries.append(entry)

    entries.sort(key=lambda e: e["SPDXID"])

    relationships = [
        {
            "spdxElementId": DOCUMENT_ID,
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        }
    ]
    for pkg in locked:
        if (pkg["name"], pkg["version"]) not in members:
            continue
        source_id = "SPDXRef-Package-%s-%s" % (sanitize(pkg["name"]), sanitize(pkg["version"]))
        seen = set()
        for spec in pkg["dependencies"]:
            dep = _resolve_dep(spec, by_name)
            if dep is None:
                continue
            target = "SPDXRef-Package-%s-%s" % (sanitize(dep["name"]), sanitize(dep["version"]))
            if target == source_id or target in seen or target not in {e["SPDXID"] for e in entries}:
                continue
            seen.add(target)
            relationships.append(
                {
                    "spdxElementId": source_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": target,
                }
            )
    relationships.sort(
        key=lambda r: (r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"])
    )

    digest = hashlib.sha256(
        "\n".join(sorted("%s@%s" % (p["name"], p["version"]) for p in locked)).encode("utf-8")
    ).hexdigest()[:16]

    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": DOCUMENT_ID,
        "name": "seagent-%s" % root_pkg["version"],
        "documentNamespace": "https://spdx.org/spdxdocs/seagent-%s-%s"
        % (sanitize(root_pkg["version"]), digest),
        "creationInfo": {"created": _created_timestamp(), "creators": [CREATOR]},
        "packages": entries,
        "relationships": relationships,
    }


def render(document):
    """Serialise deterministically: sorted keys, two-space indent, trailing newline."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------------------------
# Validation (`--check`)
# --------------------------------------------------------------------------------------------

def validate(document):
    """Return a list of human-readable problems; empty means the document is usable."""
    errors = []
    if document.get("spdxVersion") != SPDX_VERSION:
        errors.append("spdxVersion must be %r, got %r"
                      % (SPDX_VERSION, document.get("spdxVersion")))
    if document.get("SPDXID") != DOCUMENT_ID:
        errors.append("SPDXID must be %r, got %r" % (DOCUMENT_ID, document.get("SPDXID")))
    if document.get("dataLicense") != DATA_LICENSE:
        errors.append("dataLicense must be %r, got %r" % (DATA_LICENSE, document.get("dataLicense")))
    created = (document.get("creationInfo") or {}).get("created")
    if not isinstance(created, str) or not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", created):
        errors.append("creationInfo.created must be an RFC 3339 UTC timestamp, got %r" % (created,))

    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        errors.append("packages must be a non-empty list")
        packages = []

    by_id = {}
    for index, pkg in enumerate(packages):
        if not isinstance(pkg, dict):
            errors.append("packages[%d] is not an object" % index)
            continue
        spdx_id = pkg.get("SPDXID")
        if not isinstance(spdx_id, str) or not spdx_id.startswith("SPDXRef-"):
            errors.append("packages[%d].SPDXID is not an SPDXRef- identifier: %r" % (index, spdx_id))
            continue
        if spdx_id in by_id:
            errors.append("duplicate SPDXID %s" % spdx_id)
        if spdx_id == DOCUMENT_ID:
            errors.append("%s is the document id and cannot also name a package" % DOCUMENT_ID)
        by_id[spdx_id] = pkg
        for field in ("name", "versionInfo", "downloadLocation", "licenseDeclared",
                      "licenseConcluded"):
            value = pkg.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append("%s: missing or empty %s" % (spdx_id, field))
        refs = pkg.get("externalRefs") or []
        # The purl is what makes the entry actionable for a consumer ("where do I get this?").
        if not any(r.get("referenceType") == "purl" for r in refs if isinstance(r, dict)):
            errors.append("%s: no purl externalRef" % spdx_id)

    relationships = document.get("relationships") or []
    describes = 0
    for index, rel in enumerate(relationships):
        if not isinstance(rel, dict):
            errors.append("relationships[%d] is not an object" % index)
            continue
        kind = rel.get("relationshipType")
        source = rel.get("spdxElementId")
        target = rel.get("relatedSpdxElement")
        if kind not in ("DESCRIBES", "DEPENDS_ON"):
            errors.append("relationships[%d]: unexpected relationshipType %r" % (index, kind))
            continue
        if kind == "DESCRIBES":
            describes += 1
            if source != DOCUMENT_ID:
                errors.append("relationships[%d]: DESCRIBES must start at %s" % (index, DOCUMENT_ID))
        elif source not in by_id:
            errors.append("relationships[%d]: %s references unknown package %r"
                          % (index, kind, source))
        if target not in by_id:
            errors.append("relationships[%d]: %s references unknown package %r"
                          % (index, kind, target))
    if not describes:
        errors.append("no DESCRIBES relationship: the document does not say what it describes")
    return errors


def _load_document(path):
    try:
        if path == "-":
            text = sys.stdin.read()
        else:
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read()
    except OSError as exc:
        raise SystemExit("sbom: cannot read %s: %s" % (path, exc))
    try:
        return json.loads(text)
    except ValueError as exc:
        raise SystemExit("sbom: %s is not valid JSON: %s" % (path, exc))


# --------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------

def main(argv):
    parser = argparse.ArgumentParser(
        prog="sbom.py",
        description="Generate or validate the SPDX 2.3 SBOM for the seagent workspace.",
        epilog="Exit status: 0 = ok, 1 = document invalid, 2 = usage error.",
    )
    parser.add_argument("--out", metavar="FILE", default="-",
                        help="write to FILE ('-' = stdout, the default)")
    parser.add_argument("--check", action="store_true",
                        help="validate the document at --out, or build and validate a fresh one "
                             "when --out is '-' (the default)")
    parser.add_argument("--root", metavar="DIR", default=None,
                        help="workspace root (default: two levels above this script)")
    args = parser.parse_args(argv)

    root = args.root or default_root()
    # Checking a *downloaded* document must not require the workspace: `verify-release.sh` runs
    # `--check` on an unpacked dist directory on a machine that has no seagent checkout at all.
    if args.check and args.out != "-":
        document = _load_document(args.out)
    else:
        if not os.path.isfile(os.path.join(root, "Cargo.lock")):
            raise SystemExit("sbom: %s does not look like the seagent workspace (no Cargo.lock)" % root)
        document = build_document(root)

    if args.check:
        errors = validate(document)
        if errors:
            label = "the document" if args.out == "-" else args.out
            print("sbom --check: FAIL (%s)" % label, file=sys.stderr)
            for error in errors:
                print("  - %s" % error, file=sys.stderr)
            return 1
        print("sbom --check: OK (%s, %d packages, %d relationships)"
              % ("built in memory" if args.out == "-" else args.out,
                 len(document.get("packages") or []),
                 len(document.get("relationships") or [])))
        return 0

    document = build_document(root)
    text = render(document)
    if args.out == "-":
        sys.stdout.write(text)
        return 0
    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(text)
    print("sbom: wrote %s (%d packages, %d relationships)"
          % (args.out, len(document["packages"]), len(document["relationships"])), file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except BrokenPipeError:
        sys.exit(0)
