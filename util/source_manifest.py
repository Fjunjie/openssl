#!/usr/bin/env python3
"""Create and check reproducible SHA-256 manifests for a source tree.

The tool uses only the Python standard library. It never follows directory
links, and it reports changes without changing files in the source tree.
"""

import argparse
import fnmatch
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath


SCHEMA_VERSION = 1
READ_SIZE = 1024 * 1024
VALID_TYPES = {"file", "symlink"}
HEX_DIGITS = set("0123456789abcdef")


class ManifestError(Exception):
    """An invalid manifest, unsafe path, or unreadable source tree."""


def relative_name(root, path):
    """Return a stable, slash-separated name for a path under root."""
    try:
        name = path.relative_to(root).as_posix()
    except ValueError:
        raise ManifestError("path is outside source root: {}".format(path))
    if name in ("", "."):
        raise ManifestError("a manifest entry cannot name the source root")
    return name


def check_name(name):
    """Reject absolute, ambiguous, or Git metadata paths."""
    if not isinstance(name, str) or not name:
        raise ManifestError("entry path must be a nonempty string")
    if "\\" in name or "\x00" in name:
        raise ManifestError("entry path uses an invalid separator")
    parts = PurePosixPath(name).parts
    if (
        name.startswith("/")
        or len(parts) == 0
        or any(part in ("", ".", "..") for part in name.split("/"))
        or parts[0] == ".git"
        or ":" in parts[0]
    ):
        raise ManifestError("unsafe entry path: {}".format(name))
    if PurePosixPath(name).as_posix() != name:
        raise ManifestError("noncanonical entry path: {}".format(name))
    return name


def check_target(name, target):
    """Check that a link resolves to a path within the source root."""
    if not isinstance(target, str) or not target or "\x00" in target:
        raise ManifestError("invalid link target for {}".format(name))
    if "\\" in target or target.startswith("/") or ":" in target.split("/")[0]:
        raise ManifestError("absolute link target for {}".format(name))
    stack = list(PurePosixPath(name).parts[:-1])
    for part in target.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                raise ManifestError("link leaves source root: {}".format(name))
            stack.pop()
        else:
            stack.append(part)
    return target


def matches(name, patterns):
    """Match a path or one of its directories against exclude globs."""
    parts = name.split("/")
    prefixes = ["/".join(parts[:index]) for index in range(1, len(parts) + 1)]
    return any(
        fnmatch.fnmatchcase(prefix, pattern)
        for prefix in prefixes
        for pattern in patterns
    )


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            block = source.read(READ_SIZE)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def file_entry(root, path):
    """Build one entry, checking for a replacement during the read."""
    name = check_name(relative_name(root, path))
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode):
        target = os.readlink(str(path)).replace("\\", "/")
        check_target(name, target)
        after = path.lstat()
        if before.st_mtime_ns != after.st_mtime_ns:
            raise ManifestError("link changed while scanning: {}".format(name))
        return {"path": name, "type": "symlink", "target": target}
    if not stat.S_ISREG(before.st_mode):
        raise ManifestError("unsupported file type: {}".format(name))
    digest = sha256_file(path)
    after = path.lstat()
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ino != after.st_ino
    ):
        raise ManifestError("file changed while scanning: {}".format(name))
    return {
        "path": name,
        "type": "file",
        "size": before.st_size,
        "sha256": digest,
        "executable": bool(before.st_mode & 0o111),
    }


def scan(root, patterns=(), omit=()):
    """Walk a tree without following symlinks and return sorted entries."""
    root = Path(root).resolve()
    if not root.is_dir():
        raise ManifestError("source root is not a directory: {}".format(root))
    omitted = {Path(path).absolute() for path in omit}
    entries = []

    def walk_error(error):
        raise ManifestError("cannot scan source tree: {}".format(error))

    for directory, dirs, files in os.walk(
        str(root), topdown=True, followlinks=False, onerror=walk_error
    ):
        parent = Path(directory)
        if parent != root:
            name = relative_name(root, parent)
            if matches(name, patterns):
                dirs[:] = []
                continue
        retained = []
        for directory_name in sorted(dirs):
            path = parent / directory_name
            name = relative_name(root, path)
            if directory_name == ".git" or matches(name, patterns):
                continue
            if path.is_symlink():
                entries.append(file_entry(root, path))
            else:
                retained.append(directory_name)
        dirs[:] = retained
        for file_name in sorted(files):
            path = parent / file_name
            name = relative_name(root, path)
            if path.absolute() in omitted or matches(name, patterns):
                continue
            entries.append(file_entry(root, path))
    entries.sort(key=lambda entry: entry["path"])
    return entries


def validate_entry(entry):
    if not isinstance(entry, dict):
        raise ManifestError("entry must be an object")
    name = check_name(entry.get("path"))
    kind = entry.get("type")
    if not isinstance(kind, str) or kind not in VALID_TYPES:
        raise ManifestError("invalid entry type for {}".format(name))
    if kind == "symlink":
        if set(entry) != {"path", "type", "target"}:
            raise ManifestError("invalid link fields for {}".format(name))
        check_target(name, entry["target"])
    else:
        if set(entry) != {"path", "type", "size", "sha256", "executable"}:
            raise ManifestError("invalid file fields for {}".format(name))
        size = entry["size"]
        digest = entry["sha256"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ManifestError("invalid file size for {}".format(name))
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or not set(digest) <= HEX_DIGITS
        ):
            raise ManifestError("invalid SHA-256 digest for {}".format(name))
        if not isinstance(entry["executable"], bool):
            raise ManifestError("invalid executable flag for {}".format(name))
    return name


def validate_manifest(document):
    if not isinstance(document, dict):
        raise ManifestError("manifest must be an object")
    if set(document) != {"schema", "algorithm", "entries"}:
        raise ManifestError("manifest has unexpected fields")
    if (
        type(document["schema"]) is not int
        or document["schema"] != SCHEMA_VERSION
        or document["algorithm"] != "sha256"
    ):
        raise ManifestError("unsupported manifest schema or algorithm")
    entries = document["entries"]
    if not isinstance(entries, list):
        raise ManifestError("entries must be a list")
    previous = None
    for entry in entries:
        name = validate_entry(entry)
        if previous is not None and name <= previous:
            raise ManifestError("entries are unsorted or duplicated at {}".format(name))
        previous = name
    return document


def make_manifest(entries):
    return validate_manifest({
        "schema": SCHEMA_VERSION,
        "algorithm": "sha256",
        "entries": entries,
    })


def read_manifest(path):
    try:
        with Path(path).open("r", encoding="utf-8") as source:
            document = json.load(source)
    except (OSError, UnicodeError, ValueError) as error:
        raise ManifestError("cannot read manifest {}: {}".format(path, error))
    return validate_manifest(document)


def write_manifest(path, document):
    """Atomically replace a manifest so failed writes leave the old one."""
    path = Path(path)
    if not path.parent.is_dir():
        raise ManifestError("output directory does not exist: {}".format(path.parent))
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", newline="\n", dir=str(path.parent),
            prefix=".source-manifest-", suffix=".tmp", delete=False
        ) as output:
            temporary = Path(output.name)
            json.dump(document, output, indent=2, ensure_ascii=False)
            output.write("\n")
        os.replace(str(temporary), str(path))
    except OSError as error:
        raise ManifestError("cannot write manifest {}: {}".format(path, error))
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def compare(expected, actual):
    """Return added, removed, and changed paths in stable order."""
    left = {entry["path"]: entry for entry in expected["entries"]}
    right = {entry["path"]: entry for entry in actual["entries"]}
    return {
        "added": sorted(right.keys() - left.keys()),
        "removed": sorted(left.keys() - right.keys()),
        "changed": sorted(
            name for name in left.keys() & right.keys() if left[name] != right[name]
        ),
    }


def print_changes(changes, output):
    for category in ("added", "removed", "changed"):
        for name in changes[category]:
            output.write("{}\t{}\n".format(category, name))
    output.write(
        "Summary: {} added, {} removed, {} changed\n".format(
            len(changes["added"]), len(changes["removed"]), len(changes["changed"])
        )
    )


def have_changes(changes):
    return any(changes[category] for category in ("added", "removed", "changed"))


def summarize(document):
    """Count source files and bytes by extension and top-level directory."""
    validate_manifest(document)
    result = {
        "files": 0,
        "symlinks": 0,
        "bytes": 0,
        "extensions": {},
        "directories": {},
    }
    for entry in document["entries"]:
        if entry["type"] == "symlink":
            result["symlinks"] += 1
            continue
        result["files"] += 1
        size = entry["size"]
        result["bytes"] += size
        extension = PurePosixPath(entry["path"]).suffix.lower() or "(none)"
        parts = entry["path"].split("/")
        directory = parts[0] if len(parts) > 1 else "(root)"
        for key, group in (("extensions", extension), ("directories", directory)):
            row = result[key].setdefault(group, {"files": 0, "bytes": 0})
            row["files"] += 1
            row["bytes"] += size
    return result


def command_create(args):
    output = Path(args.output).absolute()
    entries = scan(args.root, args.exclude, omit=(output,))
    document = make_manifest(entries)
    write_manifest(output, document)
    print("Wrote {} entries to {}".format(len(entries), output))
    return 0


def command_verify(args):
    source = Path(args.manifest).absolute()
    expected = read_manifest(source)
    actual = make_manifest(scan(args.root, args.exclude, omit=(source,)))
    changes = compare(expected, actual)
    print_changes(changes, sys.stdout)
    return 1 if have_changes(changes) else 0


def command_diff(args):
    expected = read_manifest(args.before)
    actual = read_manifest(args.after)
    changes = compare(expected, actual)
    print_changes(changes, sys.stdout)
    return 1 if args.fail_on_change and have_changes(changes) else 0


def command_stats(args):
    summary = summarize(read_manifest(args.manifest))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        description="Create, verify, and compare SHA-256 source tree manifests."
    )
    subcommands = parser.add_subparsers(dest="command")
    subcommands.required = True

    create = subcommands.add_parser("create", help="write a new manifest")
    create.add_argument("root", help="source directory to scan")
    create.add_argument("output", help="JSON manifest path")
    create.add_argument(
        "--exclude", action="append", default=[], metavar="GLOB",
        help="exclude a path or directory with a slash-separated glob"
    )
    create.set_defaults(run=command_create)

    verify = subcommands.add_parser("verify", help="compare a tree with a manifest")
    verify.add_argument("root", help="source directory to scan")
    verify.add_argument("manifest", help="JSON manifest to check")
    verify.add_argument(
        "--exclude", action="append", default=[], metavar="GLOB",
        help="use the same exclusions as create"
    )
    verify.set_defaults(run=command_verify)

    difference = subcommands.add_parser("diff", help="compare two manifests")
    difference.add_argument("before", help="first manifest")
    difference.add_argument("after", help="second manifest")
    difference.add_argument(
        "--fail-on-change", action="store_true",
        help="return status 1 when the manifests differ"
    )
    difference.set_defaults(run=command_diff)

    statistics = subcommands.add_parser("stats", help="summarize a manifest")
    statistics.add_argument("manifest", help="JSON manifest to summarize")
    statistics.set_defaults(run=command_stats)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.run(args)
    except (ManifestError, OSError) as error:
        print("source_manifest: {}".format(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
