# Source tree manifests

source_manifest.py is an optional Python 3 utility for recording the contents
of a source tree. It uses only the Python standard library and does not affect
the OpenSSL build. Its output is a sorted JSON file with SHA-256 hashes for
regular files and targets for symbolic links.

## Quick start

From the repository root:

    python util/source_manifest.py create . source-manifest.json
    python util/source_manifest.py verify . source-manifest.json
    python util/source_manifest.py stats source-manifest.json

The manifest itself is omitted when it is saved under the scanned root.
Git metadata directories are always omitted. To omit generated files, pass
one or more exclusions:

    python util/source_manifest.py create . source-manifest.json \
      --exclude build --exclude "*.o" --exclude "__pycache__"

Use the same exclusions when verifying:

    python util/source_manifest.py verify . source-manifest.json \
      --exclude build --exclude "*.o" --exclude "__pycache__"

Each exclusion is matched against slash-separated relative paths and their
parent directories. A pattern such as build omits the top-level build
directory and its contents. A pattern such as "*.o" omits matching object
files at any depth. To omit nested cache directories, use
"*/__pycache__" as well as "__pycache__". Exclusions are supplied on the
command line and are not embedded in the manifest.

## Compare two snapshots

Create two manifests from different source trees or revisions:

    python util/source_manifest.py create old-tree old.json
    python util/source_manifest.py create new-tree new.json
    python util/source_manifest.py diff old.json new.json

The diff command prints added, removed, and changed paths. It returns zero
even if changes are found, which is useful for interactive inspection. Use
--fail-on-change to make a change produce exit status 1:

    python util/source_manifest.py diff old.json new.json --fail-on-change

## Format

The manifest has schema version 1 and names SHA-256 as its hash algorithm:

    {
      "schema": 1,
      "algorithm": "sha256",
      "entries": [
        {
          "path": "README",
          "type": "file",
          "size": 42,
          "sha256": "64 lowercase hexadecimal digits",
          "executable": false
        },
        {
          "path": "apps/alias.c",
          "type": "symlink",
          "target": "../crypto/source.c"
        }
      ]
    }

Entries are sorted by path and paths use forward slashes. The tool rejects
duplicate or unsafe paths when reading a manifest. It does not follow
symbolic links; a link target must stay within the source root. A file's
executable flag comes from the filesystem where the manifest was created.

The stats command prints JSON totals for regular files, symbolic links, and
bytes. It also groups regular files by extension and top-level directory.
Symbolic links do not add to the byte count.

## Exit codes

| Status | Meaning |
| --- | --- |
| 0 | Command succeeded; no differences for verify |
| 1 | Differences found by verify, or by diff with --fail-on-change |
| 2 | Invalid manifest, unreadable tree, or write error |

Argument parsing errors use Python's usual exit status 2.

## Platform notes

Windows Git checkouts may materialize symbolic links as ordinary text files
when symlink support is disabled. In that case the manifest records what is
actually present in the checkout. Executable bits may also differ between
filesystems. Generate and verify a manifest on the same kind of checkout
when these details matter.

The utility reads file data in chunks and checks file size and modification
time after hashing. Those checks detect common concurrent edits. For a
stable snapshot, scan a checkout that is not being modified.

## Tests

Run the standalone tests without configuring or building OpenSSL:

    python -m unittest discover -s test -p test_source_manifest.py

The symbolic-link tests skip on Windows accounts that cannot create links.
