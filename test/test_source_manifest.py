"""Behavior tests for the optional source manifest utility.

Run with: python -m unittest discover -s test -p test_source_manifest.py
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


TOOL = Path(__file__).resolve().parents[1] / "util" / "source_manifest.py"
sys.path.insert(0, str(TOOL.parent))
import source_manifest as manifest  # noqa: E402


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_record(name, data=b"data", executable=False):
    return {
        "path": name,
        "type": "file",
        "size": len(data),
        "sha256": digest(data),
        "executable": executable,
    }


def link_record(name, target):
    return {"path": name, "type": "symlink", "target": target}


def document(*entries):
    return {
        "schema": 1,
        "algorithm": "sha256",
        "entries": list(entries),
    }


class TemporaryTree(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="source-manifest-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def put(self, name, data=b"data"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def run_tool(self, *args):
        return subprocess.run(
            [sys.executable, str(TOOL), *map(str, args)],
            cwd=str(self.root), capture_output=True, text=True
        )


class PathValidationTests(unittest.TestCase):
    def test_accepts_nested_relative_path(self):
        self.assertEqual(manifest.check_name("crypto/aes/aes.c"), "crypto/aes/aes.c")

    def test_rejects_empty_path(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.check_name("")

    def test_rejects_non_string_path(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.check_name(23)

    def test_rejects_absolute_path(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.check_name("/etc/passwd")

    def test_rejects_drive_path(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.check_name("C:/Windows/system.ini")

    def test_rejects_parent_traversal(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.check_name("crypto/../secret")

    def test_rejects_current_directory(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.check_name("crypto/./aes.c")

    def test_rejects_double_separator(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.check_name("crypto//aes.c")

    def test_rejects_backslash(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.check_name("crypto\\aes.c")

    def test_rejects_git_metadata(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.check_name(".git/config")

    def test_rejects_nul(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.check_name("crypto/\x00.c")

    def test_accepts_link_with_parent_reference_inside_tree(self):
        self.assertEqual(
            manifest.check_target("apps/md4.c", "../crypto/md4/md4.c"),
            "../crypto/md4/md4.c"
        )

    def test_rejects_link_escaping_tree(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.check_target("apps/md4.c", "../../outside")

    def test_rejects_absolute_link(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.check_target("apps/md4.c", "/tmp/key")

    def test_rejects_drive_link(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.check_target("apps/md4.c", "C:/key")

    def test_rejects_empty_link(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.check_target("apps/md4.c", "")


class ManifestValidationTests(unittest.TestCase):
    def test_accepts_empty_document(self):
        self.assertEqual(manifest.validate_manifest(document()), document())

    def test_accepts_sorted_mixed_entries(self):
        value = document(file_record("a"), link_record("b", "a"))
        self.assertEqual(manifest.validate_manifest(value), value)

    def test_rejects_non_object_document(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_manifest([])

    def test_rejects_unknown_document_field(self):
        value = document()
        value["extra"] = True
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_manifest(value)

    def test_rejects_wrong_schema(self):
        value = document()
        value["schema"] = 2
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_manifest(value)

    def test_rejects_boolean_schema(self):
        value = document()
        value["schema"] = True
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_manifest(value)

    def test_rejects_wrong_algorithm(self):
        value = document()
        value["algorithm"] = "md5"
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_manifest(value)

    def test_rejects_non_list_entries(self):
        value = document()
        value["entries"] = {}
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_manifest(value)

    def test_rejects_unsorted_entries(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_manifest(document(file_record("b"), file_record("a")))

    def test_rejects_duplicate_entries(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_manifest(document(file_record("a"), file_record("a")))

    def test_rejects_extra_file_field(self):
        entry = file_record("a")
        entry["unknown"] = 1
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_entry(entry)

    def test_rejects_non_string_type(self):
        entry = file_record("a")
        entry["type"] = []
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_entry(entry)

    def test_rejects_missing_file_field(self):
        entry = file_record("a")
        del entry["sha256"]
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_entry(entry)

    def test_rejects_negative_size(self):
        entry = file_record("a")
        entry["size"] = -1
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_entry(entry)

    def test_rejects_boolean_size(self):
        entry = file_record("a")
        entry["size"] = True
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_entry(entry)

    def test_rejects_short_digest(self):
        entry = file_record("a")
        entry["sha256"] = "abc"
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_entry(entry)

    def test_rejects_uppercase_digest(self):
        entry = file_record("a")
        entry["sha256"] = entry["sha256"].upper()
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_entry(entry)

    def test_rejects_non_boolean_executable(self):
        entry = file_record("a")
        entry["executable"] = 1
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_entry(entry)

    def test_rejects_extra_link_field(self):
        entry = link_record("link", "target")
        entry["size"] = 1
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_entry(entry)

    def test_rejects_invalid_link_target(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_entry(link_record("link", "../outside"))


class ScanTests(TemporaryTree):
    def test_empty_tree(self):
        self.assertEqual(manifest.scan(self.root), [])

    def test_content_hash_and_size(self):
        self.put("a.c", b"\x00\x01\xfe")
        self.assertEqual(manifest.scan(self.root), [file_record("a.c", b"\x00\x01\xfe")])

    def test_sorted_paths(self):
        self.put("z.c")
        self.put("a/second.c")
        self.put("a/first.c")
        self.assertEqual(
            [entry["path"] for entry in manifest.scan(self.root)],
            ["a/first.c", "a/second.c", "z.c"]
        )

    def test_git_directory_is_always_ignored(self):
        self.put(".git/config", b"private")
        self.put("README", b"public")
        self.assertEqual(
            [entry["path"] for entry in manifest.scan(self.root)],
            ["README"]
        )

    def test_nested_git_directory_is_ignored(self):
        self.put("nested/.git/config", b"private")
        self.put("nested/source.c")
        self.assertEqual(
            [entry["path"] for entry in manifest.scan(self.root)],
            ["nested/source.c"]
        )

    def test_exclude_directory(self):
        self.put("build/generated.h")
        self.put("crypto/aes.c")
        entries = manifest.scan(self.root, ("build",))
        self.assertEqual([entry["path"] for entry in entries], ["crypto/aes.c"])

    def test_exclude_glob(self):
        self.put("crypto/a.c")
        self.put("crypto/a.o")
        entries = manifest.scan(self.root, ("*.o",))
        self.assertEqual([entry["path"] for entry in entries], ["crypto/a.c"])

    def test_omit_output_file(self):
        self.put("manifest.json", b"old")
        self.put("source.c")
        entries = manifest.scan(self.root, omit=(self.root / "manifest.json",))
        self.assertEqual([entry["path"] for entry in entries], ["source.c"])

    def test_rejects_missing_root(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.scan(self.root / "missing")

    def test_reports_directory_walk_error(self):
        with mock.patch.object(
            manifest.os, "walk", side_effect=lambda *args, **kwargs:
            kwargs["onerror"](OSError("cannot read directory"))
        ):
            with self.assertRaisesRegex(
                manifest.ManifestError, "cannot scan source tree"
            ):
                manifest.scan(self.root)

    def test_rejects_directory_as_file_entry(self):
        directory = self.root / "directory"
        directory.mkdir()
        with self.assertRaises(manifest.ManifestError):
            manifest.file_entry(self.root, directory)

    def test_rejects_file_changed_during_read(self):
        path = self.put("source.c", b"before")
        original = manifest.sha256_file

        def alter_and_hash(candidate):
            result = original(candidate)
            candidate.write_bytes(b"after!")
            return result

        with mock.patch.object(manifest, "sha256_file", side_effect=alter_and_hash):
            with self.assertRaises(manifest.ManifestError):
                manifest.file_entry(self.root, path)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_records_file_symlink_without_following(self):
        target = self.put("crypto/source.c")
        link = self.root / "crypto" / "alias.c"
        try:
            os.symlink(target.name, link)
        except OSError as error:
            self.skipTest("symlink permission unavailable: {}".format(error))
        entries = manifest.scan(self.root)
        self.assertEqual(entries[0], link_record("crypto/alias.c", "source.c"))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_records_directory_symlink_without_descending(self):
        self.put("crypto/source.c")
        link = self.root / "alias"
        try:
            os.symlink("crypto", link, target_is_directory=True)
        except OSError as error:
            self.skipTest("symlink permission unavailable: {}".format(error))
        entries = manifest.scan(self.root)
        self.assertEqual(
            [entry["path"] for entry in entries],
            ["alias", "crypto/source.c"]
        )
        self.assertEqual(entries[0]["type"], "symlink")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_rejects_escaping_symlink(self):
        link = self.root / "outside"
        try:
            os.symlink("../outside", link)
        except OSError as error:
            self.skipTest("symlink permission unavailable: {}".format(error))
        with self.assertRaises(manifest.ManifestError):
            manifest.scan(self.root)


class ComparisonTests(unittest.TestCase):
    def test_identical_manifests(self):
        value = document(file_record("a"))
        self.assertEqual(
            manifest.compare(value, value),
            {"added": [], "removed": [], "changed": []}
        )

    def test_added_path(self):
        changes = manifest.compare(document(), document(file_record("a")))
        self.assertEqual(changes["added"], ["a"])
        self.assertTrue(manifest.have_changes(changes))

    def test_removed_path(self):
        changes = manifest.compare(document(file_record("a")), document())
        self.assertEqual(changes["removed"], ["a"])

    def test_changed_digest(self):
        changes = manifest.compare(
            document(file_record("a", b"one")),
            document(file_record("a", b"two"))
        )
        self.assertEqual(changes["changed"], ["a"])

    def test_changed_file_type(self):
        changes = manifest.compare(
            document(file_record("a")),
            document(link_record("a", "b"))
        )
        self.assertEqual(changes["changed"], ["a"])

    def test_changed_link_target(self):
        changes = manifest.compare(
            document(link_record("a", "b")),
            document(link_record("a", "c"))
        )
        self.assertEqual(changes["changed"], ["a"])

    def test_changed_executable_flag(self):
        changes = manifest.compare(
            document(file_record("a", executable=False)),
            document(file_record("a", executable=True))
        )
        self.assertEqual(changes["changed"], ["a"])

    def test_reports_each_category_in_sorted_order(self):
        changes = manifest.compare(
            document(file_record("b"), file_record("c"), file_record("d")),
            document(file_record("a"), file_record("c", b"new"), file_record("e"))
        )
        self.assertEqual(changes["added"], ["a", "e"])
        self.assertEqual(changes["removed"], ["b", "d"])
        self.assertEqual(changes["changed"], ["c"])


class StatisticsTests(unittest.TestCase):
    def test_empty_manifest(self):
        self.assertEqual(manifest.summarize(document()), {
            "files": 0, "symlinks": 0, "bytes": 0,
            "extensions": {}, "directories": {}
        })

    def test_counts_regular_files_and_bytes(self):
        result = manifest.summarize(document(
            file_record("a.c", b"one"),
            file_record("b.c", b"four")
        ))
        self.assertEqual(result["files"], 2)
        self.assertEqual(result["bytes"], 7)
        self.assertEqual(result["extensions"][".c"], {"files": 2, "bytes": 7})

    def test_counts_links_separately(self):
        result = manifest.summarize(document(
            file_record("a.c", b"one"),
            link_record("b.c", "a.c")
        ))
        self.assertEqual(result["files"], 1)
        self.assertEqual(result["symlinks"], 1)
        self.assertEqual(result["bytes"], 3)

    def test_groups_root_and_directories(self):
        result = manifest.summarize(document(
            file_record("README", b"a"),
            file_record("crypto/a.c", b"ab"),
            file_record("crypto/nested/b.c", b"abc")
        ))
        self.assertEqual(result["directories"]["(root)"], {"files": 1, "bytes": 1})
        self.assertEqual(result["directories"]["crypto"], {"files": 2, "bytes": 5})

    def test_groups_extensionless_files(self):
        result = manifest.summarize(document(file_record("README", b"abc")))
        self.assertEqual(
            result["extensions"]["(none)"],
            {"files": 1, "bytes": 3}
        )

    def test_normalizes_extension_case(self):
        result = manifest.summarize(document(
            file_record("a.C", b"a"),
            file_record("b.c", b"b")
        ))
        self.assertEqual(result["extensions"][".c"]["files"], 2)

    def test_rejects_invalid_document(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.summarize({"entries": []})


class CommandLineTests(TemporaryTree):
    def test_create_writes_valid_json(self):
        self.put("crypto/aes.c", b"source")
        output = self.root / "manifest.json"
        result = self.run_tool("create", self.root, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            manifest.read_manifest(output)["entries"],
            [file_record("crypto/aes.c", b"source")]
        )

    def test_create_excludes_manifest_itself(self):
        self.put("source.c")
        output = self.root / "manifest.json"
        self.assertEqual(self.run_tool("create", self.root, output).returncode, 0)
        self.assertEqual(self.run_tool("create", self.root, output).returncode, 0)
        self.assertEqual(len(manifest.read_manifest(output)["entries"]), 1)

    def test_create_is_byte_reproducible(self):
        self.put("b.c", b"b")
        self.put("a.c", b"a")
        output = self.root / "manifest.json"
        self.assertEqual(self.run_tool("create", self.root, output).returncode, 0)
        first = output.read_bytes()
        self.assertEqual(self.run_tool("create", self.root, output).returncode, 0)
        self.assertEqual(output.read_bytes(), first)
        self.assertTrue(first.endswith(b"\n"))

    def test_create_excludes_matching_directory(self):
        self.put("build/generated.c")
        self.put("crypto/aes.c")
        output = self.root / "manifest.json"
        result = self.run_tool("create", self.root, output, "--exclude", "build")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            [entry["path"] for entry in manifest.read_manifest(output)["entries"]],
            ["crypto/aes.c"]
        )

    def test_verify_unchanged_tree(self):
        self.put("source.c")
        output = self.root / "manifest.json"
        self.assertEqual(self.run_tool("create", self.root, output).returncode, 0)
        result = self.run_tool("verify", self.root, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0 added, 0 removed, 0 changed", result.stdout)

    def test_verify_added_file(self):
        self.put("source.c")
        output = self.root / "manifest.json"
        self.assertEqual(self.run_tool("create", self.root, output).returncode, 0)
        self.put("extra.c")
        result = self.run_tool("verify", self.root, output)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("added\textra.c", result.stdout)

    def test_verify_removed_file(self):
        source = self.put("source.c")
        output = self.root / "manifest.json"
        self.assertEqual(self.run_tool("create", self.root, output).returncode, 0)
        source.unlink()
        result = self.run_tool("verify", self.root, output)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("removed\tsource.c", result.stdout)

    def test_verify_changed_file(self):
        source = self.put("source.c", b"old")
        output = self.root / "manifest.json"
        self.assertEqual(self.run_tool("create", self.root, output).returncode, 0)
        source.write_bytes(b"new")
        result = self.run_tool("verify", self.root, output)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("changed\tsource.c", result.stdout)

    def test_verify_requires_matching_exclusions(self):
        self.put("source.c")
        self.put("build/output.c")
        output = self.root / "manifest.json"
        result = self.run_tool("create", self.root, output, "--exclude", "build")
        self.assertEqual(result.returncode, 0, result.stderr)
        same = self.run_tool("verify", self.root, output, "--exclude", "build")
        self.assertEqual(same.returncode, 0, same.stderr)
        different = self.run_tool("verify", self.root, output)
        self.assertEqual(different.returncode, 1)
        self.assertIn("added\tbuild/output.c", different.stdout)

    def test_diff_reports_changes_but_succeeds_by_default(self):
        before = self.root / "before.json"
        after = self.root / "after.json"
        manifest.write_manifest(before, document(file_record("a", b"old")))
        manifest.write_manifest(after, document(file_record("a", b"new")))
        result = self.run_tool("diff", before, after)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("changed\ta", result.stdout)

    def test_diff_can_fail_on_change(self):
        before = self.root / "before.json"
        after = self.root / "after.json"
        manifest.write_manifest(before, document())
        manifest.write_manifest(after, document(file_record("a")))
        result = self.run_tool("diff", before, after, "--fail-on-change")
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_diff_identical_with_fail_flag(self):
        before = self.root / "before.json"
        manifest.write_manifest(before, document(file_record("a")))
        result = self.run_tool("diff", before, before, "--fail-on-change")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_stats_prints_json_summary(self):
        self.put("README", b"about")
        self.put("crypto/a.c", b"123")
        output = self.root / "manifest.json"
        self.assertEqual(self.run_tool("create", self.root, output).returncode, 0)
        result = self.run_tool("stats", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["files"], 2)
        self.assertEqual(summary["bytes"], 8)
        self.assertEqual(summary["directories"]["crypto"]["files"], 1)

    def test_stats_rejects_invalid_manifest(self):
        bad = self.put("bad.json", b"{}")
        result = self.run_tool("stats", bad)
        self.assertEqual(result.returncode, 2)
        self.assertIn("manifest has unexpected fields", result.stderr)

    def test_rejects_malformed_json(self):
        bad = self.put("bad.json", b"{not json")
        result = self.run_tool("verify", self.root, bad)
        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot read manifest", result.stderr)

    def test_rejects_unsafe_manifest_entry(self):
        bad = self.put("bad.json", json.dumps(
            document(file_record("../outside"))
        ).encode())
        result = self.run_tool("verify", self.root, bad)
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsafe entry path", result.stderr)

    def test_rejects_missing_output_directory(self):
        self.put("source.c")
        result = self.run_tool(
            "create", self.root, self.root / "missing" / "manifest.json"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("output directory does not exist", result.stderr)

    def test_rejects_missing_source_directory(self):
        result = self.run_tool(
            "create", self.root / "missing", self.root / "manifest.json"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("source root is not a directory", result.stderr)

    def test_help_lists_subcommands(self):
        result = self.run_tool("--help")
        self.assertEqual(result.returncode, 0)
        for command in ("create", "verify", "diff", "stats"):
            self.assertIn(command, result.stdout)

    def test_rejects_unknown_subcommand(self):
        result = self.run_tool("unknown")
        self.assertNotEqual(result.returncode, 0)
