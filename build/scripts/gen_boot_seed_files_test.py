#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2026 vivo Mobile Communication Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Compile generated literals and check their runtime bytes with rustc.

Run with: python3 -B build/scripts/gen_boot_seed_files_test.py
"""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import gen_boot_seed_files as generator


class RustCatalogTests(unittest.TestCase):

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="blueos-boot-literals-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def run_command(self, arguments, cwd=None):
        result = subprocess.run(arguments, cwd=cwd, capture_output=True)
        self.assertEqual(result.returncode, 0,
                         result.stderr.decode("utf-8", errors="replace"))
        return result.stdout

    def compiled_values(self, declarations, iterator, externs=()):
        # Expected bytes are compared in Python, independently of the Rust
        # escaping function being tested. Length framing also preserves NULs.
        body = """
use std::io::Write;

fn main() {
    let mut output = std::io::stdout().lock();
    for bytes in ITERATOR {
        output.write_all(&(bytes.len() as u64).to_le_bytes()).unwrap();
        output.write_all(bytes).unwrap();
    }
}
""".replace("ITERATOR", iterator)
        source = self.directory / "main.rs"
        source.write_text(declarations + body, encoding="utf-8")
        binary = self.directory / "literal-check"
        self.run_command([
            "rustc", "--edition=2021", "-Dwarnings",
            str(source), "-o",
            str(binary), *externs
        ])
        output = self.run_command([str(binary)])
        values = []
        offset = 0
        while offset < len(output):
            prefix = output[offset:offset + 8]
            self.assertEqual(len(prefix), 8)
            length = int.from_bytes(prefix, "little")
            offset += 8
            value = output[offset:offset + length]
            self.assertEqual(len(value), length)
            values.append(value)
            offset += length
        return values

    def check_literals(self, values, c_strings=False):
        literal = generator.c_literal if c_strings else generator.rust_literal
        value_type = "core::ffi::CStr" if c_strings else "str"
        declarations = f"const VALUES: &[&{value_type}] = &[\n"
        declarations += ",\n".join(literal(value) for value in values)
        declarations += "\n];\n"
        method = "to_bytes" if c_strings else "as_bytes"
        actual = self.compiled_values(
            declarations, f"VALUES.iter().map(|value| value.{method}())")
        self.assertEqual(actual, [value.encode("utf-8") for value in values])

    def test_rust_literals_preserve_unicode_and_control_characters(self):
        values = [
            "", "plain ASCII", '"quoted" \\ path', "\b\f\r\n\t\0",
            "你好 / café / e\u0301 / 🚀", "\u0085\u2028\u2029",
            "\u202e\u2066\u2069", "".join(map(chr, range(256)))
        ]
        values.extend(
            chr(point) for point in
            [0x7ff, 0x800, 0xd7ff, 0xe000, 0xffff, 0x10000, 0x10ffff])
        self.check_literals(values)

    def test_rust_literals_reject_surrogates(self):
        for value in ["\ud800", "\udfff", "/apps/\udc80/app.elf"]:
            with self.subTest(value=repr(value)):
                with self.assertRaisesRegex(SystemExit, "Unicode surrogate"):
                    generator.rust_literal(value)

    def test_c_literals_preserve_escaped_utf8_paths(self):
        self.check_literals([
            "", "/tmp/你好/🚀.elf", '/tmp/"quoted"/back\\slash',
            "/tmp/\b\f\r\n\t\x7f\u0085\u2028\u2029.elf"
        ],
                            c_strings=True)

    def test_c_literals_reject_nul(self):
        for value in ["\0", "/tmp/a\0b"]:
            with self.subTest(value=repr(value)):
                with self.assertRaisesRegex(SystemExit, "contains NUL"):
                    generator.c_literal(value)

    def read_catalog(self, arguments):
        catalog = self.directory / "catalog.rs"
        self.run_command([
            sys.executable, "-B",
            str(Path(generator.__file__).resolve()), "--catalog-out",
            str(catalog), *arguments
        ],
                         cwd=self.directory)
        library = self.directory / "libboot_seed_catalog.rlib"
        self.run_command([
            "rustc", "--edition=2021", "-Dwarnings", "--crate-type=rlib",
            "--crate-name=boot_seed_catalog",
            str(catalog), "-o",
            str(library)
        ])
        return self.compiled_values(
            "", "boot_seed_catalog::FILES.iter().flat_map(|entry| "
            "[entry.path.as_bytes(), entry.host_path.to_bytes()])",
            ["--extern", f"boot_seed_catalog={library}"])

    def test_cli_preserves_direct_and_json_layout_paths(self):
        artifact = self.directory / 'artifact_你好_"_\\_\t_\r_\n_🚀.elf'
        artifact.write_bytes(b"catalog records paths, not these bytes")
        paths = [
            "/apps/你好/app.elf", '/apps/"quoted"/back\\slash/app.elf',
            "/apps/\b\f\r\n\t\u0085\u2028\u2029/🚀.elf"
        ]
        layout = self.directory / "layout.json"
        # Default JSON escaping includes surrogate pairs for non-BMP scalars;
        # these are decoded before rendering the Rust source.
        layout.write_text(json.dumps([{
            "vfs_path": path,
            "artifact": artifact.name
        } for path in paths[1:]]),
                          encoding="utf-8")
        actual = self.read_catalog(
            ["--file", f"{paths[0]},{artifact.name}", "--layout",
             str(layout)])
        expected = []
        for path in paths:
            expected.extend(
                [path.encode("utf-8"),
                 str(artifact).encode("utf-8")])
        self.assertEqual(actual, expected)

    def test_empty_catalog_compiles(self):
        self.assertEqual(self.read_catalog([]), [])


if __name__ == "__main__":
    unittest.main()
