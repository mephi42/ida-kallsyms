#!/usr/bin/env python3
import gzip
import os
import runpy
import sys
import unittest

from test import ida_state

sys.modules["ida_state"] = ida_state  # Share with run_path imports


class TestIDAKallsyms(unittest.TestCase):
    """Test ida-kallsyms.py functionality."""

    def setUp(self):
        ida_state.reset()

    def test_ida_kallsyms(self):
        """Test executing ida-kallsyms.py with real kallsyms data."""
        # Load real kallsyms test data (smallest file)
        basedir = os.path.dirname(__file__)
        with gzip.GzipFile(
            os.path.join(basedir, "kallsyms-6.2.8.seccon2023.kmemo.x86_64.gz")
        ) as fp:
            rodata = fp.read()

        # Set up .rodata segment
        ida_state.segments[".rodata"] = (".rodata", 0, len(rodata) - 1)
        ida_state.memory[(0, len(rodata))] = rodata

        # Execute ida-kallsyms.py
        ida9_api_path = os.path.join(os.path.dirname(__file__), "ida9_api")
        sys.path.insert(0, ida9_api_path)
        try:
            runpy.run_path("ida-kallsyms.py", run_name="__main__")
        finally:
            sys.path.remove(ida9_api_path)

        # Verify symbols were applied
        self.assertEqual(len(ida_state.names), 23829)
        # Check a few known symbols
        self.assertEqual(ida_state.names[0xFFFFFFFF81000000], "_text")
        self.assertEqual(ida_state.names[0xFFFFFFFF81B4E01E], "_einittext")


if __name__ == "__main__":
    unittest.main()
