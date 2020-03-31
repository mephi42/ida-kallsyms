#!/usr/bin/env python3
import gzip
import os
import unittest

from find_kallsyms import find_kallsyms_in_rodata


class TestFindKallsyms(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
        self.basedir = os.path.dirname(__file__)

    def _read(self, name):
        with gzip.GzipFile(os.path.join(self.basedir, name)) as fp:
            return bytearray(fp.read())

    def test_kallsyms_4_16_3_s390x(self):
        addresses_and_names = list(find_kallsyms_in_rodata(
            self._read('kallsyms-4.16.3-301.fc28.s390x.gz')))
        self.assertEqual(62766, len(addresses_and_names))
        self.assertEquals((0, 'T_text'), addresses_and_names[0])
        self.assertEquals((0xd31e00, 'B__bss_stop'), addresses_and_names[-1])

    def test_kallsyms_3_10_0_x86_64(self):
        addresses_and_names = list(find_kallsyms_in_rodata(
            self._read('kallsyms-3.10.0-862.11.6.el7.x86_64.gz')))
        self.assertEqual(82619, len(addresses_and_names))
        self.assertEquals(
            (0x4161de0, 'Airq_stack_union'), addresses_and_names[0])
        self.assertEquals((0x4cae000, 'B__brk_limit'), addresses_and_names[-1])

    def test_kallsyms_5_1_9_x86_64(self):
        addresses_and_names = list(find_kallsyms_in_rodata(
            self._read('kallsyms-5.1.9.balsn2019.krazynote.x86_64.gz')))
        self.assertEqual(74045, len(addresses_and_names))
        self.assertEquals((0, 'Airq_stack_union'), addresses_and_names[0])
        self.assertEquals(
            (0xffffffff82a2c000, 'B__brk_limit'), addresses_and_names[-1])

    def test_kallsyms_5_1_0_aarch64(self):
        addresses_and_names = list(find_kallsyms_in_rodata(
            self._read('kallsyms-5.1.0.tasteless2019.tee.aarch64.gz')))
        self.assertEqual(117079, len(addresses_and_names))
        self.assertEquals((0, 't_head'), addresses_and_names[0])
        self.assertEquals((0x13ce000, 'B_end'), addresses_and_names[-1])

    def test_kallsyms_5_3_0_x86_64(self):
        addresses_and_names = list(find_kallsyms_in_rodata(
            self._read('kallsyms-5.3.0.hitcon2019.poe.x86_64.gz')))
        self.assertEqual(88612, len(addresses_and_names))
        self.assertEquals((0, 'Afixed_percpu_data'), addresses_and_names[0])
        self.assertEquals(
            (0xffffffff83200000, 'T__init_scratch_end'),
            addresses_and_names[-1],
        )

    def test_kallsyms_4_4_0_arm(self):
        addresses_and_names = list(find_kallsyms_in_rodata(
            self._read('kallsyms-4.4.0-1085-raspi2.arm.gz')))
        self.assertEqual(78413, len(addresses_and_names))
        self.assertEquals((0x80008000, 'Tstext'), addresses_and_names[0])
        self.assertEquals((0x80f56454, 'B__bss_stop'), addresses_and_names[-1])


if __name__ == '__main__':
    unittest.main()
