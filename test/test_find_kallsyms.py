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
            return fp.read()

    def test_kallsyms_4_16_3_s390x(self):
        addresses_and_names = list(
            find_kallsyms_in_rodata(self._read("kallsyms-4.16.3-301.fc28.s390x.gz"))
        )
        self.assertEqual(62766, len(addresses_and_names))
        self.assertEqual((0, "T_text"), addresses_and_names[0])
        self.assertEqual((0xD31E00, "B__bss_stop"), addresses_and_names[-1])

    def test_kallsyms_3_10_0_x86_64(self):
        addresses_and_names = list(
            find_kallsyms_in_rodata(
                self._read("kallsyms-3.10.0-862.11.6.el7.x86_64.gz")
            )
        )
        self.assertEqual(82619, len(addresses_and_names))
        self.assertEqual((0, "Airq_stack_union"), addresses_and_names[0])
        (dump_stack_address,) = [
            address for address, name in addresses_and_names if name == "Tdump_stack"
        ]
        self.assertEqual(0xFFFFFFFF817135BB, dump_stack_address)
        self.assertEqual(
            (0xFFFFFFFF82657000, "B__brk_limit"),
            addresses_and_names[-1],
        )

    def test_kallsyms_5_1_9_x86_64(self):
        addresses_and_names = list(
            find_kallsyms_in_rodata(
                self._read("kallsyms-5.1.9.balsn2019.krazynote.x86_64.gz")
            )
        )
        self.assertEqual(74045, len(addresses_and_names))
        self.assertEqual((0, "Airq_stack_union"), addresses_and_names[0])
        self.assertEqual((0xFFFFFFFF82A2C000, "B__brk_limit"), addresses_and_names[-1])

    def test_kallsyms_5_1_0_aarch64(self):
        addresses_and_names = list(
            find_kallsyms_in_rodata(
                self._read("kallsyms-5.1.0.tasteless2019.tee.aarch64.gz")
            )
        )
        self.assertEqual(117079, len(addresses_and_names))
        self.assertEqual((0, "t_head"), addresses_and_names[0])
        self.assertEqual((0x13CE000, "B_end"), addresses_and_names[-1])

    def test_kallsyms_5_3_0_x86_64(self):
        addresses_and_names = list(
            find_kallsyms_in_rodata(
                self._read("kallsyms-5.3.0.hitcon2019.poe.x86_64.gz")
            )
        )
        self.assertEqual(88612, len(addresses_and_names))
        self.assertEqual((0, "Afixed_percpu_data"), addresses_and_names[0])
        self.assertEqual(
            (0xFFFFFFFF83200000, "T__init_scratch_end"),
            addresses_and_names[-1],
        )

    def test_kallsyms_4_4_0_arm(self):
        addresses_and_names = list(
            find_kallsyms_in_rodata(self._read("kallsyms-4.4.0-1085-raspi2.arm.gz"))
        )
        self.assertEqual(78413, len(addresses_and_names))
        self.assertEqual((0x80008000, "Tstext"), addresses_and_names[0])
        self.assertEqual((0x80F56454, "B__bss_stop"), addresses_and_names[-1])

    def test_kallsyms_4_4_223_i686(self):
        addresses_and_names = list(
            find_kallsyms_in_rodata(
                self._read("kallsyms-4.4.223.defcon2020.ooofs.i686.gz")
            )
        )
        self.assertEqual(80397, len(addresses_and_names))
        self.assertEqual((0xC1000000, "Tstartup_32"), addresses_and_names[0])
        self.assertEqual((0xC1E9B000, "B__brk_limit"), addresses_and_names[-1])

    def test_kallsyms_4_4_223_i686_v2(self):
        addresses_and_names = list(
            find_kallsyms_in_rodata(self._read("kallsyms-4.4.223.defconfig.i686.gz"))
        )
        self.assertEqual(39874, len(addresses_and_names))
        self.assertEqual(
            (0xC1000338, "tsanitize_boot_params.constprop.0"),
            addresses_and_names[0],
        )
        self.assertEqual((0xC1BE29BD, "T_einittext"), addresses_and_names[-1])


if __name__ == "__main__":
    unittest.main()
