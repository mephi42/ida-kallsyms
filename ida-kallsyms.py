from idaapi import get_bytes, require
from ida_segment import get_segm_by_name

require('find_kallsyms')
require('ida_utils')
rodata_segm = get_segm_by_name('.rodata')
if rodata_segm is None:
    rodata_segm = get_segm_by_name('.text')
rodata_size = rodata_segm.end_ea - rodata_segm.start_ea + 1
rodata = b''.join(get_bytes(rodata_segm.start_ea, rodata_size))
kallsyms = find_kallsyms.find_kallsyms_in_rodata(rodata)  # noqa: F821
ida_utils.apply_kallsyms(kallsyms)  # noqa: F821
