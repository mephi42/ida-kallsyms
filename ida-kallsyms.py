from idaapi import get_bytes
from ida_segment import get_segm_by_name

from find_kallsyms import find_kallsyms_in_rodata
from ida_utils import apply_kallsyms

rodata_segm = get_segm_by_name('.rodata')
if rodata_segm is None:
    rodata_segm = get_segm_by_name('.text')
rodata_size = rodata_segm.end_ea - rodata_segm.start_ea + 1
rodata = b''.join(get_bytes(rodata_segm.start_ea, rodata_size))
apply_kallsyms(find_kallsyms_in_rodata(rodata))
