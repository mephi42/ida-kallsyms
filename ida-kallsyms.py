from idaapi import get_bytes
from ida_name import is_uname, set_name
from ida_segment import get_segm_by_name

from find_kallsyms import find_kallsyms_in_rodata

rodata_segm = get_segm_by_name('.rodata')
if rodata_segm is None:
    rodata_segm = get_segm_by_name('.text')
rodata_size = rodata_segm.end_ea - rodata_segm.start_ea + 1
rodata = b''.join(get_bytes(rodata_segm.start_ea, rodata_size))
for address, name in find_kallsyms_in_rodata(rodata):
    if name[0] != 'A':
        new_name = str(name[1:])
        if not is_uname(new_name):
            new_name = '_' + new_name
        if is_uname(new_name):
            set_name(address, new_name)
