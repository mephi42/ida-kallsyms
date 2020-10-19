from ida_kernwin import ask_file
from idaapi import require

require('ida_utils')
path = ask_file(False, '*.like.json', 'build-vmlinux output')
if path is not None:
    ida_utils.apply_like(path)  # noqa: F821
