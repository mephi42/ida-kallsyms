from ida_kernwin import ask_file
from idaapi import require

require('ida_utils')
path = ask_file(False, '.', 'kallsyms')
with open(path) as fp:
    ida_utils.apply_kallsyms(ida_utils.parse_kallsyms(fp))
