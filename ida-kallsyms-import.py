from ida_kernwin import ask_file
from idaapi import require

require("ida_kallsyms_utils")
path = ask_file(False, "*.kallsyms", "find-kallsyms output")
if path is not None:
    with open(path) as fp:
        ida_kallsyms_utils.apply_kallsyms(  # noqa: F821
            ida_kallsyms_utils.parse_kallsyms(fp)  # noqa: F821
        )
