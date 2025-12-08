from ida_bytes import del_items
from ida_name import is_uname, set_name


def parse_kallsyms(fp):
    for line in fp:
        address, name = line.strip().split()
        yield int(address, 16), name


def _is_uname(name):
    """Check if name is a valid IDA name, excluding reserved words."""
    return is_uname(name) and name not in (
        "class",
        "new",
    )


def apply_kallsyms(kallsyms):
    for address, name in kallsyms:
        if name[0] != "A":
            new_name = str(name[1:])
            if not _is_uname(new_name):
                new_name = "_" + new_name
            if _is_uname(new_name):
                if not set_name(address, new_name):
                    del_items(address)
                    set_name(address, new_name)
