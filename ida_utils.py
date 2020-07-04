from ida_name import is_uname, set_name


def parse_kallsyms(fp):
    for line in fp:
        address, name = line.strip().split()
        yield int(address, 16), name


def apply_kallsyms(kallsyms):
    for address, name in kallsyms:
        if name[0] != 'A':
            new_name = str(name[1:])
            if not is_uname(new_name):
                new_name = '_' + new_name
            if is_uname(new_name):
                set_name(address, new_name)
