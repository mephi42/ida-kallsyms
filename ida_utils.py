import json

from idc import apply_type, parse_decl
from ida_bytes import del_items
from ida_name import get_name_ea, is_uname, set_name
from ida_struct import add_struc, get_struc_id
from idaapi import BADADDR


def parse_kallsyms(fp):
    for line in fp:
        address, name = line.strip().split()
        yield int(address, 16), name


def _is_uname(name):
    return is_uname(name) and name not in (
        'class',
        'new',
    )


def apply_kallsyms(kallsyms):
    for address, name in kallsyms:
        if name[0] != 'A':
            new_name = str(name[1:])
            if not _is_uname(new_name):
                new_name = '_' + new_name
            if _is_uname(new_name):
                if not set_name(address, new_name):
                    del_items(address)
                    set_name(address, new_name)


DEFAULT_TYPE = 'char'


def resolve_type(like, die_offset, alias=None):
    if die_offset is None:
        return 'void'
    type = like['types'].get(str(die_offset))
    if type is None:
        return DEFAULT_TYPE
    kind = type[0]
    if kind == 'struct':
        if type[1] is None:
            if alias is None:
                struct_name = 'struct_' + hex(die_offset)
            else:
                struct_name = alias
        else:
            struct_name = type[1]
        struct_id = get_struc_id(str(struct_name))
        if struct_id != BADADDR:
            return struct_name
        struct_id = add_struc(BADADDR, str(struct_name), 0)
        if struct_id != BADADDR:
            return struct_name
        return DEFAULT_TYPE
    if kind == 'typedef':
        return resolve_type(like, type[2], type[1])
    if kind == 'pointer':
        return resolve_type(like, type[1]) + '*'
    if kind == 'base':
        if type[1]:
            return '__int' + str(type[2] * 8)
        else:
            return 'unsigned __int' + str(type[2] * 8)
    return DEFAULT_TYPE


def apply_like(path):
    with open(path) as fp:
        like = json.load(fp)
    for return_type, name, parameters, has_varargs in \
            like['subprograms'].values():
        address = get_name_ea(BADADDR, str(name))
        if address == BADADDR:
            print('Subprogram not found: ' + name)
            continue
        decl = resolve_type(like, return_type) + ' ' + name + '('
        first = True
        for parameter_type, parameter_name in parameters:
            if first:
                first = False
            else:
                decl += ', '
            if not _is_uname(str(parameter_name)):
                parameter_name = '_' + parameter_name
            decl += resolve_type(like, parameter_type)
            if _is_uname(str(parameter_name)):
                decl += ' ' + parameter_name
        if has_varargs:
            if not first:
                decl += ', '
            decl += '...'
        decl += ')'
        print(decl)
        apply_type(address, parse_decl(str(decl), 0))
