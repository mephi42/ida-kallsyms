import json

from idc import add_struc, add_struc_member, apply_type, del_struc_member, \
    parse_decl
from ida_bytes import del_items, FF_BYTE, FF_DATA, FF_DWRD, FF_OWRD, FF_QWRD, \
    FF_STRUCT, FF_WORD
from ida_name import get_name_ea, is_uname, set_name
from ida_struct import get_struc_id
from idaapi import BADADDR, get_inf_structure


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
DEFAULT_TYPE_SIZE = 1
DEFAULT_TYPE_FLAGS = FF_DATA | FF_BYTE
DEFAULT_TYPE_ID = -1
INFO = get_inf_structure()
if INFO.is_64bit():
    PTR_SIZE = 8
    FF_PTR = FF_QWRD
elif INFO.is_32bit():
    PTR_SIZE = 4
    FF_PTR = FF_DWRD
else:
    PTR_SIZE = 2
    FF_PTR = FF_WORD


def get_flags(like, die_offset):
    type = like['types'].get(str(die_offset))
    if type is None:
        return DEFAULT_TYPE_FLAGS
    kind = type[0]
    if kind in ('struct', 'union'):
        return FF_DATA | FF_STRUCT
    if kind == 'typedef':
        return get_flags(like, type[2])
    if kind == 'pointer':
        return FF_DATA | FF_PTR
    if kind == 'base':
        return {
            1: FF_BYTE,
            2: FF_WORD,
            4: FF_DWRD,
            8: FF_QWRD,
            16: FF_OWRD,
        }[type[2]]
    if kind in ('const', 'volatile'):
        return get_flags(like, type[1])
    return DEFAULT_TYPE_SIZE


def get_type_id(like, die_offset):
    type = like['types'].get(str(die_offset))
    if type is None:
        return DEFAULT_TYPE_ID
    kind = type[0]
    if kind in ('struct', 'union'):
        if len(type) != 5:
            return DEFAULT_TYPE_ID
        return type[4]
    if kind == 'typedef':
        return get_type_id(like, type[2])
    if kind in ('const', 'volatile'):
        return get_type_id(like, type[1])
    return DEFAULT_TYPE_SIZE


def get_type_size(like, die_offset):
    type = like['types'].get(str(die_offset))
    if type is None:
        return DEFAULT_TYPE_SIZE
    kind = type[0]
    if kind in ('struct', 'union'):
        return type[2]
    if kind == 'typedef':
        return get_type_size(like, type[2])
    if kind == 'pointer':
        return PTR_SIZE
    if kind == 'base':
        return type[2]
    if kind in ('const', 'volatile'):
        return get_type_size(like, type[1])
    return DEFAULT_TYPE_SIZE


def resolve_type(like, die_offset, log_fp, alias=None):
    if die_offset is None:
        return 'void'
    type = like['types'].get(str(die_offset))
    if type is None:
        return DEFAULT_TYPE
    kind = type[0]
    if kind in ('struct', 'union'):
        if type[1] is None:
            if alias is None:
                struct_name = '{}_{}'.format(kind, hex(die_offset))
            else:
                struct_name = alias
        else:
            struct_name = type[1]
        if (not _is_uname(str(struct_name)) or
                (get_struc_id(str(struct_name)) == BADADDR and
                 get_name_ea(BADADDR, str(struct_name)) != BADADDR)):
            struct_name = '_' + struct_name
        struct_id = get_struc_id(str(struct_name))
        if struct_id != BADADDR:
            if len(type) == 4:
                type.append(struct_id)
            return struct_name
        log_fp.write('{}: ...\n'.format(struct_name))
        log_fp.flush()
        struct_id = add_struc(BADADDR, str(struct_name), kind == 'union')
        log_fp.write('... id={}\n'.format(hex(struct_id)))
        log_fp.flush()
        if struct_id == BADADDR:
            return DEFAULT_TYPE
        type.append(struct_id)
        end_member_name = 'field_{:X}'.format(type[2] - 1)
        log_fp.write('{}.{}: ...\n'.format(struct_name, end_member_name))
        log_fp.flush()
        ret = add_struc_member(
            struct_id,
            end_member_name,
            type[2] - 1,
            DEFAULT_TYPE_FLAGS,
            DEFAULT_TYPE_ID,
            DEFAULT_TYPE_SIZE,
        )
        log_fp.write('... = {}\n'.format(ret))
        log_fp.flush()
        for member_type_die_offset, member_name, member_offset in type[3]:
            if member_name is None:
                member_name = 'field_{:X}'.format(member_offset)
            elif not _is_uname(str(member_name)):
                member_name = '_' + member_name
            member_type_str = resolve_type(
                like, member_type_die_offset, log_fp)
            member_flags = get_flags(like, member_type_die_offset)
            member_type_id = get_type_id(like, member_type_die_offset)
            member_size = get_type_size(like, member_type_die_offset)
            if member_offset + member_size == type[2]:
                del_struc_member(struct_id, type[2] - 1)
            log_fp.write('{} {}.{} (size={}): ...\n'.format(
                member_type_str, struct_name, member_name, member_size))
            log_fp.flush()
            ret = add_struc_member(
                struct_id,
                str(member_name),
                member_offset,
                member_flags,
                member_type_id,
                member_size,
            )
            log_fp.write('... ret={}\n'.format(ret))
            log_fp.flush()
        return struct_name
    if kind == 'typedef':
        return resolve_type(like, type[2], log_fp, type[1])
    if kind == 'pointer':
        return resolve_type(like, type[1], log_fp) + '*'
    if kind == 'base':
        if type[1]:
            return '__int' + str(type[2] * 8)
        else:
            return 'unsigned __int' + str(type[2] * 8)
    if kind in ('const', 'volatile'):
        return resolve_type(like, type[1], log_fp)
    return DEFAULT_TYPE


def apply_like(path):
    with open('{}.log'.format(path), 'w') as log_fp:
        with open(path) as fp:
            like = json.load(fp)
        for return_type, name, parameters, has_varargs in \
                like['subprograms'].values():
            address = get_name_ea(BADADDR, str(name))
            if address == BADADDR:
                log_fp.write('Subprogram not found: {}\n'.format(name))
                log_fp.flush()
                continue
            decl = resolve_type(like, return_type, log_fp) + ' ' + name + '('
            first = True
            for parameter_type, parameter_name in parameters:
                if first:
                    first = False
                else:
                    decl += ', '
                if not _is_uname(str(parameter_name)):
                    parameter_name = '_' + parameter_name
                decl += resolve_type(like, parameter_type, log_fp)
                if _is_uname(str(parameter_name)):
                    decl += ' ' + parameter_name
            if has_varargs:
                if not first:
                    decl += ', '
                decl += '...'
            decl += ')'
            log_fp.write('{}: ...\n'.format(decl))
            log_fp.flush()
            ret = apply_type(address, parse_decl(str(decl), 0))
            log_fp.write('... ret={}\n'.format(ret))
            log_fp.flush()
