import json

from idc import add_struc, add_struc_member, apply_type, del_struc_member, \
    parse_decl
from ida_bytes import del_items, FF_BYTE, FF_DATA
from ida_name import get_name_ea, is_uname, set_name
from ida_struct import get_struc_id
from idaapi import BADADDR, get_inf_structure
from idautils import StructMembers


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
elif INFO.is_32bit():
    PTR_SIZE = 4
else:
    PTR_SIZE = 2


def get_type_size(like, die_offset):
    type = like.get(str(die_offset))
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
    if kind == 'array':
        return get_type_size(like, type[1]) * type[2]
    return DEFAULT_TYPE_SIZE


def add_end_member(struct_id, struct_name, struct_size, log_fp):
    """Forces struct size by creating a byte field at the end"""
    end_member_name = 'field_{:X}'.format(struct_size - 1)
    log_fp.write('{}.{}: ...\n'.format(struct_name, end_member_name))
    log_fp.flush()
    ret = add_struc_member(
        struct_id,
        end_member_name,
        struct_size - 1,
        DEFAULT_TYPE_FLAGS,
        DEFAULT_TYPE_ID,
        DEFAULT_TYPE_SIZE,
    )
    log_fp.write('... ret={}\n'.format(ret))
    log_fp.flush()
    return ret


def resolve_type(like, die_offset, log_fp, alias=None):
    if die_offset is None:
        return 'void'
    type = like.get(str(die_offset))
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
        if kind == 'struct' and type[2] != 0:
            ret = add_end_member(struct_id, struct_name, type[2], log_fp)
            have_end_member = ret == 0
        else:
            have_end_member = False
        for member_type_die_offset, member_name, member_offset in type[3]:
            if member_name is None:
                if kind == 'struct':
                    field_n = member_offset
                else:
                    field_n = sum(1 for _ in StructMembers(struct_id))
                member_name = 'field_{:X}'.format(field_n)
            elif not _is_uname(str(member_name)):
                member_name = '_' + member_name
            member_type_str = str(resolve_type(
                like, member_type_die_offset, log_fp))
            member_size = get_type_size(like, member_type_die_offset)
            if have_end_member and member_offset + member_size == type[2]:
                del_struc_member(struct_id, type[2] - 1)
                have_end_member = False
            log_fp.write('{} {}.{}: ...\n'.format(
                member_type_str, struct_name, member_name))
            log_fp.flush()
            ret = add_struc_member(
                struct_id,
                str(member_name),
                member_offset,
                DEFAULT_TYPE_FLAGS,
                DEFAULT_TYPE_ID,
                DEFAULT_TYPE_SIZE,
            )
            log_fp.write('... ret={}\n'.format(ret))
            log_fp.flush()
            if ret == 0:
                member_id = get_name_ea(
                    BADADDR, '{}.{}'.format(struct_name, member_name))
                apply_type(member_id, parse_decl(member_type_str, 0))
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
    if kind == 'array':
        return '{}[{}]'.format(resolve_type(like, type[1], log_fp), type[2])
    return DEFAULT_TYPE


def apply_like(path):
    with open('{}.log'.format(path), 'w') as log_fp:
        with open(path) as fp:
            like = json.load(fp)
        for item in like.values():
            if item[0] != 'subprogram':
                continue
            _, return_type, name, parameters, has_varargs = item
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
