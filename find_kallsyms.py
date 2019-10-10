#!/usr/bin/env python3
import logging
import struct
import sys


def try_parse_token_index(rodata, endianness, offset):
    fmt = endianness + 'H'
    index, = struct.unpack(fmt, rodata[offset:offset + 2])
    assert (index == 0)
    indices = [index]
    for _ in range(255):
        offset += 2
        index, = struct.unpack(fmt, rodata[offset:offset + 2])
        if index <= indices[-1]:
            return None
        indices.append(index)
    return indices


def find_token_indices(rodata, endianness):
    token_index_offset = 0
    while True:
        token_index_offset = rodata.find(
            b'\x00\x00\x00', token_index_offset) + 1
        if token_index_offset == 0:
            break
        token_index = try_parse_token_index(
            rodata, endianness, token_index_offset)
        if token_index is not None:
            yield token_index_offset, token_index


def try_parse_token_table(rodata, token_index, start_offset, end_offset):
    tokens = []
    for i in range(256):
        token_start_offset = start_offset + token_index[i]
        if i == 255:
            token_end_offset = end_offset
        else:
            token_end_offset = start_offset + token_index[i + 1]
        token = rodata[token_start_offset:token_end_offset]
        if b'\x00' in token[:-1]:
            return None
        if token[-1] != 0:
            return None
        tokens.append(token[:-1])
    return tokens


def find_token_tables(rodata, token_index, token_index_offset):
    last_token_offset = token_index_offset
    while True:
        token_table_end_offset = last_token_offset
        last_token_offset = rodata.rfind(
            b'\x00', 0, last_token_offset - 1) + 1
        if last_token_offset == 0:
            break
        token_table_offset = last_token_offset - token_index[-1]
        token_table = try_parse_token_table(
            rodata, token_index, token_table_offset, token_table_end_offset)
        if token_table is not None:
            yield token_table_offset, token_table


def find_markers(rodata, endianness, token_table_offset):
    fmt = endianness + 'I'
    first = True
    marker_offset = token_table_offset - 4
    markers = []
    while True:
        marker, = struct.unpack(fmt, rodata[marker_offset:marker_offset + 4])
        if first:
            first = False
            if marker == 0:
                marker_offset -= 4
                continue
        elif len(markers) > 0 and marker >= markers[-1]:
            return
        markers.append(marker)
        if marker == 0:
            break
        marker_offset -= 4
    markers.reverse()
    yield marker_offset, markers


def is_name_ok(rodata, token_lengths, offset, end_offset):
    n_tokens = rodata[offset]
    if n_tokens == 0 or n_tokens >= 128:
        return False
    offset += 1
    if offset + n_tokens >= end_offset:
        return False
    name_length = 0
    for _ in range(n_tokens):
        name_length += token_lengths[rodata[offset]]
        if name_length >= 128:
            return False
        offset += 1
    return True


def extract_name(rodata, token_table, offset):
    n_tokens = rodata[offset]
    name = b''
    for _ in range(n_tokens):
        offset += 1
        name += token_table[rodata[offset]]
    return name


def find_num_syms(rodata, endianness, token_table, markers_offset):
    fmt = endianness + 'I'
    token_lengths = [len(token) for token in token_table]
    name_counts = []
    offset = markers_offset
    while offset >= 9:
        offset -= 1
        if is_name_ok(rodata, token_lengths, offset, markers_offset):
            next_name_offset = offset + rodata[offset] + 1
            prev_name_count = name_counts[
                markers_offset - next_name_offset - 1]
            name_counts.append(prev_name_count + 1)
            num_syms1, = struct.unpack(fmt, rodata[offset - 4:offset])
            if name_counts[-1] == num_syms1:
                num_syms_offset = offset - 4
                break
            num_syms2, = struct.unpack(fmt, rodata[offset - 8:offset - 4])
            if name_counts[-1] == num_syms2:
                num_syms_offset = offset - 8
                break
        else:
            name_counts.append(0)
    else:
        return
    names = []
    for _ in range(name_counts[-1]):
        names.append(extract_name(rodata, token_table, offset).decode())
        offset += rodata[offset] + 1
    yield num_syms_offset, names


def get_addresses(rodata, endianness, num_syms_offset, num_syms):
    fmt = endianness + 'i'
    kallsyms_relative_base, = struct.unpack(
        endianness + 'Q', rodata[num_syms_offset - 8:num_syms_offset])
    offset = num_syms_offset - 8 - num_syms * 4
    if offset % 8 != 0:
        offset -= 4
    addresses = []
    for _ in range(num_syms):
        raw, = struct.unpack(fmt, rodata[offset:offset + 4])
        if raw >= 0:
            addresses.append(raw)
        else:
            addresses.append(kallsyms_relative_base - 1 - raw)
        offset += 4
    return addresses


def find_kallsyms_in_rodata(rodata, endianness):
    for token_index_offset, token_index in find_token_indices(
            rodata, endianness):
        logging.debug(
            '0x%08X: kallsyms_token_index=%s',
            token_index_offset, token_index)
        for token_table_offset, token_table in find_token_tables(
                rodata, token_index, token_index_offset):
            logging.debug(
                '0x%08X: kallsyms_token_table=%s',
                token_table_offset, token_table)
            for markers_offset, markers in find_markers(
                    rodata, endianness, token_table_offset):
                logging.debug(
                    '0x%08X: kallsyms_markers=%s',
                    markers_offset, markers)
                for num_syms_offset, names in find_num_syms(
                        rodata, endianness, token_table, markers_offset):
                    logging.debug(
                        '0x%08X: kallsyms_num_syms=%s',
                        num_syms_offset, len(names))
                    addresses = get_addresses(
                        rodata, endianness, num_syms_offset, len(names))
                    return zip(addresses, names)
    return []


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) != 3:
        print('Usage: {} PATH ENDIANNESS'.format(sys.argv[0]))
        sys.exit(1)
    rodata_path, endianness = sys.argv[1:]
    with open(rodata_path, 'rb') as fp:
        rodata = bytearray(fp.read())
    for address, name in find_kallsyms_in_rodata(rodata, endianness):
        print('{:016X} {}'.format(address, name))
