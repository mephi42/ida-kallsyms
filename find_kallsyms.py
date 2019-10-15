#!/usr/bin/env python3
import logging
import struct
import sys


def try_parse_token_index(rodata, endianness, offset):
    index_fmt = endianness + 'H'
    index, = struct.unpack(index_fmt, rodata[offset:offset + 2])
    assert index == 0, 'The first token index must be 0'
    indices = [index]
    for _ in range(255):
        offset += 2
        index, = struct.unpack(index_fmt, rodata[offset:offset + 2])
        if index <= indices[-1]:
            return None  # Token indices must be monotonically increasing.
        indices.append(index)
    return indices


def find_token_indices(rodata, endianness):
    token_index_offset = 0
    while True:
        # kallsyms_token_index is an array of monotonically increasing 256
        # shorts, the first of which is 0. It is located right after
        # kallsyms_token_table, which is a sequence of null-terminated strings.
        # Therefore, look for 1+2 consecutive zeroes.
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
            # Last token ends at the end of the table.
            token_end_offset = end_offset
        else:
            # Other tokens end at the start of the next respective token.
            token_end_offset = start_offset + token_index[i + 1]
        token = rodata[token_start_offset:token_end_offset]
        if b'\x00' in token[:-1]:
            return None  # Tokens must be printable.
        if token[-1] != 0:
            return None  # Tokens must be null-terminated.
        tokens.append(token[:-1])
    return tokens


def find_token_tables(rodata, token_index, token_index_offset):
    last_token_offset = token_index_offset
    while True:
        # kallsyms_token_table is a sequence of 256 null-terminated strings.
        # Find the last token by looking for a trailing \0.
        token_table_end_offset = last_token_offset
        last_token_offset = rodata.rfind(
            b'\x00', 0, last_token_offset - 1) + 1
        if last_token_offset == 0:
            break
        # The last kallsyms_token_index element corresponds to the last token.
        # Use that information to locate kallsyms_token_table.
        token_table_offset = last_token_offset - token_index[-1]
        if token_table_offset < 0:
            continue
        token_table = try_parse_token_table(
            rodata, token_index, token_table_offset, token_table_end_offset)
        if token_table is not None:
            yield token_table_offset, token_table


def find_markers(rodata, endianness, token_table_offset):
    # In 4.20 the size of markers was reduced to 4 bytes.
    for marker_fmt, marker_size in (
                (endianness + 'I', 4),
                (endianness + 'Q', 8),
            ):
        first = True
        marker_offset = token_table_offset - marker_size
        markers = []
        while True:
            # kallsyms_markers is an array of monotonically increasing offsets,
            # which starts with 0. It is aligned on an 8-byte boundary, so if
            # the element size is 4 bytes and their number is odd, it is zero-
            # padded at the end.
            marker, = struct.unpack(
                marker_fmt, rodata[marker_offset:marker_offset + marker_size])
            if first:
                first = False
                if marker == 0 and marker_size == 4:
                    # Skip padding.
                    marker_offset -= marker_size
                    continue
            elif len(markers) > 0 and marker >= markers[-1]:
                # The array is not monotonically increasing.
                return
            markers.append(marker)
            if marker == 0:
                # We found the first element.
                break
            marker_offset -= marker_size
        if marker_size == 4 and len(markers) == 2:
            # Marker size must be 8 bytes, and we must be taking the upper
            # part, which is always 0, for the first marker.
            continue
        markers.reverse()
        yield marker_offset, markers


def is_name_ok(rodata, token_lengths, offset):
    n_tokens = rodata[offset]
    if n_tokens == 0 or n_tokens >= 128:
        # Tokens are at least one byte long. Names must not be empty, and they
        # must be at most 127 characters long.
        return False
    offset += 1
    name_length = 0
    for _ in range(n_tokens):
        # The caller is expected to have verified that the name entry does not
        # span past the end of kallsyms_names, so just fetch the next token.
        name_length += token_lengths[rodata[offset]]
        if name_length >= 128:
            # Name is longer than 127 characters.
            return False
        offset += 1
    return True


def extract_name(rodata, token_table, offset):
    # Name must have already been checked, just expand tokens.
    n_tokens = rodata[offset]
    name = b''
    for _ in range(n_tokens):
        offset += 1
        name += token_table[rodata[offset]]
    return name


def find_num_syms(rodata, endianness, token_table, markers_offset):
    # kallsyms_names is a sequence of length-prefixed entries ending with
    # padding to an 8-byte boundary, followed by kallsyms_markers.
    # Unfortunately, some guesswork is required to locate the start of
    # kallsyms_names given that we know the start of kallsyms_markers.
    num_syms_fmt = endianness + 'I'
    token_lengths = [len(token) for token in token_table]
    # Indexed by (markers_offset - offset - 1). Each element is a number of
    # name entries that follow the respective offset, or None if that offset is
    # not a start of a valid name entry.
    name_counts = []
    # Whether offset still points to one of the trailing zeroes.
    trailing_zeroes = True
    offset = markers_offset
    while offset >= 9:
        offset -= 1
        if rodata[offset] != 0:
            # Trailing zeroes have ended.
            trailing_zeroes = False
        next_name_offset = offset + rodata[offset] + 1
        if next_name_offset >= markers_offset:
            # The current name entry spans past the end of kallsyms_names. This
            # is allowed if we are still looking at trailing zeroes.
            name_counts.append(0 if trailing_zeroes else None)
            continue
        next_name_count = name_counts[markers_offset - next_name_offset - 1]
        if next_name_count is None:
            # The next name entry is invalid, which means the current name
            # entry cannot be valid.
            name_counts.append(None)
            continue
        if is_name_ok(rodata, token_lengths, offset):
            # The current name entry is valid. Check whether it is preceded by
            # kallsyms_num_syms value, which is consistent with the number of
            # name entries we've seen so far.
            name_counts.append(next_name_count + 1)
            num_syms1, = struct.unpack(num_syms_fmt, rodata[offset - 4:offset])
            if name_counts[-1] == num_syms1:
                num_syms_offset = offset - 4
                break
            num_syms2, = struct.unpack(
                num_syms_fmt, rodata[offset - 8:offset - 4])
            if name_counts[-1] == num_syms2:
                num_syms_offset = offset - 8
                break
        else:
            # The current name entry is not valid. This is allowed if we are
            # still looking at trailing zeroes.
            name_counts.append(0 if trailing_zeroes else None)
    else:
        return
    # We've found kallsyms_names, now parse it.
    names = []
    for _ in range(name_counts[-1]):
        names.append(extract_name(rodata, token_table, offset).decode())
        offset += rodata[offset] + 1
    yield num_syms_offset, names


def get_addresses(rodata, endianness, num_syms_offset, num_syms):
    # Right now this function understands just one format: non-percpu
    # kallsyms_offsets followed by kallsyms_relative_base.
    address_fmt = endianness + 'i'
    kallsyms_relative_base, = struct.unpack(
        endianness + 'Q', rodata[num_syms_offset - 8:num_syms_offset])
    addresses_offset = num_syms_offset - 8 - num_syms * 4
    if addresses_offset % 8 != 0:
        addresses_offset -= 4
    offset = addresses_offset
    addresses = []
    for _ in range(num_syms):
        raw, = struct.unpack(address_fmt, rodata[offset:offset + 4])
        if raw >= 0:
            addresses.append(raw)
        else:
            addresses.append(kallsyms_relative_base - 1 - raw)
        offset += 4
    return addresses_offset, addresses


def find_kallsyms_in_rodata(rodata):
    for endianness in ('<', '>'):
        logging.debug('Endianness: %s', endianness)
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
                        addresses_offset, addresses = get_addresses(
                            rodata, endianness, num_syms_offset, len(names))
                        kallsyms_end = token_index_offset + (256 * 2)
                        kallsyms_size = kallsyms_end - addresses_offset
                        logging.debug(
                            '0x%08X: kallsyms[0x%08X]',
                            addresses_offset, kallsyms_size)
                        return zip(addresses, names)
    return []


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) != 2:
        print('Usage: {} PATH'.format(sys.argv[0]))
        sys.exit(1)
    rodata_path, = sys.argv[1:]
    with open(rodata_path, 'rb') as fp:
        rodata = bytearray(fp.read())
    for address, name in find_kallsyms_in_rodata(rodata):
        print('{:016X} {}'.format(address, name))
