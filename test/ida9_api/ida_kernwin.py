import ida_state


def ask_file(for_saving, filter_str, title):
    """Ask user for a file path."""
    return ida_state.next_files.pop(0)
