import ida_state


def del_items(ea):
    """Delete items at the specified address."""
    ida_state.names.pop(ea, None)
