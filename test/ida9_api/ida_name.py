import ida_state


def is_uname(name):
    """Check if name is a valid user name."""
    if not name or not isinstance(name, str):
        return False
    # Basic validation: must start with letter or underscore
    if not (name[0].isalpha() or name[0] == "_"):
        return False
    # Must contain only alphanumeric chars and underscores
    return all(c.isalnum() or c == "_" for c in name)


def set_name(ea, name):
    """Set name at the specified address."""
    ida_state.names[ea] = name
    return True
