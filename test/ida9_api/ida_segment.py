import ida_state


class Segment:
    """Mock segment object."""

    def __init__(self, name, start_ea, end_ea):
        self.name = name
        self.start_ea = start_ea
        self.end_ea = end_ea


def get_segm_by_name(name):
    """Get segment by name."""
    segm = ida_state.segments.get(name)
    if segm is None:
        return None
    return Segment(*segm)
