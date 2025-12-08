# Shared state for IDA mocks

# Global addr->name mapping
names = {}

# Segments
segments = {}

# File dialog
next_files = []

# RAM contents
memory = {}


def reset():
    """Reset all mock state."""
    names.clear()
    segments.clear()
    del next_files[:]
    memory.clear()
