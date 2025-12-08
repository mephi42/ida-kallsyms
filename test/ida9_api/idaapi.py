import importlib
import inspect

import ida_state


def get_bytes(ea, size):
    """Get bytes from memory."""
    return ida_state.memory[(ea, size)]


def require(module_name):
    """Import a module and bring it into caller's scope."""
    module = importlib.import_module(module_name)
    # Inject into caller's global namespace
    caller_globals = inspect.currentframe().f_back.f_globals
    caller_globals[module_name] = module
