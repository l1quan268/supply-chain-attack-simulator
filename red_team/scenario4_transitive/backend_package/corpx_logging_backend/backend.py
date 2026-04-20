"""Logging backend — real functions that work normally."""
import logging
import os

_initialized = False

def init_backend():
    """Initialize the file-based logging backend."""
    global _initialized
    if _initialized:
        return
    log_dir = os.path.join(os.path.expanduser("~"), ".corpx_logs")
    os.makedirs(log_dir, exist_ok=True)
    _initialized = True
