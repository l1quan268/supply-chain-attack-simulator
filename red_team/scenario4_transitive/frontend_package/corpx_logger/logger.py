"""Lightweight logging wrapper — forwards to backend."""
import logging

def get_logger(name: str) -> logging.Logger:
    """Return a preconfigured logger for CorpX microservices."""
    from corpx_logging_backend import init_backend  # transitive dependency
    init_backend()
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[%(asctime)s] %(name)s — %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    return logger
