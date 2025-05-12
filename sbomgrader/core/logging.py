import logging
import sys


def setup_logger(verbosity_level: int = 0, overwrite_handlers: bool = True) -> None:
    """
    Set up logging configuration. The logger uses STDERR.
    Args:
        verbosity_level:
            Positive integer, level 0 represents warnings,
            level 1 represents info and level 2 and above represent debug.
            All of these levels also include more severe logging information.
            Defaults to level 0.
        overwrite_handlers:
            If this function should overwrite existing handlers. Defaults to True.
    Returns:
        None
    """
    verbosity_table = {
        0: logging.WARNING,
        1: logging.INFO,
        2: logging.DEBUG,
    }
    log_level = verbosity_table.get(verbosity_level, logging.DEBUG)
    logger = logging.getLogger("sbomgrader")
    if overwrite_handlers:
        logger.handlers = []
    stderr_handler = logging.StreamHandler(stream=sys.stderr)
    stderr_handler.setLevel(log_level)
    logger.addHandler(stderr_handler)
    logger.setLevel(log_level)
