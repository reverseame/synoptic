import sys
import logging

import synoptic.utils as utils

logger = logging.getLogger(utils.TOOL_NAME)

""" Log format, default level to INFO """
logging.basicConfig(level=logging.INFO, format='%(name)s\t: %(levelname)s\t: %(message)s')

def debug(msg):
    log(logging.DEBUG, msg)

def info(msg):
    log(logging.INFO, msg)

def warning(msg):
    log(logging.WARNING, msg)

def error(msg, exit_code=-1):
    log(logging.ERROR, msg)
    sys.exit(exit_code)

def critical(msg, exit_code=-1):
    log(logging.CRITICAL, msg)
    sys.exit(exit_code)

def log(loglevel, msg):
    """ Show debug message """
    logger.log(loglevel, msg)
