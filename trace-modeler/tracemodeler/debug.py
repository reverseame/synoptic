import sys
import logging

logger = logging.getLogger('trace-modeler')

""" Log format """
logging.basicConfig(level=logging.DEBUG, format='%(name)s\t: %(levelname)s\t: %(message)s')

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
