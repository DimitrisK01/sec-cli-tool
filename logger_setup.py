#logger_setup

import re
import logging
import sys

class StreamToLogger:
    """
    A fake file-like stream object that redirects writes to a logger instance,
    stripping ANSI escape sequences in the process.
    """
    def __init__(self, logger, log_level=logging.INFO):
        self.logger = logger
        self.log_level = log_level
        self.ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')

    def write(self, buf):
        if isinstance(buf, bytes):
            buf = buf.decode('utf-8')  # Ensure we are handling strings, not bytes
        buf = self.ansi_escape.sub('', buf)  # Strip ANSI codes
        if buf.strip():  # Only log non-empty lines
            self.logger.log(self.log_level, buf.strip())

    def flush(self):
        # This might be called by print function, just pass as we handle buffering in logger
        pass

def setup_logging():
    # Log file to store all logs, change path as needed
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[
                            logging.FileHandler("/app/output/complete_log.txt"),
                            logging.StreamHandler(sys.stdout)  # Optional: logs in console
                        ])
    
    # Set up custom stream redirection
    stdout_logger = logging.getLogger('STDOUT')
    sys.stdout = StreamToLogger(stdout_logger, logging.INFO)

    stderr_logger = logging.getLogger('STDERR')
    sys.stderr = StreamToLogger(stderr_logger, logging.ERROR)
