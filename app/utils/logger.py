import logging
from logging.handlers import TimedRotatingFileHandler, QueueHandler, QueueListener
from queue import Queue
import os
from datetime import datetime
from app.utils.security import encrypt_data  # Your encryption function

# Queue for async logging
log_queue = Queue()

class EncryptedFileHandler(logging.Handler):
    def __init__(self, filename, when='midnight', backupCount=7, encoding='utf-8'):
        super().__init__()
        self.handler = TimedRotatingFileHandler(
            filename, when=when, backupCount=backupCount, encoding=encoding
        )

    def emit(self, record):
        try:
            msg = self.format(record)
            encrypted_msg = encrypt_data(msg)
            self.handler.stream = self.handler._open()
            self.handler.stream.write(encrypted_msg + '\n')
            self.handler.stream.flush()
            self.handler.close()
        except Exception:
            self.handleError(record)

    def close(self):
        self.handler.close()
        super().close()

def setup_logging(log_dir="logs"):
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_filename = os.path.join(log_dir, f"app_{datetime.now().strftime('%Y-%m-%d')}.log")
    encrypted_handler = EncryptedFileHandler(log_filename)
    formatter = logging.Formatter(
        '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "module": "%(module)s", '
        '"txn": "%(txn)s", "status_code": "%(status_code)s", "message": %(message)s}'
    )
    encrypted_handler.setFormatter(formatter)

    listener = QueueListener(log_queue, encrypted_handler)
    listener.start()
    return listener

def get_logger(name="app_logger") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not any(isinstance(h, QueueHandler) for h in logger.handlers):
        logger.addHandler(QueueHandler(log_queue))
    return logger
