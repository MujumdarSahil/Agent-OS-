import os
import json
import logging
import datetime

class JSONFormatter(logging.Formatter):
    """
    Format logs as a single line JSON object.
    """
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.datetime.fromtimestamp(record.created).isoformat(),
            "name": record.name,
            "level": record.levelname,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
            
        # Standard LogRecord attributes to exclude from extra context
        std_attrs = {
            'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename',
            'funcName', 'levelname', 'levelno', 'lineno', 'module',
            'msecs', 'message', 'msg', 'name', 'pathname', 'process',
            'processName', 'relativeCreated', 'stack_info', 'thread', 'threadName'
        }
        for k, v in record.__dict__.items():
            if k not in std_attrs:
                payload[k] = v
        return json.dumps(payload)

def setup_logging():
    """
    Sets up logging format based on AGENTOS_LOG_FORMAT environment variable.
    """
    log_format = os.environ.get("AGENTOS_LOG_FORMAT", "text").lower()
    
    # Get root logger
    root_logger = logging.getLogger()
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        
    handler = logging.StreamHandler()
    if log_format == "json":
        handler.setFormatter(JSONFormatter())
    else:
        # Default text format
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        
    root_logger.addHandler(handler)
    # Set default level to INFO if not configured
    if root_logger.level == logging.NOTSET:
        root_logger.setLevel(logging.INFO)
