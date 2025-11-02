import io
import logging
import pathlib
import sys
import uuid

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.logging_setup import create_stream_handler


def _build_logger(default_source: str):
    stream = io.StringIO()
    handler = create_stream_handler(
        stream, default_remote_source=default_source
    )
    logger_name = f"test_logger_{uuid.uuid4()}"
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.handlers = [handler]
    return logger, stream


def test_remote_source_default_applied_when_missing():
    logger, stream = _build_logger("[controller] - ")
    logger.info("local message")
    output = stream.getvalue().strip()
    assert output.startswith("[controller] - ")


def test_remote_source_preserved_when_present():
    logger, stream = _build_logger("[controller] - ")
    logger.info("remote message", extra={"remote_source": "[laptop] - "})
    output = stream.getvalue().strip()
    assert output.startswith("[laptop] - ")
