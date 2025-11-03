
import logging
import unittest
from unittest.mock import MagicMock, patch
from logging.handlers import RotatingFileHandler

# Mock KVMOrchestrator and its dependencies for the test
class KVMOrchestrator:
    def __init__(self, settings, remote_log_handler=None):
        self.settings = settings
        self.remote_log_handler = remote_log_handler
        self.device_name = settings.get('device_name', 'test_device')

    def _configure_logging(self):
        role = self.settings.get("role")
        root_logger = logging.getLogger()

        for handler in list(root_logger.handlers):
            if isinstance(handler, (RotatingFileHandler, MagicMock)): # MagicMock for RemoteLogHandler
                root_logger.removeHandler(handler)

        if role == "ado":
            # In a real scenario, this would create a RotatingFileHandler
            file_handler = MagicMock()
            root_logger.addHandler(file_handler)
        else:
            if self.remote_log_handler:
                root_logger.addHandler(self.remote_log_handler)

class TestLoggingConfiguration(unittest.TestCase):

    def setUp(self):
        self.root_logger = logging.getLogger()
        self.original_handlers = self.root_logger.handlers[:]

    def tearDown(self):
        self.root_logger.handlers = self.original_handlers

    def test_ado_role_adds_file_handler(self):
        """Verify that the 'ado' role configures a file handler."""
        settings = {'role': 'ado'}
        orchestrator = KVMOrchestrator(settings)

        with patch.object(self.root_logger, 'addHandler') as mock_add_handler:
            orchestrator._configure_logging()
            self.assertEqual(mock_add_handler.call_count, 1)
            self.assertIsInstance(mock_add_handler.call_args[0][0], MagicMock)

    def test_client_role_adds_remote_handler(self):
        """Verify that a client role configures a remote handler."""
        mock_remote_handler = MagicMock()
        settings = {'role': 'input_provider'}
        orchestrator = KVMOrchestrator(settings, remote_log_handler=mock_remote_handler)

        with patch.object(self.root_logger, 'addHandler') as mock_add_handler:
            orchestrator._configure_logging()
            mock_add_handler.assert_called_once_with(mock_remote_handler)

if __name__ == '__main__':
    unittest.main()
