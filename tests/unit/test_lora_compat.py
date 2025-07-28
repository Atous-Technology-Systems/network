"""
Test LoRa Optimizer Compatibility Layer

Tests for the LoRaOptimizer compatibility wrapper that provides a backward-compatible
interface for the LoraAdaptiveEngine and LoraAdaptiveEngine.
"""
import unittest
from unittest.mock import patch, MagicMock, ANY, call, PropertyMock
import sys
import os
import logging

# Create a proper mock for RPi.GPIO
class MockGPIO:
    BCM = 'BCM'
    IN = 'IN'
    OUT = 'OUT'
    HIGH = True
    LOW = False
    
    @staticmethod
    def setmode(mode):
        pass
        
    @staticmethod
    def setup(pin, mode, initial=None):
        pass
        
    @staticmethod
    def input(pin):
        return False
        
    @staticmethod
    def output(pin, state):
        pass

# Apply the mock before any imports
sys.modules['RPi'] = MagicMock()
sys.modules['RPi.GPIO'] = MockGPIO()

# Now import the modules
from atous_sec_network.network.lora_compat import LoRaOptimizer

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Add the project root to the Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import the module we're testing
try:
    # Import the module we want to patch first
    from atous_sec_network.network import lora_optimizer
    # Now import the module under test
    from atous_sec_network.network.lora_compat import LoRaOptimizer
except ImportError as e:
    print(f"Import error: {e}")
    print(f"Current sys.path: {sys.path}")
    raise

class TestLoRaOptimizerCompat(unittest.TestCase):
    """Test the LoRaOptimizer compatibility layer"""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create mock for serial module
        self.serial_patcher = patch('serial.Serial')
        self.mock_serial = self.serial_patcher.start()
        
        # Configure serial mock
        self.mock_serial.return_value.is_open = True
        self.mock_serial.return_value.timeout = 1.0
        self.mock_serial.return_value.in_waiting = 0
        
        # Create a real mock for the hardware interface
        self.mock_hardware = MagicMock()
        self.mock_hardware.port = 'COM1'
        self.mock_hardware.baudrate = 9600
        self.mock_hardware.timeout = 1.0
        self.mock_hardware.serial = self.mock_serial.return_value
        
        # Configure the mock hardware methods
        self.mock_hardware.send_command.return_value = (True, "OK")
        self.mock_hardware.add_checksum.side_effect = lambda x: f"{x}*XX"
        self.mock_hardware.verify_checksum.return_value = True
        
        # Create a real mock for the engine
        self.mock_engine = MagicMock()
        
        # Patch the classes to return our mocks
        self.hardware_patcher = patch('atous_sec_network.network.lora_compat.LoraHardwareInterface', 
                                    return_value=self.mock_hardware)
        self.engine_patcher = patch('atous_sec_network.network.lora_compat.LoraAdaptiveEngine',
                                  return_value=self.mock_engine)
        
        # Start the patches
        self.mock_hardware_class = self.hardware_patcher.start()
        self.mock_engine_class = self.engine_patcher.start()
        
        # Create an instance of the class under test
        self.lora = LoRaOptimizer()
        
        # Configure the mock hardware interface
        self.mock_hardware.port = 'COM1'
        self.mock_hardware.baudrate = 9600
        self.mock_hardware.timeout = 1.0
        self.mock_hardware.serial = self.mock_serial.return_value
        self.mock_hardware.send_command.return_value = (True, "OK")
        
        # Enable debug logging for tests
        logging.disable(logging.NOTSET)
        logger.setLevel(logging.DEBUG)
        
    def tearDown(self):
        """Clean up after each test method."""
        self.hardware_patcher.stop()
        self.engine_patcher.stop()
        self.serial_patcher.stop()
        # Re-enable logging
        logging.disable(logging.NOTSET)
    
    def test_initialize_success(self):
        """Test successful initialization of LoRa module."""
        logger.info("=== Starting test_initialize_success ===")
        
        # Reset mocks to ensure clean state
        self.mock_hardware.send_command.reset_mock()
        self.mock_hardware_class.reset_mock()
        self.mock_engine_class.reset_mock()
        
        # Configure the mock to return success for the AT command
        self.mock_hardware.send_command.return_value = (True, "OK")
        
        # Verify initial state
        logger.info("1. Verifying initial state...")
        self.assertFalse(self.lora.initialized, "LoRa should not be initialized yet")
        self.assertIsNone(self.lora.hardware, "Hardware should be None before initialization")
        self.assertIsNone(self.lora.engine, "Engine should be None before initialization")
        
        # Configure the mock hardware
        logger.info("2. Configuring mocks...")
        self.mock_hardware.port = 'COM1'
        self.mock_hardware.baudrate = 9600
        self.mock_hardware.timeout = 1.0
        
        # Reset mock call counts to ignore setup calls
        self.mock_hardware.send_command.reset_mock()
        self.mock_hardware_class.reset_mock()
        self.mock_engine_class.reset_mock()
        
        # Call the method under test
        logger.info("3. Calling initialize()...")
        result = self.lora.initialize(port='COM1', baud=9600)
        
        # Log the results
        logger.info(f"4. initialize() returned: {result}")
        logger.info(f"   lora.initialized: {self.lora.initialized}")
        logger.info(f"   lora.hardware: {self.lora.hardware}")
        logger.info(f"   lora.engine: {self.lora.engine}")
        
        # Log all calls to send_command for debugging
        logger.info("5. All calls to send_command:")
        for i, call_item in enumerate(self.mock_hardware.send_command.mock_calls, 1):
            logger.info(f"   Call {i}: {call_item}")
        
        # Verify the result
        logger.info("6. Verifying results...")
        self.assertTrue(result, "initialize() should return True on success")
        self.assertTrue(self.lora.initialized, "LoRa should be marked as initialized")
        self.assertIsNotNone(self.lora.hardware, "Hardware interface should be initialized")
        self.assertIsNotNone(self.lora.engine, "Engine should be initialized")
        
        # Verify hardware interface was created with correct parameters
        logger.info("7. Verifying hardware interface creation...")
        self.mock_hardware_class.assert_called_once_with(port='COM1', baudrate=9600)
        call_args, call_kwargs = self.mock_hardware_class.call_args
        self.assertEqual(call_kwargs.get('port'), 'COM1', "Port should be set to COM1")
        self.assertEqual(call_kwargs.get('baudrate'), 9600, "Baudrate should be 9600")
        
        # Verify adaptive engine was created with default config
        logger.info("8. Verifying adaptive engine creation...")
        self.mock_engine_class.assert_called_once()
        call_args, call_kwargs = self.mock_engine_class.call_args
        self.assertEqual(len(call_args), 1, "Engine should be created with one positional argument")
        
        config = call_args[0]
        expected_config = {
            "frequency": 915.0,
            "spreading_factor": 7,
            "tx_power": 14,
            "bandwidth": 125000,
            "coding_rate": "4/5",
            "region": "BR"
        }
        
        for key, value in expected_config.items():
            self.assertIn(key, config, f"Config should contain key: {key}")
            self.assertEqual(config[key], value, f"Config value for {key} should be {value}")
        
        # Verify the AT command was sent to check communication
        logger.info("9. Verifying AT command was sent...")
        self.mock_hardware.send_command.assert_called_once_with("AT")
    
    def test_initialize_failure(self):
        """Test initialization failure when hardware setup fails."""
        logger.info("=== Starting test_initialize_failure ===")
        
        # Configure the mock to raise an exception
        self.mock_hardware_class.side_effect = Exception("Hardware error")
        
        # Call the method under test
        logger.info("Calling initialize() with failing hardware...")
        result = self.lora.initialize(port='COM1', baud=9600)
        
        # Verify the result
        logger.info(f"initialize() returned: {result}")
        self.assertFalse(result, "initialize() should return False on failure")
        self.assertFalse(self.lora.initialized, "LoRa should not be marked as initialized")
        self.assertIsNone(self.lora.hardware, "Hardware should be None after failed initialization")
        self.assertIsNone(self.lora.engine, "Engine should be None after failed initialization")
    
    def test_send_success(self):
        """Test successful message sending."""
        logger.info("=== Starting test_send_success ===")
        
        # Reset mocks to ensure clean state
        self.mock_hardware.send_command.reset_mock()
        self.mock_hardware_class.reset_mock()
        self.mock_engine_class.reset_mock()
        
        # Configure the mock to return success for the AT command during initialization
        self.mock_hardware.send_command.return_value = (True, "OK")

        # Initialize the module
        logger.info("1. Initializing LoRa...")
        init_result = self.lora.initialize(port='COM1', baud=9600)
        self.assertTrue(init_result, "Initialization should succeed")
        self.assertTrue(self.lora.initialized, "LoRa should be initialized")
        
        # Reset mock to clear initialization calls
        self.mock_hardware.send_command.reset_mock()
        
        # Test message and expected length
        test_message = "TestMessage"
        expected_length = len(test_message)
        
        # Configure the mock for the send command
        # We'll use side_effect to handle multiple calls
        # Each call to send() makes 2 send_command calls: AT and AT+SEND
        self.mock_hardware.send_command.side_effect = [
            (True, "OK"),  # Response to AT
            (True, "OK"),  # Response to AT+SEND
            (True, "OK"),  # Response to AT (second call)
            (True, "OK")   # Response to AT+SEND (second call)
        ]
        
        logger.info(f"2. Sending message: {test_message}")
        logger.info(f"   Expected return value: {expected_length}")
        
        # First call to send()
        result = self.lora.send(test_message)
        
        # Verify the result
        logger.info(f"3. First send() returned: {result}")
        self.assertEqual(result, expected_length, "First send() should return length of sent message")
        
        # Verify the first set of commands were called correctly
        logger.info("4. Verifying first set of commands...")
        calls = self.mock_hardware.send_command.call_args_list
        
        # First call should be AT
        self.assertEqual(calls[0][0][0], "AT", 
                        "First call should be AT command")
        
        # Second call should be AT+SEND
        self.assertEqual(calls[1][0][0], f"AT+SEND={test_message}", 
                        "Second call should be AT+SEND command")
        
        # Second call to send()
        result = self.lora.send(test_message)
        
        # Verify the second result
        logger.info(f"5. Second send() returned: {result}")
        self.assertEqual(result, expected_length, 
                       f"Second send() should return {expected_length}, got {result}")
        
        # Verify all commands were called correctly
        logger.info("6. Verifying all commands...")
        calls = self.mock_hardware.send_command.call_args_list
        self.assertEqual(len(calls), 4, "Should have 4 total send_command calls (2 per send)")
        
        # Verify the second set of commands
        self.assertEqual(calls[2][0][0], "AT", 
                        "Third call should be AT command")
        self.assertEqual(calls[3][0][0], f"AT+SEND={test_message}", 
                        "Fourth call should be AT+SEND command")
        
        # Verify the send command was called correctly
        expected_call = f"AT+SEND={test_message}"
        actual_call = calls[1][0][0]  # Get the second call (AT+SEND)
        self.assertEqual(actual_call, expected_call, 
                        f"Expected call to be '{expected_call}', got '{actual_call}'")
    
    def test_send_not_initialized(self):
        """Test sending when not initialized."""
        # Don't initialize, just try to send
        message = "TestMessage"
        result = self.lora.send(message)
        
        # Should fail with -1
    
    def test_receive_not_initialized(self):
        """Test receiving when not initialized."""
        # Don't initialize, just try to receive
        result = self.lora.receive()
        
        # Should return None
        self.assertIsNone(result)
        self.mock_hardware.send_command.assert_not_called()
    
    def test_receive_error(self):
        """Test handling of receive errors."""
        # Initialize first
        self.lora.initialize(port='COM1', baud=9600)
        
        # Configure the mock to return an error
        self.mock_hardware.send_command.return_value = (False, "Error")
        
        # Call the method under test
        result = self.lora.receive()
        
        # Should return None on error
        self.assertIsNone(result)
    
    def test_receive_success(self):
        """Test successful message reception."""
        logger.info("=== Starting test_receive_success ===")
        
        # Reset mocks to ensure clean state
        self.mock_hardware.send_command.reset_mock()
        self.mock_hardware_class.reset_mock()
        self.mock_engine_class.reset_mock()
        
        # Configure the mock to return success for the AT command
        self.mock_hardware.send_command.return_value = (True, "OK")
        
        # Initialize the module
        logger.info("1. Initializing LoRa...")
        init_result = self.lora.initialize(port='COM1', baud=9600)
        self.assertTrue(init_result, "Initialization should succeed")
        
        # Reset mock to clear initialization calls
        self.mock_hardware.send_command.reset_mock()
        
        # Configure the mock to return a test message    
        test_message = "Hello, World!"
        mock_response = f"RECV,{test_message}"
        self.mock_hardware.send_command.return_value = (True, mock_response)
        
        logger.info(f"2. Receiving message with mock response: {mock_response}")
        
        # Call the method under test
        result = self.lora.receive()
        
        # Verify the result
        logger.info(f"3. receive() returned: {result}")
        self.assertEqual(result, test_message,
                       f"Expected to receive '{test_message}', got '{result}'")
        
        # Verify the receive command was called correctly
        self.mock_hardware.send_command.assert_called_once_with("AT+RECV")
    
    def test_receive_timeout(self):
        """Test receive with timeout parameter."""
        logger.info("=== Starting test_receive_timeout ===")
        
        # Reset mocks to ensure clean state
        self.mock_hardware.send_command.reset_mock()
        
        # Configure the mock to return success for the AT command during initialization
        self.mock_hardware.send_command.return_value = (True, "OK")
        
        # Initialize the module
        logger.info("1. Initializing LoRa...")
        init_result = self.lora.initialize(port='COM1', baud=9600)
        self.assertTrue(init_result, "Initialization should succeed")
        self.assertTrue(self.lora.initialized, "LoRa should be initialized")
        
        # Reset mock to clear initialization calls
        self.mock_hardware.send_command.reset_mock()
        
        # Configure the mock for the receive command
        test_message = "Test with timeout"
        self.mock_hardware.send_command.return_value = (True, f"RECV,{test_message}")
        
        # Call receive with timeout
        logger.info("2. Receiving message with timeout=5.0")
        result = self.lora.receive(timeout=5.0)
        
        # Verify the result
        logger.info(f"3. receive() returned: {result}")
        self.assertEqual(result, test_message, "Should return the received message")
        
        # Verify the command was called correctly
        logger.info("4. Verifying command was called...")
        self.mock_hardware.send_command.assert_called_once_with("AT+RECV")

if __name__ == '__main__':
    unittest.main()
