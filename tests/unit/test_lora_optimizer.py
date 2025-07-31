"""
Test LoRa Optimizer - TDD Implementation
Testa o sistema de adaptação dinâmica de parâmetros LoRa
"""
import unittest
from unittest.mock import Mock, patch, MagicMock, call
import time
from typing import Dict, List
import sys
from pathlib import Path
import io

# Add the tests directory to the path so we can import our mocks
tests_dir = Path(__file__).parent.parent
sys.path.append(str(tests_dir))

# Import our mocks first to ensure they're available for patching
from mocks.gpio_mock import GPIO  # Import our GPIO mock
from mocks.serial_mock import DummySerial, serial as mock_serial_module

# Now import the code under test
from atous_sec_network.network.lora_optimizer import LoraAdaptiveEngine, LoraHardwareInterface


class TestLoraOptimizer(unittest.TestCase):
    """Testa o sistema de otimização LoRa adaptativa"""
    
    def setUp(self):
        """Configuração inicial para cada teste"""
        self.base_config = {
            "frequency": 915.0,
            "spreading_factor": 7,
            "tx_power": 14,
            "bandwidth": 125000,
            "coding_rate": "4/5",
            "region": "BR"
        }
        self.engine = LoraAdaptiveEngine(self.base_config)
    
    def test_initial_configuration(self):
        """Testa se a configuração inicial é aplicada corretamente"""
        self.assertEqual(self.engine.config["spreading_factor"], 7)
        self.assertEqual(self.engine.config["tx_power"], 14)
        self.assertEqual(self.engine.config["region"], "BR")
    
    def test_region_specific_limits(self):
        """Testa limites específicos por região"""
        region_configs = {
            "BR": {"max_tx_power": 14, "max_duty_cycle": 0.1, "frequency": 915.0},
            "EU": {"max_tx_power": 14, "max_duty_cycle": 0.01, "frequency": 868.0},
            "US": {"max_tx_power": 30, "max_duty_cycle": 1.0, "frequency": 915.0}
        }
        
        for region, limits in region_configs.items():
            with self.subTest(region=region):
                config = self.base_config.copy()
                config["region"] = region
                engine = LoraAdaptiveEngine(config)
                self.assertEqual(engine.REGION_LIMITS[region], limits)


class TestLoraHardwareInterface(unittest.TestCase):
    """Testa interface com hardware LoRa"""
    
    @patch('atous_sec_network.network.lora_optimizer.GPIO')
    @patch('atous_sec_network.network.lora_optimizer.serial.Serial')
    @patch('atous_sec_network.network.lora_optimizer.serial.tools.list_ports.comports')
    def test_serial_communication_with_retry(self, mock_comports, mock_serial_constructor, mock_gpio):
        """Tests serial communication with retry and validation"""
        # Setup GPIO mock
        mock_gpio.BCM = 11
        mock_gpio.OUT = 1
        mock_gpio.IN = 0
        mock_gpio.HIGH = 1
        mock_gpio.LOW = 0
        mock_gpio.setmode = Mock()
        mock_gpio.setup = Mock()
        
        # Create a mock serial port
        mock_serial = MagicMock()
        mock_serial_constructor.return_value = mock_serial
        mock_serial.is_open = True
        
        # Setup port listing mock
        mock_comports.return_value = [Mock(device="COM1")]
        
        # Setup response sequence
        read_responses = [b'OK\r\n', b'ERROR\r\n', b'OK\r\n']
        mock_serial.read.side_effect = read_responses
        
        # Create hardware interface and test it
        interface = LoraHardwareInterface(port="COM1")
        
        # Test first command (should succeed)
        success, response = interface.send_command("AT")
        self.assertTrue(success, "First command should succeed")
        self.assertEqual(response, "OK", "First response should be OK")
        
        # Verify the command was sent correctly
        mock_serial.write.assert_called_with(b'AT\r\n')
        
        # Reset mock for next test
        mock_serial.write.reset_mock()
        
        # Test second command (should fail)
        success, response = interface.send_command("BAD")
        self.assertFalse(success, "Second command should fail")
        self.assertEqual(response, "ERROR", "Second response should be ERROR")
        
        # Verify the command was sent correctly
        mock_serial.write.assert_called_with(b'BAD\r\n')
        
        # Reset mock for next test
        mock_serial.write.reset_mock()
        
        # Test third command (should succeed)
        success, response = interface.send_command("AT")
        self.assertTrue(success, "Third command should succeed")
        self.assertEqual(response, "OK", "Third response should be OK")
        
        # Verify the command was sent correctly
        mock_serial.write.assert_called_with(b'AT\r\n')
        
        # Verify the serial port was opened and closed correctly
        mock_serial_constructor.assert_called_once_with(port="COM1", baudrate=9600, timeout=1)
        mock_serial.open.assert_called_once()
    
    @patch('atous_sec_network.network.lora_optimizer.GPIO')
    @patch('atous_sec_network.network.lora_optimizer.serial.Serial')
    @patch('atous_sec_network.network.lora_optimizer.serial.tools.list_ports.comports')
    def test_gpio_initialization(self, mock_comports, mock_serial_constructor, mock_gpio):
        """Tests GPIO initialization"""
        # Setup mock GPIO constants to match RPi.GPIO
        mock_gpio.BCM = 11
        mock_gpio.BOARD = 10
        mock_gpio.OUT = 1
        mock_gpio.IN = 0
        mock_gpio.HIGH = 1
        mock_gpio.LOW = 0
        
        # Create a mock serial port
        mock_serial = MagicMock()
        mock_serial_constructor.return_value = mock_serial
        mock_serial.is_open = True
        mock_serial.open = Mock()
        
        # Setup port listing mock
        mock_comports.return_value = [Mock(device="COM1")]
        
        # Create interface
        interface = LoraHardwareInterface()
        
        # Verify GPIO setup
        mock_gpio.setmode.assert_called_once_with(11)  # Should be called with GPIO.BCM (11)
        
        # Check that setup was called for both pins with correct modes
        setup_calls = [
            call(17, 1),  # Reset pin (17) as OUTPUT (1)
            call(18, 0)   # Ready pin (18) as INPUT (0)
        ]
        mock_gpio.setup.assert_has_calls(setup_calls, any_order=True)
        assert mock_gpio.setup.call_count == 2  # Should be called exactly twice
    
    @patch('atous_sec_network.network.lora_optimizer.GPIO')
    @patch('atous_sec_network.network.lora_optimizer.serial.Serial')
    @patch('atous_sec_network.network.lora_optimizer.serial.tools.list_ports.comports')
    def test_serial_pool_initialization(self, mock_comports, mock_serial_constructor, mock_gpio):
        """Tests serial pool initialization and management"""
        # Setup GPIO mock
        mock_gpio.BCM = 11
        mock_gpio.OUT = 1
        mock_gpio.IN = 0
        mock_gpio.HIGH = 1
        mock_gpio.LOW = 0
        mock_gpio.setmode = Mock()
        mock_gpio.setup = Mock()
        
        # Setup serial mock
        mock_serial = MagicMock()
        mock_serial_constructor.return_value = mock_serial
        mock_serial.is_open = True
        mock_serial.open = Mock()
        mock_serial.read.return_value = b'OK\r\n'
        # Setup port listing mock
        mock_comports.return_value = [Mock(device="COM1")]
        
        # Test with default pool size (1)
        interface = LoraHardwareInterface(port="COM1")
        self.assertEqual(len(interface._serial_pool), 1, "Default pool size should be 1")
        
        # Test with custom pool size
        pool_size = 3
        interface = LoraHardwareInterface(port="COM1", pool_size=pool_size)
        self.assertEqual(len(interface._serial_pool), pool_size, 
                        f"Pool size should be {pool_size}")
        
        # Verify all connections are initialized
        self.assertEqual(mock_serial_constructor.call_count, pool_size, 
                        f"Should create {pool_size} serial connections")
        
        # Verify all connections are opened
        self.assertEqual(mock_serial.open.call_count, pool_size, 
                        f"Should open {pool_size} serial connections")
        
        # Test getting a connection from the pool
        connection = interface._get_connection()
        self.assertIsNotNone(connection, "Should return a valid connection")
        
        # Test returning a connection to the pool
        interface._return_connection(connection)
        
        # Test getting multiple connections from the pool
        connections = []
        for _ in range(pool_size):
            conn = interface._get_connection()
            self.assertIsNotNone(conn, "Should return a valid connection")
            connections.append(conn)
        
        # Verify all connections are unique
        self.assertEqual(len(set(connections)), pool_size, 
                        "Should return unique connections from the pool")
        
        # Test getting a connection when pool is empty (should create a new one)
        extra_connection = interface._get_connection()
        self.assertIsNotNone(extra_connection, "Should return a valid connection")
        
        # Verify a new connection was created when pool was empty
        self.assertEqual(mock_serial_constructor.call_count, pool_size + 1, 
                        "Should create a new connection when pool is empty")
        
        # Test closing all connections
        interface.close()
        self.assertEqual(mock_serial.close.call_count, pool_size + 1, 
                        "Should close all connections")
    
    @patch('atous_sec_network.network.lora_optimizer.GPIO')
    @patch('atous_sec_network.network.lora_optimizer.serial.Serial')
    @patch('atous_sec_network.network.lora_optimizer.serial.tools.list_ports.comports')
    def test_at_command_validation(self, mock_comports, mock_serial_constructor, mock_gpio):
        """Tests AT command validation"""
        # Setup GPIO mock
        mock_gpio.BCM = 11
        mock_gpio.OUT = 1
        mock_gpio.IN = 0
        mock_gpio.HIGH = 1
        mock_gpio.LOW = 0
        mock_gpio.setmode = Mock()
        mock_gpio.setup = Mock()
        
        # Setup serial mock
        mock_serial = MagicMock()
        mock_serial_constructor.return_value = mock_serial
        mock_serial.is_open = True
        mock_serial.open = Mock()
        mock_serial.read.return_value = b'OK\r\n'
        # Setup port listing mock
        mock_comports.return_value = [Mock(device="COM1")]
        
        # Create interface
        interface = LoraHardwareInterface(port="COM1")
        
        # Test invalid commands
        invalid_commands = [
            "",                    # Empty command
            "   ",                 # Only whitespace
            None,                   # None command
            "AT+TEST=123",         # No checksum
            "AT+TEST=123*XX",      # Invalid checksum format
            "AT+TEST=123*1",       # Checksum too short
            "AT+TEST=123*123",     # Checksum too long
            "AT+TEST=123*XX*YY",   # Multiple checksums
            "AT+TEST=123*XX\r\n",  # Newline in command
            "AT+TEST=123*XX\n",    # Newline in command
            "AT+TEST=123*XX\r",    # Carriage return in command
            "AT+TEST=123*XX "       # Trailing space
        ]
        
        for cmd in invalid_commands:
            with self.subTest(cmd=cmd):
                with self.assertRaises(ValueError):
                    interface.validate_command(cmd)
        
        # Test valid commands (should not raise exceptions)
        # Calculate correct checksums for test commands
        valid_commands = [
            "AT",
            "AT+TEST=123*25",  # Correct checksum for AT+TEST=123
            "AT+MODE=TEST*16", # Correct checksum for AT+MODE=TEST
            "AT+POWER=14*59"   # Correct checksum for AT+POWER=14
        ]
        
        for cmd in valid_commands:
            with self.subTest(cmd=cmd):
                try:
                    interface.validate_command(cmd)
                except ValueError:
                    self.fail(f"Valid command raised ValueError: {cmd}")
        
        # Verify no commands were sent to the serial port during validation
        mock_serial.write.assert_not_called()
    
    @patch('atous_sec_network.network.lora_optimizer.GPIO')
    @patch('atous_sec_network.network.lora_optimizer.serial.Serial')
    @patch('atous_sec_network.network.lora_optimizer.serial.tools.list_ports.comports')
    def test_serial_pool_initialization(self, mock_comports, mock_serial_constructor, mock_gpio):
        """Tests serial port pooling"""
        ports = ["/dev/ttyUSB0", "/dev/ttyUSB1", "COM1", "COM2"]
        
        # Setup GPIO mock
        mock_gpio.BCM = 11
        mock_gpio.OUT = 0
        mock_gpio.IN = 1
        mock_gpio.setmode = Mock()
        mock_gpio.setup = Mock()
        
        # Create a mock serial port
        mock_serial = MagicMock()
        mock_serial_constructor.return_value = mock_serial
        mock_serial.is_open = True
        mock_serial.read.return_value = b'OK\r\n'
        
        # Setup port listing mock to return our test ports
        mock_comports.return_value = [Mock(device=p) for p in ports]
        
        # Create interface - this should try to initialize with the first port
        interface = LoraHardwareInterface()
        
        # Verify port enumeration was called
        mock_comports.assert_called_once()
        
        # Verify serial was initialized with the first available port
        mock_serial_constructor.assert_called_once()
        
        # Check the port used in the constructor call
        self.assertEqual(mock_serial_constructor.call_args[1]['port'], "/dev/ttyUSB0")
    
    @patch('atous_sec_network.network.lora_optimizer.GPIO')
    @patch('atous_sec_network.network.lora_optimizer.serial.Serial')
    @patch('atous_sec_network.network.lora_optimizer.serial.tools.list_ports.comports')
    def test_checksum(self, mock_comports, mock_serial_constructor, mock_gpio):
        """Tests checksum calculation for command validation"""
        # Setup GPIO mock
        mock_gpio.BCM = 11
        mock_gpio.OUT = 1
        mock_gpio.IN = 0
        mock_gpio.HIGH = 1
        mock_gpio.LOW = 0
        mock_gpio.setmode = Mock()
        mock_gpio.setup = Mock()
        
        # Setup serial mock
        mock_serial = MagicMock()
        mock_serial_constructor.return_value = mock_serial
        mock_serial.is_open = True
        mock_serial.open = Mock()
        
        # Setup port listing mock
        mock_comports.return_value = [Mock(device="COM1")]
        
        # Create interface
        interface = LoraHardwareInterface(port="COM1")
        
        # Test checksum calculation with various commands
        test_commands = [
            "AT+ADDR=1234",
            "AT+MODE=TEST",
            "AT+POWER=14"
        ]
        
        for cmd in test_commands:
            # Add checksum to the command
            cmd_with_checksum = interface.add_checksum(cmd)
            
            # Verify the checksum is correctly formatted
            self.assertTrue(cmd_with_checksum.startswith(cmd + "*"), 
                         f"Checksum should be appended to the command: {cmd}")
            self.assertEqual(len(cmd_with_checksum.split("*")[1]), 2, 
                          "Checksum should be 2 characters long")
            
            # Verify the checksum can be verified
            self.assertTrue(interface.verify_checksum(cmd_with_checksum),
                          f"Checksum verification failed for command: {cmd}")
            
            # Test tampering detection
            if len(cmd_with_checksum) > 3:  # Ensure we can safely tamper
                tampered_cmd = cmd_with_checksum[:-2] + "00"  # Change last 2 digits
                self.assertFalse(interface.verify_checksum(tampered_cmd),
                               f"Tampered command should fail verification: {tampered_cmd}")
        
        # Test edge cases
        with self.assertRaises(ValueError):
            interface.verify_checksum("*XX")  # No command before checksum
            
        with self.assertRaises(ValueError):
            interface.verify_checksum("AT+TEST")  # No checksum