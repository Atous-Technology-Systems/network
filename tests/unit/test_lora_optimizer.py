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
    @patch('serial.Serial')
    @patch('serial.tools.list_ports.comports')
    def test_serial_communication_with_retry(self, mock_comports, mock_serial_constructor, mock_gpio):
        """Tests serial communication with retry and validation"""
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
        
        # Test second command (should fail)
        success, response = interface.send_command("BAD")
        self.assertFalse(success, "Second command should fail")
        self.assertEqual(response, "ERROR", "Second response should be ERROR")
        
        # Test third command (should succeed)
        success, response = interface.send_command("AT")
        self.assertTrue(success, "Third command should succeed")
        self.assertEqual(response, "OK", "Third response should be OK")
    
    @patch('atous_sec_network.network.lora_optimizer.GPIO')
    @patch('serial.Serial')
    @patch('serial.tools.list_ports.comports')
    def test_gpio_initialization(self, mock_comports, mock_serial_constructor, mock_gpio):
        """Tests GPIO initialization"""
        # Setup expected pin modes
        mock_gpio.BCM = 11
        mock_gpio.OUT = 0
        mock_gpio.IN = 1
        
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
        mock_gpio.setmode.assert_called_with(mock_gpio.BCM)
        mock_gpio.setup.assert_any_call(17, mock_gpio.OUT)  # Reset pin
        mock_gpio.setup.assert_any_call(18, mock_gpio.IN)   # Ready pin
    
    @patch('atous_sec_network.network.lora_optimizer.GPIO')
    @patch('serial.Serial')
    @patch('serial.tools.list_ports.comports')
    def test_at_command_validation(self, mock_comports, mock_serial_constructor, mock_gpio):
        """Tests AT command validation"""
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
        
        # Setup port listing mock
        mock_comports.return_value = [Mock(device="COM1")]
        
        # Create interface and test
        interface = LoraHardwareInterface()
        
        # Test invalid commands
        with self.assertRaises(ValueError):
            interface.send_command("")  # Empty command
        with self.assertRaises(ValueError):
            interface.send_command("   ")  # Only whitespace
        with self.assertRaises(ValueError):
            interface.send_command(None)  # None command
    
    @patch('atous_sec_network.network.lora_optimizer.GPIO')
    @patch('serial.Serial')
    @patch('serial.tools.list_ports.comports')
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
    @patch('serial.Serial')
    @patch('serial.tools.list_ports.comports')
    def test_checksum(self, mock_comports, mock_serial_constructor, mock_gpio):
        """Tests checksum calculation for command validation"""
        with patch('atous_sec_network.network.lora_optimizer.GPIO') as mock_gpio, \
             patch('serial.Serial') as mock_serial, \
             patch('serial.tools.list_ports.comports') as mock_comports:
            
            # Setup GPIO mock
            mock_gpio.BCM = 11
            mock_gpio.OUT = 0
            mock_gpio.IN = 1
            mock_gpio.setmode = Mock()
            mock_gpio.setup = Mock()
            
            # Setup serial mock
            mock_serial.return_value.write.return_value = 10
            mock_serial.return_value.in_waiting = True
            mock_serial.return_value.is_open = True
            mock_serial.return_value.open = Mock()
            
            # Setup port listing mock
            mock_comports.return_value = [Mock(device="COM1")]
            interface = LoraHardwareInterface()
            
            # Test sample commands
            cmd = "AT+ADDR=1234"
            cmd_with_checksum = interface.add_checksum(cmd)
            self.assertTrue(interface.verify_checksum(cmd_with_checksum))
            
            # Test tampering detection
            tampered_cmd = cmd_with_checksum[:-2] + "00"  # Change last 2 digits
            self.assertFalse(interface.verify_checksum(tampered_cmd))