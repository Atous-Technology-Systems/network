"""
Test LoRa Optimizer - TDD Implementation
Testa o sistema de adaptação dinâmica de parâmetros LoRa
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
import time
from typing import Dict, List
import sys
from pathlib import Path

tests_dir = Path(__file__).parent.parent
sys.path.append(str(tests_dir))

from atous_sec_network.network.lora_optimizer import LoraAdaptiveEngine, LoraHardwareInterface
from mocks.gpio_mock import GPIO  # Import our GPIO mock


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
    
    def test_serial_communication_with_retry(self):
        """Tests serial communication with retry and validation"""
        with patch('atous_sec_network.network.lora_optimizer.GPIO') as mock_gpio, \
             patch('serial.Serial') as mock_serial, \
             patch('serial.tools.list_ports.comports') as mock_comports:
            # Setup GPIO mock
            mock_gpio.BCM = 11
            mock_gpio.OUT = 0
            mock_gpio.IN = 1
            mock_gpio.setmode = Mock()
            mock_gpio.setup = Mock()
            
            # Setup mock instance behavior
            mock_serial.return_value.write.return_value = 10
            mock_serial.return_value.in_waiting = True
            mock_serial.return_value.is_open = True
            
            # Setup port listing mock
            mock_comports.return_value = [Mock(device="COM1")]
            
            # Setup response sequence
            read_responses = [b'OK\r\n', b'ERROR\r\n', b'OK\r\n']
            response_iter = iter(read_responses)
            
            def mock_read(size=None):
                try:
                    return next(response_iter)
                except StopIteration:
                    return b''
                
            mock_serial.return_value.read = mock_read
            
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
    
    def test_gpio_initialization(self):
        """Tests GPIO initialization"""
        with patch('atous_sec_network.network.lora_optimizer.GPIO') as mock_gpio, \
             patch('serial.tools.list_ports.comports') as mock_comports, \
             patch('serial.Serial') as mock_serial:
            # Setup expected pin modes
            mock_gpio.BCM = 11
            mock_gpio.OUT = 0
            mock_gpio.IN = 1
            
            # Setup serial mock
            mock_serial.return_value.write.return_value = 10
            mock_serial.return_value.in_waiting = True
            mock_serial.return_value.is_open = True
            mock_serial.return_value.open = Mock()
            
            # Setup port listing mock
            mock_comports.return_value = [Mock(device="COM1")]
            
            # Create interface
            interface = LoraHardwareInterface()
            
            # Verify GPIO setup
            mock_gpio.setmode.assert_called_with(mock_gpio.BCM)
            mock_gpio.setup.assert_any_call(17, mock_gpio.OUT)  # Reset pin
            mock_gpio.setup.assert_any_call(18, mock_gpio.IN)   # Ready pin
    
    def test_at_command_validation(self):
        """Tests AT command validation"""
        with patch('atous_sec_network.network.lora_optimizer.GPIO') as mock_gpio, \
             patch('serial.Serial') as mock_serial, \
             patch('serial.tools.list_ports.comports') as mock_comports:
            
            # Setup GPIO mock
            mock_gpio.BCM = 11
            mock_gpio.OUT = 0
            mock_gpio.IN = 1
            mock_gpio.setmode = Mock()
            mock_gpio.setup = Mock()
            
            # Setup mock serial
            mock_serial.return_value.write.return_value = 10
            mock_serial.return_value.in_waiting = True
            mock_serial.return_value.is_open = True
            mock_serial.return_value.read.return_value = b'OK\r\n'
            mock_serial.return_value.open = Mock()
            
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
    
    def test_serial_pool_initialization(self):
        """Tests serial port pooling"""
        ports = ["/dev/ttyUSB0", "/dev/ttyUSB1", "COM1", "COM2"]
        
        with patch('atous_sec_network.network.lora_optimizer.GPIO') as mock_gpio, \
             patch('serial.Serial') as mock_serial, \
             patch('serial.tools.list_ports.comports') as mock_comports:
            
            # Setup GPIO mock
            mock_gpio.BCM = 11
            mock_gpio.OUT = 0
            mock_gpio.IN = 1
            mock_gpio.setmode = Mock()
            mock_gpio.setup = Mock()
            
            # Setup mock serial
            mock_serial.return_value.write.return_value = 10
            mock_serial.return_value.in_waiting = True
            mock_serial.return_value.is_open = True
            mock_serial.return_value.read.return_value = b'OK\r\n'
            mock_serial.return_value.open = Mock()
            
            # Setup port listing mock
            mock_comports.return_value = [Mock(device=p) for p in ports]
            
            # Create interface
            interface = LoraHardwareInterface()
            
            # Verify port enumeration
            mock_comports.assert_called_once()
            
            # Verify serial initialization with first port
            mock_serial.assert_called_once()
            self.assertEqual(mock_serial.call_args[1]['port'], "/dev/ttyUSB0")
    
    def test_checksum(self):
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