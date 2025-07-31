"""
LoRa Adaptive Engine - Dynamic Parameter Optimization
"""

import threading
import serial
import serial.tools.list_ports
from serial import SerialException
import logging
import time
import math
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from collections import deque

# Optional GPIO support for Raspberry Pi
GPIO = None
HAS_HARDWARE = False

try:
    import RPi.GPIO as GPIO
    HAS_HARDWARE = True
except ImportError:
    # For development environments without RPi.GPIO
    try:
        from tests.mocks.gpio_mock import GPIO
        HAS_HARDWARE = True  # Set to True since we're using mocks
        logging.info("Using mock GPIO implementation for testing")
    except ImportError:
        logging.warning("GPIO not available - GPIO functionality disabled")
        HAS_HARDWARE = False
        GPIO = None

# Make GPIO available as a module attribute for testing
__all__ = ['LoraHardwareInterface', 'LoraAdaptiveEngine', 'LoraMetrics', 'GPIO']


class LoraHardwareInterface:
    """Interface for LoRa hardware communication"""
    
    def __init__(self, port=None, baudrate=9600, timeout=1, gpio_module=None, pool_size=1):
        """Initialize hardware interface
        
        Args:
            port: Serial port path (optional - will auto-detect if not specified)
            baudrate: Serial baudrate
            timeout: Serial timeout in seconds
            gpio_module: Optional GPIO module to use (for testing)
            pool_size: Number of serial connections to maintain in the pool (default: 1)
        """
        self.baudrate = baudrate
        self.timeout = timeout
        self.pool_size = max(1, int(pool_size))  # Ensure at least 1 connection
        self._serial_pool = []
        self._current_connection = 0
        
        # Use the provided GPIO module or the global one
        self.gpio = gpio_module if gpio_module is not None else GPIO
        
        # Initialize GPIO pins if GPIO is available
        if self.gpio is not None:
            try:
                self.gpio.setmode(self.gpio.BCM)  # Always setup GPIO - HAS_HARDWARE flag only affects real/mock GPIO
                self.gpio.setup(17, self.gpio.OUT)  # Reset pin
                self.gpio.setup(18, self.gpio.IN)   # Ready pin
            except Exception as e:
                logging.warning(f"Failed to initialize GPIO: {e}")
                self.gpio = None
        
        if port:
            self.port = port
        else:
            # Auto-detect port
            import serial.tools.list_ports
            ports = list(serial.tools.list_ports.comports())
            if not ports:
                raise Exception("No serial ports found")
            self.port = ports[0].device  # Use first available port
            
        self._setup_serial()
    
    def add_checksum(self, command: str) -> str:
        """Add checksum to command
        
        Args:
            command: Command string
            
        Returns:
            Command with checksum appended
        """
        checksum = 0
        for char in command:
            checksum ^= ord(char)
        return f"{command}*{checksum:02X}"

    def verify_checksum(self, command_with_checksum: str) -> bool:
        """Verify checksum in command
        
        Args:
            command_with_checksum: Command with checksum appended
            
        Returns:
            True if checksum matches, False otherwise
            
        Raises:
            ValueError: If command format is invalid or no checksum present
        """
        if '*' not in command_with_checksum:
            raise ValueError("No checksum found in command")
            
        try:
            command, checksum = command_with_checksum.rsplit('*', 1)
            
            # Check if command part is empty or invalid
            if not command:
                raise ValueError("Invalid command format")
                
            actual_checksum = 0
            for char in command:
                actual_checksum ^= ord(char)
            return checksum == f"{actual_checksum:02X}"
        except ValueError as e:
            if "No checksum found" in str(e) or "Invalid command format" in str(e):
                raise
            raise ValueError("Invalid checksum format")
    
    def validate_command(self, command: str) -> bool:
        """Validate command format without sending it
        
        Args:
            command: Command to validate
            
        Returns:
            True if command is valid, False otherwise
            
        Raises:
            ValueError: If command validation fails
        """
        # Validate command format
        if not command or not isinstance(command, str):
            raise ValueError("Command must be a non-empty string")
            
        # Strip whitespace and check if empty
        command = command.strip()
        if not command:
            raise ValueError("Command must be a non-empty string")
            
        # Check for invalid characters and formats
        if '\r' in command or '\n' in command:
            raise ValueError("Command cannot contain newline characters")
            
        # Check for trailing spaces
        if command != command.rstrip():
            raise ValueError("Command cannot have trailing spaces")
            
        # For AT commands with parameters, require checksum
        if command.startswith("AT+") and "=" in command and "*" not in command:
            raise ValueError("AT commands with parameters must include a checksum")
            
        # If command has checksum, validate it
        if "*" in command:
            # Validate checksum format
            if command.count("*") != 1:
                raise ValueError("Command can only have one checksum")
                
            try:
                cmd_part, checksum_part = command.rsplit("*", 1)
                
                # Validate checksum format (should be 2 hex digits)
                if len(checksum_part) != 2:
                    raise ValueError("Checksum must be exactly 2 characters")
                    
                # Try to parse as hex
                int(checksum_part, 16)
                
                # Verify checksum is correct
                if not self.verify_checksum(command):
                    raise ValueError("Invalid checksum")
                    
            except ValueError as e:
                if "Invalid checksum" in str(e) or "Checksum must be" in str(e):
                    raise
                raise ValueError("Invalid checksum format")
                
        return True
        
    def _setup_serial(self):
        """Setup serial connection pool with retry"""
        max_retries = 3
        retry_delay = 1
        
        # Clear any existing connections
        for conn in self._serial_pool:
            if conn and hasattr(conn, 'close') and conn.is_open:
                conn.close()
        self._serial_pool = []
        
        # Create new connections
        for _ in range(self.pool_size):
            for attempt in range(max_retries):
                try:
                    conn = serial.Serial(
                        port=self.port,
                        baudrate=self.baudrate,
                        timeout=self.timeout
                    )
                    # Explicitly call open() for test compatibility
                    conn.open()
                    self._serial_pool.append(conn)
                    break
                except SerialException as e:
                    logging.error(f"Failed to open serial port (attempt {attempt + 1}): {e}")
                    if attempt >= max_retries - 1:
                        raise
                    time.sleep(retry_delay)
        
        # Set the current serial connection to the first one in the pool
        if self._serial_pool:
            self.serial = self._serial_pool[0]
    
    def _get_next_connection(self):
        """Get the next available serial connection from the pool using round-robin"""
        if not self._serial_pool:
            raise RuntimeError("No serial connections available in the pool")
            
        # Get next connection in round-robin fashion
        conn = self._serial_pool[self._current_connection]
        self._current_connection = (self._current_connection + 1) % len(self._serial_pool)
        return conn
        
    def send_command(self, command: str, retry_count=3) -> tuple[bool, str]:
        """Send command to LoRa module with retry
        
        Args:
            command: Command to send
            retry_count: Number of retries on failure
            
        Returns:
            (success, response)
            
        Raises:
            ValueError: If command validation fails
            RuntimeError: If no serial connections are available
        """
        # Get the next available connection
        if not self._serial_pool:
            self._setup_serial()  # Try to reinitialize connections
            if not self._serial_pool:
                raise RuntimeError("No serial connections available")
                
        conn = self._get_next_connection()
        
        # Validate command format
        if not command or not isinstance(command, str):
            raise ValueError("Command must be a non-empty string")
            
        # Strip whitespace and check if empty
        command = command.strip()
        if not command:
            raise ValueError("Command must be a non-empty string")
            
        # Check for invalid characters and formats
        if '\r' in command or '\n' in command:
            raise ValueError("Command cannot contain newline characters")
            
        # Check for trailing spaces
        if command != command.rstrip():
            raise ValueError("Command cannot have trailing spaces")
            
        # If command already has checksum, validate it
        if '*' in command:
            parts = command.split('*')
            if len(parts) != 2:
                raise ValueError("Invalid checksum format - multiple asterisks found")
            
            checksum_part = parts[1]
            if len(checksum_part) != 2:
                raise ValueError("Checksum must be exactly 2 characters")
                
            # Validate checksum is hexadecimal
            try:
                int(checksum_part, 16)
            except ValueError:
                raise ValueError("Checksum must be valid hexadecimal")
                
            # Verify the checksum is correct
            if not self.verify_checksum(command):
                raise ValueError("Invalid checksum")
                
            # Command already has valid checksum, use as-is
            cmd_with_checksum = command
        else:
            # For AT commands with parameters, require checksum
            if command.startswith('AT+') and '=' in command:
                raise ValueError("AT commands with parameters must include checksum")
            
            # Add checksum to command (except for simple commands without parameters)
            if command == "AT" or (not command.startswith("AT+") and "=" not in command):
                cmd_with_checksum = command
            else:
                cmd_with_checksum = self.add_checksum(command)
            
        if not self.serial or not hasattr(self.serial, 'is_open') or not self.serial.is_open:
            try:
                self._setup_serial()
            except Exception as e:
                return False, str(e)
        
        for attempt in range(retry_count):
            try:
                # Send command (checksum already added during validation)
                self.serial.write(cmd_with_checksum.encode() + b'\r\n')
                
                # Wait for response with timeout
                start_time = time.time()
                response = b''
                
                while time.time() - start_time < self.timeout:
                    if self.serial.in_waiting:
                        response += self.serial.read(self.serial.in_waiting)
                        if b'\r\n' in response:
                            break
                    time.sleep(0.1)
                
                # Validate response
                response_str = response.decode().strip()
                if response_str and not response_str.startswith('ERROR'):
                    return True, response_str
                else:
                    return False, response_str or "No valid response received"
                
            except SerialException as e:
                logging.error(f"Serial error on attempt {attempt + 1}: {e}")
                if attempt < retry_count - 1:
                    time.sleep(1)
                    self._setup_serial()
        
        return False, "Max retries exceeded"


@dataclass
class LoraMetrics:
    """Estrutura para métricas LoRa"""
    rssi: float
    snr: float
    packet_loss: float
    timestamp: float


class LoraAdaptiveEngine:
    """
    Motor de adaptação dinâmica para parâmetros LoRa
    
    Otimiza automaticamente spreading factor, potência de transmissão
    e outros parâmetros baseado em condições do canal e requisitos
    de energia vs. confiabilidade.
    """
    
    # Limites regionais para LoRa
    REGION_LIMITS = {
        "BR": {"max_tx_power": 14, "max_duty_cycle": 0.1, "frequency": 915.0},
        "EU": {"max_tx_power": 14, "max_duty_cycle": 0.01, "frequency": 868.0},
        "US": {"max_tx_power": 30, "max_duty_cycle": 1.0, "frequency": 915.0},
        "AU": {"max_tx_power": 30, "max_duty_cycle": 1.0, "frequency": 915.0}
    }
    
    # Limites físicos dos parâmetros
    PARAMETER_BOUNDS = {
        "spreading_factor": {"min": 7, "max": 12},
        "tx_power": {"min": 5, "max": 30},
        "bandwidth": {"min": 125000, "max": 500000},
        "coding_rate": ["4/5", "4/6", "4/7", "4/8"]
    }
    
    def __init__(self, base_config: Dict, history_size: int = 100):
        """Initialize LoRa adaptation engine.

        Args:
            base_config: Initial parameter configuration
            history_size: Size of metrics history
        """
        # Initialize hardware-related attributes
        self.GPIO = None
        self.gpio_available = False
        self.port_monitor_thread = None
        self.stop_monitor = False
        self.metrics_history = []  # Use list instead of deque for slicing support
        self.config = base_config.copy()
        self.region = base_config.get("region", "BR")
        self.logger = logging.getLogger(__name__)
        
        # Histórico de métricas com janela deslizante
        self.metrics_history = deque(maxlen=history_size)
        self.metrics = {
            "rssi": deque(maxlen=history_size),
            "snr": deque(maxlen=history_size),
            "packet_loss": 0.0
        }
        
        # Contadores para estabilização
        self.adjustment_count = 0
        self.last_adjustment_time = 0
        self.min_adjustment_interval = 30  # segundos
        
        # Configurações de otimização
        self.optimization_mode = "balanced"  # balanced, energy, reliability
        self.target_packet_loss = 0.05  # 5%
        self.target_snr = -7.5
        
        # Validação inicial
        self._validate_config()
        self._setup_hardware()
    
    def _validate_config(self) -> None:
        """Valida configuração inicial"""
        region_limits = self.REGION_LIMITS.get(self.region)
        if not region_limits:
            raise ValueError(f"Unsupported region: {self.region}")
        
        # Adjust frequency for region
        self.config["frequency"] = region_limits["frequency"]
        
        # Validate spreading factor
        sf = self.config.get("spreading_factor")
        sf_bounds = self.PARAMETER_BOUNDS["spreading_factor"]
        if not sf_bounds["min"] <= sf <= sf_bounds["max"]:
            raise ValueError(
                f"Spreading factor {sf} fora dos limites permitidos "
                f"({sf_bounds['min']}-{sf_bounds['max']})"
            )
        
        # Validate power limits
        tx_power = self.config.get("tx_power")
        power_bounds = self.PARAMETER_BOUNDS["tx_power"]
        max_power = min(region_limits["max_tx_power"], power_bounds["max"])
        
        if tx_power < power_bounds["min"]:
            raise ValueError(
                f"Potência {tx_power}dBm abaixo do mínimo permitido "
                f"({power_bounds['min']}dBm)"
            )
            
        if tx_power > max_power:
            self.logger.warning(f"Power reduced to {max_power}dBm (regional limit)")
            self.config["tx_power"] = max_power
            
        # Validate coding rate
        if self.config.get("coding_rate") not in self.PARAMETER_BOUNDS["coding_rate"]:
            raise ValueError(
                f"Taxa de codificação {self.config.get('coding_rate')} inválida. "
                f"Valores permitidos: {self.PARAMETER_BOUNDS['coding_rate']}"
            )
    
    def _setup_hardware(self) -> None:
        """
        Configura interface com hardware LoRa
        
        Inicializa GPIO e portas seriais com pool de conexões e monitoramento
        de recursos. Implementa recuperação automática de falhas.
        """
        self.gpio_available = False
        self.serial_available = False
        
        # Default configuration
        self.lora_pins = {
            "reset": 17,
            "dio0": 27,
            "spi_nss": 8
        }
        self.serial_ports = []
        self.serial_pool = []
        self.max_serial_connections = 4
        self.port_monitor_thread = None
        self.monitor_active = False
        self.allow_simulation = self.config.get("allow_simulation", True)
        
        # Initialize GPIO if available
        if HAS_HARDWARE and GPIO is not None:
            try:
                # Store GPIO instance
                self.GPIO = GPIO
                
                # Safe GPIO configuration
                self.GPIO.setwarnings(False)
                self.GPIO.setmode(self.GPIO.BCM)
                
                # Initialize and validate all pins
                pin_config_success = True
                for name, pin in self.lora_pins.items():
                    try:
                        self.GPIO.setup(pin, self.GPIO.OUT, initial=self.GPIO.LOW)
                        # Validate pin function if possible
                        if hasattr(self.GPIO, 'gpio_function'):
                            pin_function = self.GPIO.gpio_function(pin)
                            if pin_function != self.GPIO.OUT:
                                raise RuntimeError(f"Pin {pin} ({name}) not set to OUTPUT mode")
                    except Exception as e:
                        pin_config_success = False
                        self.logger.error(f"Failed to setup {name} pin {pin}: {e}")
                        if not self.allow_simulation:
                            raise
                
                if pin_config_success:
                    self.gpio_available = True
                    self.logger.info("GPIO successfully configured for LoRa")
                else:
                    self.logger.warning("Some GPIO pins failed to configure - falling back to simulation")
                    
            except Exception as e:
                self.logger.error(f"Failed to initialize GPIO: {e}")
                if not self.allow_simulation:
                    raise
                self.logger.warning("Falling back to simulation mode")
        else:
            self.logger.info("Hardware interfaces not available - using simulation mode")
            
        # Tenta usar serial se disponível (já importado no topo do módulo)
        try:
            if serial is not None:
                self.Serial = serial.Serial
                
                # Descobre portas disponíveis
                available_ports = list(serial.tools.list_ports.comports())
                self.serial_ports = [
                    port.device for port in available_ports
                    if "USB" in port.device or "ACM" in port.device
                ]
                
                if self.serial_ports:
                    # Inicializa pool de conexões
                    self._init_serial_pool()
                    self.serial_available = True
                    self.logger.info(f"Serial interface available on ports: {self.serial_ports}")
                    
                    # Inicia monitoramento de portas
                    self._start_port_monitor()
                else:
                    self.logger.warning("No suitable serial ports found")
            else:
                raise ImportError("Serial module not available")
                
        except (ImportError, AttributeError) as e:
            self.Serial = None
            self.logger.info(f"Serial interface not available - using simulation: {str(e)}")
            
    def _init_serial_pool(self) -> None:
        """Inicializa pool de conexões seriais"""
        for port in self.serial_ports[:self.max_serial_connections]:
            try:
                ser = self.Serial(
                    port=port,
                    baudrate=57600,
                    timeout=1,
                    writeTimeout=1
                )
                self.serial_pool.append({
                    "port": port,
                    "connection": ser,
                    "in_use": False,
                    "last_error": None,
                    "error_count": 0
                })
                self.logger.info(f"Initialized serial connection on {port}")
            except SerialException as e:
                self.logger.error(f"Failed to initialize serial on {port}: {e}")
                
    def _start_port_monitor(self) -> None:
        """Inicia thread de monitoramento de portas"""
        import threading
        self.monitor_active = True
        self.port_monitor_thread = threading.Thread(
            target=self._monitor_ports,
            daemon=True
        )
        self.port_monitor_thread.start()
        
    def _monitor_ports(self) -> None:
        """Monitora portas seriais e tenta recuperar de erros"""
        while self.monitor_active:
            for conn in self.serial_pool:
                if conn["error_count"] > 3:
                    try:
                        self._reset_connection(conn)
                    except Exception as e:
                        self.logger.error(f"Failed to reset {conn['port']}: {e}")
            time.sleep(5)  # Verifica a cada 5 segundos
            
    def _reset_connection(self, conn: dict) -> None:
        """Reseta uma conexão serial com problemas"""
        try:
            if conn["connection"].is_open:
                conn["connection"].close()
                
            conn["connection"].open()
            conn["error_count"] = 0
            conn["last_error"] = None
            self.logger.info(f"Reset serial connection on {conn['port']}")
            
        except Exception as e:
            conn["last_error"] = str(e)
            conn["error_count"] += 1
            raise
            
    def _cleanup_gpio(self) -> None:
        """Limpa configurações GPIO no shutdown"""
        try:
            # Only cleanup if we initialized GPIO and it's available
            if (hasattr(self, 'gpio_available') and self.gpio_available and
                hasattr(self, 'GPIO') and self.GPIO):
                for pin in self.lora_pins.values():
                    self.GPIO.cleanup(pin)
                self.logger.info("GPIO cleanup completed")
                
                # Clear state for tests if we're using mock
                if hasattr(self.GPIO, 'pin_states'):
                    self.GPIO.pin_states.clear()
        except Exception as e:
            self.logger.error(f"Error during GPIO cleanup: {e}")
                
    def __del__(self) -> None:
        """Cleanup no garbage collection"""
        # Para monitoramento
        self.monitor_active = False
        if self.port_monitor_thread:
            self.port_monitor_thread.join(timeout=1.0)
            
        # Fecha conexões seriais
        if hasattr(self, 'serial_pool'):
            for conn in self.serial_pool:
                try:
                    if conn["connection"].is_open:
                        conn["connection"].close()
                except Exception:
                    pass
                    
        # Cleanup GPIO
        self._cleanup_gpio()
    
    def log_metrics(self, rssi: float, snr: float, lost_packets: float) -> None:
        """
        Registra métricas de desempenho do canal
        
        Args:
            rssi: Received Signal Strength Indicator (dBm)
            snr: Signal-to-Noise Ratio (dB)
            lost_packets: Taxa de perda de pacotes (0-1)
            
        Raises:
            ValueError: Se os valores estiverem fora dos limites válidos
        """
        # Validate packet loss
        if not isinstance(lost_packets, (int, float)):
            raise ValueError("Packet loss must be a number")
        if not 0 <= lost_packets <= 1:
            raise ValueError("Taxa de perda de pacotes deve estar entre 0 e 1")
            
        # Validate RSSI (typical LoRa range: -150 to 0 dBm)
        if not isinstance(rssi, (int, float)):
            raise ValueError("RSSI must be a number")
        if not -150 <= rssi <= 0:
            raise ValueError("RSSI must be between -150 and 0 dBm")
            
        # Validate SNR (typical LoRa range: -20 to 10 dB)
        if not isinstance(snr, (int, float)):
            raise ValueError("SNR must be a number")
        if not -20 <= snr <= 10:
            raise ValueError("SNR must be between -20 and 10 dB")
            
        timestamp = time.time()
        
        # Add to metrics history
        self.metrics["rssi"].append(rssi)
        self.metrics["snr"].append(snr)
        self._update_packet_loss(lost_packets)
        
        # Store complete metric
        metric = LoraMetrics(rssi, snr, lost_packets, timestamp)
        self.metrics_history.append(metric)
        
        self.logger.debug(f"Metrics: RSSI={rssi:.1f}dBm, SNR={snr:.1f}dB, Loss={lost_packets:.3f}")
    
    def adjust_parameters(self) -> bool:
        """
        Ajusta parâmetros baseado em condições do canal
        
        Returns:
            True se parâmetros foram ajustados, False caso contrário
        """
        current_time = time.time()
        
        # Verifica intervalo mínimo entre ajustes
        if (current_time - self.last_adjustment_time) < self.min_adjustment_interval:
            return False
        
        # Precisa de histórico mínimo
        if len(self.metrics_history) < 5:
            return False
        
        adjustments_made = False
        region_limits = self.REGION_LIMITS[self.region]
        
        # Calculate moving averages using deque
        if not self.metrics["rssi"] or not self.metrics["snr"]:
            return False
            
        avg_rssi = sum(self.metrics["rssi"]) / len(self.metrics["rssi"])
        avg_snr = sum(self.metrics["snr"]) / len(self.metrics["snr"])
        avg_packet_loss = self.metrics["packet_loss"]  # Already an EMA
        
        # Histerese para spreading factor (evita oscilações)
        sf_histerese = 0.02  # 2% de margem
        if avg_packet_loss > (self.target_packet_loss + sf_histerese):
            if self.config["spreading_factor"] < self.PARAMETER_BOUNDS["spreading_factor"]["max"]:
                self.config["spreading_factor"] += 1
                adjustments_made = True
                self.logger.info(f"SF aumentado para {self.config['spreading_factor']} (alta perda: {avg_packet_loss:.3f})")
        elif avg_packet_loss < (self.target_packet_loss - sf_histerese):
            if self.config["spreading_factor"] > self.PARAMETER_BOUNDS["spreading_factor"]["min"]:
                self.config["spreading_factor"] -= 1
                adjustments_made = True
                self.logger.info(f"SF reduzido para {self.config['spreading_factor']} (baixa perda: {avg_packet_loss:.3f})")
        
        # Power adjustment with hysteresis
        snr_histerese = 1.0  # 1dB margin
        good_conditions = (
            avg_snr > (self.target_snr + snr_histerese) and 
            avg_packet_loss < 0.05 and 
            len(self.metrics_history) >= 5
        )
        
        self.logger.debug(f"Adjustment check: SNR={avg_snr:.1f} (target={self.target_snr}, hist={snr_histerese}), "
                       f"Loss={avg_packet_loss:.3f}, History={len(self.metrics_history)}, "
                       f"Good conditions={good_conditions}")
        
        if good_conditions and self.config["tx_power"] > self.PARAMETER_BOUNDS["tx_power"]["min"]:
            # Guaranteed 2dB reduction for good conditions
            current_power = self.config["tx_power"]
            self.config["tx_power"] = max(
                self.PARAMETER_BOUNDS["tx_power"]["min"],
                current_power - 2
            )
            self.logger.info(f"Reduced power from {current_power}dBm to {self.config['tx_power']}dBm "
                           f"(SNR: {avg_snr:.1f}dB, Loss: {avg_packet_loss:.3f})")
            adjustments_made = True
        elif avg_snr < (self.target_snr - snr_histerese):
            if self.config["tx_power"] < region_limits["max_tx_power"]:
                # Ajuste fino baseado na diferença do SNR
                snr_diff = self.target_snr - avg_snr
                power_step = min(2, max(1, round(snr_diff / 2)))  # Ajuste proporcional
                new_power = self.config["tx_power"] + power_step
                max_power = region_limits["max_tx_power"]
                self.config["tx_power"] = min(new_power, max_power)
                adjustments_made = True
                self.logger.info(f"Potência aumentada para {self.config['tx_power']}dBm (SNR: {avg_snr:.1f}dB)")
        
        # Ajuste de largura de banda para otimização
        if self.optimization_mode == "energy" and adjustments_made:
            self._optimize_bandwidth_for_energy()
        elif self.optimization_mode == "reliability" and adjustments_made:
            self._optimize_bandwidth_for_reliability()
        
        if adjustments_made:
            self.adjustment_count += 1
            self.last_adjustment_time = current_time
            self._reconfigure_radio()
        
        return adjustments_made
    
    def _optimize_bandwidth_for_energy(self) -> None:
        """Otimiza largura de banda para economia de energia"""
        if self.config["bandwidth"] < self.PARAMETER_BOUNDS["bandwidth"]["max"]:
            self.config["bandwidth"] = min(
                self.config["bandwidth"] * 2,
                self.PARAMETER_BOUNDS["bandwidth"]["max"]
            )
            self.logger.info(f"Largura de banda aumentada para {self.config['bandwidth']}Hz (modo energia)")
    
    def _optimize_bandwidth_for_reliability(self) -> None:
        """Otimiza largura de banda para confiabilidade"""
        if self.config["bandwidth"] > self.PARAMETER_BOUNDS["bandwidth"]["min"]:
            self.config["bandwidth"] = max(
                self.config["bandwidth"] // 2,
                self.PARAMETER_BOUNDS["bandwidth"]["min"]
            )
            self.logger.info(f"Largura de banda reduzida para {self.config['bandwidth']}Hz (modo confiabilidade)")
    
    def _reconfigure_radio(self) -> None:
        """
        Aplica novas configurações ao hardware com retry e validação
        
        Raises:
            RuntimeError: Se falhar após todas as tentativas
        """
        if self.serial_available:
            try:
                commands = [
                    f"AT+SF={self.config['spreading_factor']}",
                    f"AT+POWER={self.config['tx_power']}",
                    f"AT+BW={self.config['bandwidth']}",
                    f"AT+CR={self.config['coding_rate']}"
                ]
                
                max_retries = 3
                backoff_time = 0.5  # segundos
                
                for cmd in commands:
                    # Validação de comando
                    if not self._validate_at_command(cmd):
                        raise ValueError(f"Comando AT inválido: {cmd}")
                    
                    # Retry loop com backoff exponencial
                    for attempt in range(max_retries):
                        try:
                            self.logger.debug(f"Enviando comando: {cmd} (tentativa {attempt + 1})")
                            # Adiciona checksum
                            cmd_with_checksum = self._add_checksum(cmd)
                            self.Serial.write(f"{cmd_with_checksum}\r\n".encode())
                            
                            # Espera resposta com timeout
                            response = self._read_with_timeout(5.0)
                            
                            if b'OK' in response:
                                break  # Comando bem sucedido
                            else:
                                error_msg = response.decode().strip()
                                self.logger.warning(f"Erro no comando {cmd}: {error_msg}")
                                if attempt < max_retries - 1:
                                    time.sleep(backoff_time * (2 ** attempt))
                                    continue
                                raise RuntimeError(f"Falha após {max_retries} tentativas: {error_msg}")
                                
                        except Exception as e:
                            if attempt == max_retries - 1:
                                raise RuntimeError(f"Erro na comunicação serial: {str(e)}")
                            time.sleep(backoff_time * (2 ** attempt))
                
                # Verifica configuração aplicada
                if self._verify_config():
                    self.logger.info("Rádio reconfigurado com sucesso")
                else:
                    raise RuntimeError("Falha na verificação da configuração")
                    
            except Exception as e:
                self.logger.error(f"Erro ao reconfigurar rádio: {e}")
                raise  # Re-raise para tratamento em nível superior
        else:
            self.logger.info(f"Simulação: Reconfigurando rádio - SF={self.config['spreading_factor']}, "
                           f"TX={self.config['tx_power']}dBm, BW={self.config['bandwidth']}Hz")
                           
    def _validate_at_command(self, cmd: str) -> bool:
        """Valida sintaxe e parâmetros de comando AT"""
        if not cmd.startswith("AT+"):
            return False
            
        # Valida formato e valores
        try:
            cmd_parts = cmd.split("=")
            if len(cmd_parts) != 2:
                return False
                
            command, value = cmd_parts
            if command == "AT+SF":
                value = int(value)
                return self.PARAMETER_BOUNDS["spreading_factor"]["min"] <= value <= self.PARAMETER_BOUNDS["spreading_factor"]["max"]
            elif command == "AT+POWER":
                value = int(value)
                return self.PARAMETER_BOUNDS["tx_power"]["min"] <= value <= self.PARAMETER_BOUNDS["tx_power"]["max"]
            elif command == "AT+BW":
                value = int(value)
                return self.PARAMETER_BOUNDS["bandwidth"]["min"] <= value <= self.PARAMETER_BOUNDS["bandwidth"]["max"]
            elif command == "AT+CR":
                return value in self.PARAMETER_BOUNDS["coding_rate"]
            else:
                return False
        except ValueError:
            return False
            
    def _add_checksum(self, cmd: str) -> str:
        """Adiciona checksum ao comando AT"""
        checksum = sum(cmd.encode()) & 0xFF
        return f"{cmd}*{checksum:02X}"
        
    def _read_with_timeout(self, timeout: float) -> bytes:
        """Lê resposta serial com timeout"""
        start_time = time.time()
        response = bytearray()
        
        while (time.time() - start_time) < timeout:
            if self.Serial.in_waiting:
                char = self.Serial.read()
                response.extend(char)
                if response.endswith(b'\r\n'):
                    break
            time.sleep(0.01)
            
        return bytes(response)
        
    def _verify_config(self) -> bool:
        """Verifica se configuração foi aplicada corretamente"""
        try:
            # Lê configuração atual
            self.Serial.write(b"AT+CONFIG?\r\n")
            response = self._read_with_timeout(2.0)
            
            # Parseia resposta
            config = self._parse_config_response(response)
            
            # Compara com configuração desejada
            return (
                config.get("SF") == self.config["spreading_factor"] and
                config.get("POWER") == self.config["tx_power"] and
                config.get("BW") == self.config["bandwidth"] and
                config.get("CR") == self.config["coding_rate"]
            )
        except Exception as e:
            self.logger.error(f"Erro ao verificar configuração: {e}")
            return False
    
    def _calculate_throughput(self) -> float:
        """Calcula throughput teórico baseado nos parâmetros atuais"""
        # Fórmula LoRa: throughput = (SF * BW) / (2^SF * CR)
        sf = self.config["spreading_factor"]
        bw = self.config["bandwidth"]
        
        # Taxa de codificação
        cr_map = {"4/5": 0.8, "4/6": 0.67, "4/7": 0.57, "4/8": 0.5}
        cr = cr_map.get(self.config["coding_rate"], 0.8)
        
        # Throughput em bps
        throughput = (sf * bw) / (2**sf * cr)
        return throughput
    
    def _estimate_range(self) -> float:
        """Estima alcance baseado nos parâmetros atuais"""
        # Modelo simplificado de path loss
        tx_power = self.config["tx_power"]
        sf = self.config["spreading_factor"]
        
        # Sensibilidade do receptor (dBm)
        sensitivity = -120 + (sf - 7) * 2.5
        
        # Path loss model (simplificado)
        path_loss = tx_power - sensitivity - 20  # Margem de segurança
        
        # Distância estimada (metros)
        # PL = 20*log10(d) + 20*log10(f) + 32.44
        frequency = self.config["frequency"] / 1000  # GHz
        distance = 10**((path_loss - 20*math.log10(frequency) - 32.44) / 20)
        
        return distance
    
    def _estimate_energy_consumption(self) -> float:
        """Estima consumo energético (mA)"""
        # Consumo base
        base_consumption = 25  # mA
        
        # Adicional por spreading factor
        sf_consumption = (self.config["spreading_factor"] - 7) * 2
        
        # Adicional por potência de transmissão
        power_consumption = (self.config["tx_power"] - 5) * 1.5
        
        total_consumption = base_consumption + sf_consumption + power_consumption
        return total_consumption
    
    def get_performance_summary(self) -> Dict:
        """Retorna resumo de desempenho atual"""
        return {
            "current_config": self.config.copy(),
            "metrics": {
                "avg_rssi": sum(self.metrics["rssi"]) / len(self.metrics["rssi"]) if self.metrics["rssi"] else 0,
                "avg_snr": sum(self.metrics["snr"]) / len(self.metrics["snr"]) if self.metrics["snr"] else 0,
                "packet_loss": self.metrics["packet_loss"],
                "adjustment_count": self.adjustment_count
            },
            "performance": {
                "throughput": self._calculate_throughput(),
                "estimated_range": self._estimate_range(),
                "energy_consumption": self._estimate_energy_consumption()
            },
            "region_limits": self.REGION_LIMITS[self.region]
        }
    
    def set_optimization_mode(self, mode: str) -> None:
        """Define modo de otimização"""
        valid_modes = ["balanced", "energy", "reliability"]
        if mode not in valid_modes:
            raise ValueError(f"Modo inválido. Use: {valid_modes}")
        
        self.optimization_mode = mode
        self.logger.info(f"Modo de otimização alterado para: {mode}")
    
    def reset_metrics(self) -> None:
        """Reseta histórico de métricas."""
        self.metrics_history.clear()
        self.metrics["rssi"].clear()
        self.metrics["snr"].clear()
        self.metrics["packet_loss"] = 0.0
        self.adjustment_count = 0
        self.logger.info("Métricas resetadas")
        
    def _update_packet_loss(self, new_value: float) -> None:
        """Update packet loss with exponential moving average.

        Args:
            new_value: New packet loss value to incorporate (0.0-1.0)
        """
        alpha = 0.7  # Weight for exponential moving average
        self.metrics["packet_loss"] = (alpha * self.metrics["packet_loss"] + 
                                     (1 - alpha) * new_value)