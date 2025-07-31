"""
LoRa Optimizer - Compatibility Layer

This module provides backward compatibility with the old LoRaOptimizer interface
while using the new LoraAdaptiveEngine implementation.
"""
from typing import Optional
import logging
from .lora_optimizer import LoraAdaptiveEngine, LoraHardwareInterface

logger = logging.getLogger(__name__)

class LoRaOptimizer:
    """Compatibility wrapper for LoRaOptimizer that uses LoraAdaptiveEngine"""
    
    def __init__(self):
        """Initialize the LoRa optimizer with default settings"""
        self.initialized = False
        self.engine = None
        self.hardware = None
        self.port = None
        self.baud = None
        self.frequency = 915.0  # Default frequency in MHz
        self.power = 14  # Default power in dBm
        self.spreading_factor = 7  # Default spreading factor
        
    def initialize(self, port: str, baud: int = 9600) -> bool:
        """Initialize the LoRa hardware interface
        
        Args:
            port: Serial port to use for communication
            baud: Baud rate for serial communication
            
        Returns:
            bool: True if initialization was successful, False otherwise
        """
        logger.debug(f"Initializing LoRa with port={port}, baud={baud}")
        
        try:
            self.port = port
            self.baud = baud
            
            logger.debug("Creating LoraHardwareInterface instance")
            # Initialize hardware interface
            self.hardware = LoraHardwareInterface(port=port, baudrate=baud)
            logger.debug(f"Hardware interface created: {self.hardware}")
            
            # Initialize adaptive engine with default config
            config = {
                "frequency": 915.0,
                "spreading_factor": 7,
                "tx_power": 14,
                "bandwidth": 125000,
                "coding_rate": "4/5",
                "region": "BR"
            }
            logger.debug(f"Creating LoraAdaptiveEngine with config: {config}")
            self.engine = LoraAdaptiveEngine(config)
            logger.debug(f"Engine created: {self.engine}")
            
            # Test communication (this should work with mocks)
            logger.debug("Sending AT command to test communication")
            result = self.hardware.send_command("AT")
            logger.debug(f"AT command result: {result}")
            
            # Handle both tuple and single value returns
            if isinstance(result, tuple) and len(result) == 2:
                success, response = result
            else:
                success, response = (True, result)
            
            logger.debug(f"AT command response - success: {success}, response: {response}")
            
            if not success:
                logger.error(f"AT command failed. Response: {response}")
                self.initialized = False
                return False
                
            # Set initialized flag only after successful communication test
            self.initialized = True
            logger.debug("LoRa initialization successful")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize LoRa: {e}", exc_info=True)
            self.initialized = False
            return False
    
    def send_data(self, message) -> bool:
        """Send data via LoRa
        
        Args:
            message: Data to send
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.initialized or not self.hardware:
            return False
            
        try:
            # First try the direct send method if available
            if hasattr(self.hardware, 'send'):
                result = self.hardware.send(message)
                # Handle both boolean and integer returns
                if isinstance(result, bool):
                    return result
                elif isinstance(result, int):
                    return result > 0
                else:
                    return bool(result)
            else:
                # Fall back to the old send method
                result = self.send(message)
                return result > 0
        except Exception as e:
            logger.error(f"Error in send_data: {e}")
            return False
            
    def send(self, message: str) -> int:
        """Send a message via LoRa
        
        Args:
            message: Message to send
            
        Returns:
            int: Number of bytes sent, or -1 on failure
        """
        logger.debug(f"send() called with message: {message}")
        
        if not self.initialized or not self.hardware:
            error_msg = "LoRa not initialized"
            logger.error(error_msg)
            return -1
            
        try:
            # Convert message to string if needed
            if not isinstance(message, str):
                message = str(message)
                
            # Get the expected message length for the response
            msg_len = len(message)
            
            # Send AT command first
            logger.debug("Sending AT command")
            at_success, at_response = self.hardware.send_command("AT")
            logger.debug(f"AT command response: success={at_success}, response={at_response}")
            
            if not at_success or at_response != "OK":
                logger.error(f"AT command failed: {at_response}")
                return -1
            
            # Send the actual message
            cmd = f"AT+SEND={message}"
            logger.debug(f"Sending command: {cmd}")
            
            # Send the message and get response
            success, response = self.hardware.send_command(cmd)
            logger.debug(f"send_command() returned: success={success}, response={response}")
            
            # For test compatibility, return len(message) on success, -1 on failure
            if success and (response == "OK" or response is None):
                logger.debug(f"Message sent successfully, returning length: {msg_len}")
                return msg_len
            
            logger.warning(f"Message send failed. Success: {success}, Response: {response}")
            return -1
                
        except Exception as e:
            logger.error(f"Error sending message: {e}", exc_info=True)
            return -1
    
    def receive_data(self, timeout: float = 1.0):
        """Receive data via LoRa
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            Data received, or None if no data or error
        """
        if not self.initialized or not self.hardware:
            return None
            
        try:
            # First try the direct receive method if available
            if hasattr(self.hardware, 'receive'):
                result = self.hardware.receive(timeout)
                return result
            else:
                # Fall back to the old receive method
                return self.receive(timeout)
        except Exception as e:
            logger.error(f"Error in receive_data: {e}")
            return None
            
    def receive(self, timeout: float = 1.0) -> Optional[str]:
        """Receive a message via LoRa
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            str: Received message, or None if no message or error
        """
        logger.debug(f"receive() called with timeout: {timeout}")
        
        if not self.initialized or not self.hardware:
            logger.error("LoRa not initialized")
            return None
            
        try:
            # Save original timeout
            original_timeout = None
            if hasattr(self.hardware, 'serial') and hasattr(self.hardware.serial, 'timeout'):
                original_timeout = self.hardware.serial.timeout
                self.hardware.serial.timeout = timeout
                logger.debug(f"Set serial timeout to {timeout}")
            
            # Read data - handle both response formats: (success, response) and just response
            logger.debug("Calling send_command('AT+RECV')")
            
            if hasattr(self.hardware, 'send_command'):
                result = self.hardware.send_command("AT+RECV")
                logger.debug(f"send_command() returned: {result}")
                
                if isinstance(result, tuple) and len(result) == 2:
                    success, response = result
                else:
                    success, response = (True, result)
            else:
                success, response = (False, None)
            
            logger.debug(f"Parsed response - success: {success}, response: {response}")
            
            # Restore original timeout if it was changed
            if original_timeout is not None and hasattr(self.hardware, 'serial'):
                self.hardware.serial.timeout = original_timeout
                logger.debug("Restored original serial timeout")
            
            # Parse the response - handle both test and real-world formats
            if success and response is not None:
                if isinstance(response, str):
                    if response.startswith("RECV,"):
                        # Format: RECV,<message>
                        msg = response[5:]
                        logger.debug(f"Received message (RECV format): {msg}")
                        return msg
                    elif response != "ERROR":
                        logger.debug(f"Received message (direct format): {response}")
                        return response
                else:
                    # If response is not a string, convert to string
                    msg = str(response)
                    logger.debug(f"Received non-string message (converted): {msg}")
                    return msg
            
            logger.debug("No valid message received")
            return None
                
        except Exception as e:
            logger.error(f"Error receiving message: {e}", exc_info=True)
            return None
    
    def set_frequency(self, frequency: float) -> bool:
        """Set the LoRa frequency
        
        Args:
            frequency: Frequency in MHz
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.initialized:
            return False
            
        try:
            self.frequency = frequency
            if self.engine:
                self.engine.set_parameter('frequency', frequency)
            return True
        except Exception:
            return False
            
    def set_power(self, power: int) -> bool:
        """Set the LoRa transmit power
        
        Args:
            power: Transmit power in dBm
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.initialized:
            return False
            
        try:
            self.power = power
            if self.engine:
                self.engine.set_parameter('tx_power', power)
            return True
        except Exception:
            return False
            
    def set_spreading_factor(self, sf: int) -> bool:
        """Set the LoRa spreading factor
        
        Args:
            sf: Spreading factor (7-12)
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.initialized:
            return False
            
        try:
            self.spreading_factor = sf
            if self.engine:
                self.engine.set_parameter('spreading_factor', sf)
            return True
        except Exception:
            return False
            
    def close(self):
        """Close the LoRa connection and clean up"""
        if self.hardware and hasattr(self.hardware, 'close'):
            self.hardware.close()
        self.initialized = False
        
    def __del__(self):
        """Ensure resources are cleaned up"""
        self.close()

# Alias for backward compatibility
LoraOptimizer = LoRaOptimizer
