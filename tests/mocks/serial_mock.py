"""
Mock implementation of pyserial for testing.
"""

class DummySerial:
    """Mock serial port implementation for testing."""
    
    def __init__(self, port=None, baudrate=9600, bytesize=8, parity='N', stopbits=1, timeout=None, **kwargs):
        self.port = port
        self.baudrate = baudrate
        self.bytesize = bytesize
        self.parity = parity
        self.stopbits = stopbits
        self.timeout = timeout
        self.is_open = True
        self._in_waiting = 0
        self._read_buffer = b''
        self._write_buffer = b''
        
        # For testing purposes, we can preload responses
        self._response_map = {}
        
    @property
    def in_waiting(self):
        """Return the number of bytes in the input buffer."""
        return len(self._read_buffer)
    
    def open(self):
        """Open the serial port."""
        if not self.is_open:
            self.is_open = True
            return True
        return False
    
    def close(self):
        """Close the serial port."""
        if self.is_open:
            self.is_open = False
            return True
        return False
    
    def read(self, size=1):
        """Read bytes from the serial port."""
        if not self.is_open:
            raise Exception("Port is not open")
            
        if not self._read_buffer:
            return b''
            
        data = self._read_buffer[:size]
        self._read_buffer = self._read_buffer[size:]
        return data
    
    def write(self, data):
        """Write data to the serial port."""
        if not self.is_open:
            raise Exception("Port is not open")
            
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        self._write_buffer += data
        return len(data)
    
    def reset_input_buffer(self):
        """Clear input buffer."""
        self._read_buffer = b''
    
    def reset_output_buffer(self):
        """Clear output buffer."""
        self._write_buffer = b''
    
    def flush(self):
        """Flush the output buffer."""
        pass
    
    # Test helper methods
    def set_response(self, command, response):
        """Set a response for a specific command."""
        if isinstance(command, str):
            command = command.encode('utf-8')
        if isinstance(response, str):
            response = response.encode('utf-8')
        self._response_map[command] = response
    
    def simulate_response(self, response):
        """Simulate receiving a response from the device."""
        if isinstance(response, str):
            response = response.encode('utf-8')
        self._read_buffer += response


# Create a mock serial module
class MockSerialModule:
    """Mock serial module that can be used to patch the serial module."""
    
    def __init__(self):
        self.Serial = DummySerial
        self.SerialException = Exception
        self.PARITY_NONE = 'N'
        self.STOPBITS_ONE = 1
        self.EIGHTBITS = 8
    
    def __getattr__(self, name):
        # Forward any other attributes to the DummySerial class
        return getattr(DummySerial, name, None)


# Create a singleton instance
serial = MockSerialModule()
Serial = DummySerial
SerialException = Exception
