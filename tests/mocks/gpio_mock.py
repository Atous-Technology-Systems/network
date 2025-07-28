"""Mock implementation of RPi.GPIO for testing"""

class GPIOMock:
    BCM = 11
    BOARD = 10
    OUT = 1
    IN = 0
    HIGH = 1
    LOW = 0
    
    # Class variables to track state
    mode = None
    warnings = True
    pin_states = {}
    
    def setmode(self, mode):
        """Set pin numbering mode"""
        self.mode = mode
        GPIOMock.mode = mode  # Set both instance and class variable
    
    def setwarnings(self, state):
        """Set warnings state"""
        self.warnings = state
        GPIOMock.warnings = state
    
    def setup(self, pin, direction, initial=None):
        """Setup a pin"""
        value = self.LOW if initial is None else initial
        self.pin_states[pin] = value
        GPIOMock.pin_states[pin] = value
    
    def output(self, pin, state):
        """Set output state"""
        self.pin_states[pin] = state
        GPIOMock.pin_states[pin] = state
    
    def input(self, pin):
        """Read input state"""
        return self.pin_states.get(pin, self.LOW)
    
    def cleanup(self, pin=None):
        """Cleanup GPIO settings"""
        if pin is None:
            self.pin_states.clear()
            GPIOMock.pin_states.clear()
        else:
            self.pin_states.pop(pin, None)
            GPIOMock.pin_states.pop(pin, None)
    
    def gpio_function(self, pin):
        """Get pin function"""
        return self.OUT if pin in self.pin_states else self.IN

# Create a singleton instance
GPIO = GPIOMock()
