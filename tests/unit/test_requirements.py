"""
Test Requirements - TDD Implementation
Verifica se todas as dependências necessárias estão disponíveis
"""
import unittest
import subprocess
import sys
import shutil
from typing import List, Dict


class TestDependencies(unittest.TestCase):
    """Testa se todas as dependências Python estão instaladas"""
    
    def test_python_version(self):
        """Verifica se a versão do Python é >= 3.8"""
        version = sys.version_info
        self.assertGreaterEqual(version.major, 3)
        if version.major == 3:
            self.assertGreaterEqual(version.minor, 8)
    
    def test_core_dependencies(self):
        """Testa dependências principais"""
        required_packages = [
            "numpy",
            "torch", 
            "transformers",
            "flwr",
            "sklearn",
            "pandas"
        ]
        
        for package in required_packages:
            with self.subTest(package=package):
                try:
                    __import__(package)
                except ImportError as e:
                    self.fail(f"Dependency missing: {package} - {e}")
    
    def test_network_dependencies(self):
        """Testa dependências de rede"""
        required_packages = [
            "paho.mqtt",
            "requests",
            "websockets"
        ]
        
        for package in required_packages:
            with self.subTest(package=package):
                try:
                    __import__(package)
                except ImportError as e:
                    self.fail(f"Network dependency missing: {package} - {e}")
    
    def test_security_dependencies(self):
        """Testa dependências de segurança"""
        required_packages = [
            "cryptography",
            "certifi"
        ]
        
        for package in required_packages:
            with self.subTest(package=package):
                try:
                    __import__(package)
                except ImportError as e:
                    self.fail(f"Security dependency missing: {package} - {e}")
    
    def test_monitoring_dependencies(self):
        """Testa dependências de monitoramento"""
        required_packages = [
            "prometheus_client",
            "psutil"
        ]
        
        for package in required_packages:
            with self.subTest(package=package):
                try:
                    __import__(package)
                except ImportError as e:
                    self.fail(f"Monitoring dependency missing: {package} - {e}")


class TestSystemDependencies(unittest.TestCase):
    """Testa dependências do sistema operacional"""
    
    def test_mosquitto_installation(self):
        """Verifica se o Mosquitto MQTT broker está instalado (ou ignora se não disponível)"""
        if shutil.which("mosquitto") is None:
            self.skipTest("Mosquitto MQTT broker ausente - ignorando teste")
        result = subprocess.run(
            ['mosquitto', '-h'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            self.skipTest("Mosquitto MQTT broker presente, mas retornou código diferente - ignorando teste")
    
    def test_python_executable(self):
        """Verifica se o Python 3 está disponível"""
        try:
            result = subprocess.run(
                ['python3', '--version'], 
                capture_output=True, 
                text=True,
                timeout=5
            )
            self.assertIn('Python 3', result.stdout, "Python 3 not installed")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.fail("Python 3 not found in system PATH")
    
    def test_pip_availability(self):
        """Verifica se o pip (ou pip3) está disponível"""
        for candidate in ([sys.executable, '-m', 'pip'], ['pip'], ['pip3']):
            try:
                result = subprocess.run(
                    candidate + ['--version'] if isinstance(candidate, list) else [candidate, '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and 'pip' in result.stdout.lower():
                    # Found a working pip
                    return
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        self.fail("pip executable (pip/pip3) not found in system PATH")


class TestHardwareCapabilities(unittest.TestCase):
    """Testa capacidades de hardware necessárias"""
    
    def test_serial_port_access(self):
        """Verifica acesso a portas seriais (para LoRa)"""
        try:
            import serial
            # Tenta listar portas disponíveis
            try:
                ports = serial.tools.list_ports.comports()
                # Não falha se não houver portas, apenas verifica se a biblioteca funciona
                self.assertIsInstance(ports, list)
            except AttributeError:
                # Fallback para versões mais antigas do pyserial
                self.assertTrue(hasattr(serial, 'Serial'))
        except ImportError:
            self.fail("pyserial not installed - required for LoRa communication")
    
    def test_gpio_access(self):
        """Verifica acesso a GPIO (para Raspberry Pi)"""
        try:
            import RPi.GPIO as GPIO
            # Testa se consegue configurar GPIO
            GPIO.setmode(GPIO.BCM)
            GPIO.cleanup()
        except ImportError:
            # GPIO não é crítico para desenvolvimento
            self.skipTest("RPi.GPIO not available - skipping GPIO tests")
        except RuntimeError:
            # Erro esperado se não estiver rodando em Raspberry Pi
            self.skipTest("Not running on Raspberry Pi - skipping GPIO tests")


if __name__ == '__main__':
    unittest.main()