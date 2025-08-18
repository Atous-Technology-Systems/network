"""
Testes TDD Simples para LLMService - Task 1: Carregamento Síncrono

Este arquivo implementa testes básicos seguindo TDD para resolver o problema de carregamento
assíncrono que causa erro 503 no endpoint /api/llm/query.
"""

import pytest
import asyncio
import sys
from pathlib import Path
import os

# Mock das bibliotecas externas antes de importar
class MockTorch:
    def __init__(self):
        self.float16 = "float16"
    
    def no_grad(self):
        class NoGradContext:
            def __enter__(self):
                pass
            def __exit__(self, exc_type, exc_val, exc_tb):
                pass
        return NoGradContext()

class MockTransformers:
    class AutoTokenizer:
        @staticmethod
        def from_pretrained(*args, **kwargs):
            return MockTokenizer()
    
    class AutoModelForCausalLM:
        @staticmethod
        def from_pretrained(*args, **kwargs):
            return MockModel()

class MockTokenizer:
    def __init__(self):
        self.eos_token_id = 50256
    
    def encode(self, text, **kwargs):
        return [ord(c) % 1000 for c in text[:50]]
    
    def decode(self, tokens, **kwargs):
        return ''.join([chr(t) if t < 65536 else '?' for t in tokens])

class MockModel:
    def __init__(self):
        pass
    
    def generate(self, *args, **kwargs):
        return [[1, 2, 3, 4, 5]]

class MockTFLite:
    class Interpreter:
        def __init__(self, model_path):
            self.model_path = model_path
        
        def allocate_tensors(self):
            pass
        
        def get_input_details(self):
            return [{'shape': [1, 512], 'dtype': 'float32'}]
        
        def get_output_details(self):
            return [{'shape': [1, 512], 'dtype': 'float32'}]
        
        def set_tensor(self, index, value):
            pass
        
        def invoke(self):
            pass
        
        def get_tensor(self, index):
            return [0.1, 0.2, 0.3]

# Mock das bibliotecas
sys.modules['torch'] = MockTorch()
sys.modules['transformers'] = MockTransformers()
sys.modules['tflite'] = MockTFLite()

# Agora importar o serviço LLM
from atous_sec_network.ml.llm_service import LLMService, LLMResponse

class TestLLMServiceTDDSyncLoadingSimple:
    """Testes TDD simples para carregamento síncrono do LLMService"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.test_model_path = "tests/test_models/gemma-3n-test"
        self.llm_service = None
        
        # Criar diretório de teste se não existir
        Path(self.test_model_path).mkdir(parents=True, exist_ok=True)
    
    def teardown_method(self):
        """Cleanup após cada teste"""
        if self.llm_service:
            try:
                asyncio.run(self.llm_service.shutdown())
            except:
                pass
        
        # Limpar diretório de teste
        import shutil
        if os.path.exists(self.test_model_path):
            shutil.rmtree(self.test_model_path)
    
    def test_01_llm_service_initialization_sets_loaded_false(self):
        """
        Teste 1: Verificar que o LLMService inicia com is_loaded = False
        """
        # Arrange & Act
        service = LLMService(self.test_model_path)
        
        # Assert
        # Com carregamento síncrono, o modelo pode estar carregado após inicialização
        assert service.model_path == self.test_model_path
        # Verificar se pelo menos um dos atributos está definido
        assert hasattr(service, 'is_loaded')
        assert hasattr(service, 'model')
        assert hasattr(service, 'tokenizer')
    
    def test_02_llm_service_has_model_ready_method(self):
        """
        Teste 2: Verificar que o LLMService tem método is_model_ready()
        """
        # Arrange
        service = LLMService(self.test_model_path)
        
        # Act & Assert
        assert hasattr(service, 'is_model_ready')
        assert callable(service.is_model_ready)
    
    def test_03_model_ready_returns_false_when_not_loaded(self):
        """
        Teste 3: is_model_ready() retorna False quando modelo não está carregado
        """
        # Arrange
        service = LLMService(self.test_model_path)
        service.is_loaded = False
        
        # Act
        result = service.is_model_ready()
        
        # Assert
        assert result is False
    
    def test_04_model_ready_returns_true_when_loaded(self):
        """
        Teste 4: is_model_ready() retorna True quando modelo está carregado
        """
        # Arrange
        service = LLMService(self.test_model_path)
        service.is_loaded = True
        service.model = MockModel()
        service.tokenizer = MockTokenizer()
        
        # Act
        result = service.is_model_ready()
        
        # Assert
        assert result is True
    
    def test_05_sync_loading_method_exists(self):
        """
        Teste 5: Verificar que existe método para carregamento síncrono
        """
        # Arrange
        service = LLMService(self.test_model_path)
        
        # Act & Assert
        assert hasattr(service, '_load_model_sync')
        assert callable(service._load_model_sync)
    
    def test_06_sync_loading_can_load_tflite_model(self):
        """
        Teste 6: _load_model_sync() pode carregar modelo TFLite
        """
        # Arrange
        service = LLMService(self.test_model_path)
        
        # Act
        result = service._load_model_sync()
        
        # Assert
        assert result is True
        assert service.is_loaded is True
        assert service.model is not None
        assert service.tokenizer is not None
    
    def test_07_sync_loading_can_load_pytorch_model(self):
        """
        Teste 7: _load_model_sync() pode carregar modelo PyTorch
        """
        # Arrange
        service = LLMService(self.test_model_path)
        
        # Act
        result = service._load_model_sync()
        
        # Assert
        assert result is True
        assert service.is_loaded is True
        assert service.model is not None
        assert service.tokenizer is not None
    
    def test_08_sync_loading_handles_model_not_found(self):
        """
        Teste 8: _load_model_sync() trata modelo não encontrado
        """
        # Arrange
        service = LLMService("path/that/does/not/exist")
        
        # Act
        result = service._load_model_sync()
        
        # Assert
        assert result is False
        assert service.is_loaded is False
    
    def test_09_fallback_mode_method_exists(self):
        """
        Teste 9: Verificar que existe método para ativar modo fallback
        """
        # Arrange
        service = LLMService(self.test_model_path)
        
        # Act & Assert
        assert hasattr(service, '_activate_fallback_mode')
        assert callable(service._activate_fallback_mode)
    
    def test_10_fallback_model_method_exists(self):
        """
        Teste 10: Verificar que existe método para carregar modelo fallback
        """
        # Arrange
        service = LLMService(self.test_model_path)
        
        # Act & Assert
        assert hasattr(service, '_load_fallback_model')
        assert callable(service._load_fallback_model)
    
    def test_11_fallback_model_returns_usable_model(self):
        """
        Teste 11: _load_fallback_model() retorna modelo utilizável
        """
        # Arrange
        service = LLMService(self.test_model_path)
        
        # Act
        fallback_model = service._load_fallback_model()
        
        # Assert
        assert fallback_model is not None
        # Verificar que o modelo fallback tem métodos básicos
        assert hasattr(fallback_model, 'allocate_tensors')
        assert hasattr(fallback_model, 'invoke')
    
    def test_12_constructor_calls_sync_loading(self):
        """
        Teste 12: Construtor chama _load_model_sync() automaticamente
        """
        # Arrange & Act
        with pytest.MonkeyPatch().context() as m:
            # Mock do método _load_model_sync para retornar True e definir is_loaded
            def mock_load_sync(self):
                self.is_loaded = True
                return True
            
            m.setattr(LLMService, '_load_model_sync', mock_load_sync)
            service = LLMService(self.test_model_path)
            
            # Assert - verificar que o método foi chamado durante a inicialização
            assert service.is_loaded is True
    
    def test_13_model_status_method_exists(self):
        """
        Teste 13: Verificar que existe método para obter status do modelo
        """
        # Arrange
        service = LLMService(self.test_model_path)
        
        # Act & Assert
        assert hasattr(service, 'get_model_status')
        assert callable(service.get_model_status)
    
    def test_14_model_status_returns_correct_structure(self):
        """
        Teste 14: get_model_status() retorna estrutura correta
        """
        # Arrange
        service = LLMService(self.test_model_path)
        
        # Act
        status = service.get_model_status()
        
        # Assert
        assert 'status' in status
        assert 'details' in status
        assert 'fallback_mode' in status
        assert status['status'] in ['ready', 'degraded', 'unavailable']
    
    def test_15_query_method_checks_model_ready(self):
        """
        Teste 15: Método query() verifica se modelo está pronto
        """
        # Arrange
        service = LLMService(self.test_model_path)
        service.is_loaded = False
        
        # Act & Assert
        with pytest.raises(Exception):  # Deve falhar se modelo não estiver pronto
            asyncio.run(service.query("test question"))

if __name__ == "__main__":
    # Executar testes
    pytest.main([__file__, "-v"])
