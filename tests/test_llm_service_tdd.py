"""
Testes TDD para LLMService - Task 1: Carregamento Síncrono

Este arquivo implementa testes seguindo TDD para resolver o problema de carregamento
assíncrono que causa erro 503 no endpoint /api/llm/query.
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import os

# Importar o serviço LLM
from atous_sec_network.ml.llm_service import LLMService, LLMResponse
from atous_sec_network.core.logging_config import get_logger

logger = get_logger('test.llm_service_tdd')

class TestLLMServiceTDDSyncLoading:
    """Testes TDD para carregamento síncrono do LLMService"""
    
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
        assert service.is_loaded is False
        assert service.model is None
        assert service.tokenizer is None
        assert service.model_path == self.test_model_path
    
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
        service.model = Mock()
        service.tokenizer = Mock()
        
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
        
        # Mock do modelo TFLite
        mock_tflite_model = Mock()
        mock_tflite_model.allocate_tensors = Mock()
        
        with patch('atous_sec_network.ml.llm_service.tflite.Interpreter') as mock_interpreter:
            mock_interpreter.return_value = mock_tflite_model
            
            # Act
            result = service._load_model_sync()
            
            # Assert
            assert result is True
            assert service.is_loaded is True
            assert service.model is not None
            assert service.tokenizer is not None
            mock_tflite_model.allocate_tensors.assert_called_once()
    
    def test_07_sync_loading_can_load_pytorch_model(self):
        """
        Teste 7: _load_model_sync() pode carregar modelo PyTorch
        """
        # Arrange
        service = LLMService(self.test_model_path)
        
        # Mock do modelo PyTorch
        mock_model = Mock()
        mock_tokenizer = Mock()
        mock_tokenizer.eos_token_id = 50256
        
        with patch('atous_sec_network.ml.llm_service.AutoTokenizer.from_pretrained') as mock_tokenizer_class, \
             patch('atous_sec_network.ml.llm_service.AutoModelForCausalLM.from_pretrained') as mock_model_class:
            
            mock_tokenizer_class.return_value = mock_tokenizer
            mock_model_class.return_value = mock_model
            
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
    
    def test_09_sync_loading_activates_fallback_when_main_fails(self):
        """
        Teste 9: _load_model_sync() ativa fallback quando modelo principal falha
        """
        # Arrange
        service = LLMService(self.test_model_path)
        
        # Mock para falhar carregamento principal
        with patch.object(service, '_load_tflite_model', return_value=False), \
             patch.object(service, '_load_pytorch_model', return_value=False), \
             patch.object(service, '_activate_fallback_mode') as mock_fallback:
            
            # Act
            result = service._load_model_sync()
            
            # Assert
            mock_fallback.assert_called_once()
            # Result pode ser True se fallback funcionar, False se não
    
    def test_10_fallback_mode_method_exists(self):
        """
        Teste 10: Verificar que existe método para ativar modo fallback
        """
        # Arrange
        service = LLMService(self.test_model_path)
        
        # Act & Assert
        assert hasattr(service, '_activate_fallback_mode')
        assert callable(service._activate_fallback_mode)
    
    def test_11_fallback_mode_loads_fallback_model(self):
        """
        Teste 11: _activate_fallback_mode() carrega modelo fallback
        """
        # Arrange
        service = LLMService(self.test_model_path)
        
        with patch.object(service, '_load_fallback_model') as mock_load_fallback:
            mock_load_fallback.return_value = Mock()
            
            # Act
            service._activate_fallback_mode()
            
            # Assert
            mock_load_fallback.assert_called_once()
            assert service.fallback_mode is True
    
    def test_12_fallback_model_method_exists(self):
        """
        Teste 12: Verificar que existe método para carregar modelo fallback
        """
        # Arrange
        service = LLMService(self.test_model_path)
        
        # Act & Assert
        assert hasattr(service, '_load_fallback_model')
        assert callable(service._load_fallback_model)
    
    def test_13_fallback_model_returns_usable_model(self):
        """
        Teste 13: _load_fallback_model() retorna modelo utilizável
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
    
    def test_14_constructor_calls_sync_loading(self):
        """
        Teste 14: Construtor chama _load_model_sync() automaticamente
        """
        # Arrange & Act
        with patch.object(LLMService, '_load_model_sync') as mock_sync_load:
            mock_sync_load.return_value = True
            service = LLMService(self.test_model_path)
            
            # Assert
            mock_sync_load.assert_called_once()
    
    def test_15_model_status_endpoint_works(self):
        """
        Teste 15: Endpoint /model-status funciona corretamente
        """
        # Arrange
        service = LLMService(self.test_model_path)
        service.is_loaded = True
        service.model = Mock()
        service.tokenizer = Mock()
        
        # Act
        status = service.get_model_status()
        
        # Assert
        assert 'status' in status
        assert 'details' in status
        assert 'fallback_mode' in status
        assert status['status'] in ['ready', 'degraded', 'unavailable']
    
    def test_16_query_endpoint_checks_model_ready(self):
        """
        Teste 16: Endpoint de query verifica se modelo está pronto
        """
        # Arrange
        service = LLMService(self.test_model_path)
        service.is_loaded = False
        
        # Act & Assert
        with pytest.raises(Exception):  # Deve falhar se modelo não estiver pronto
            asyncio.run(service.query("test question"))
    
    def test_17_sync_loading_sets_appropriate_status(self):
        """
        Teste 17: Carregamento síncrono define status apropriado
        """
        # Arrange
        service = LLMService(self.test_model_path)
        
        # Mock do modelo TFLite
        mock_tflite_model = Mock()
        mock_tflite_model.allocate_tensors = Mock()
        
        with patch('atous_sec_network.ml.llm_service.tflite.Interpreter') as mock_interpreter:
            mock_interpreter.return_value = mock_tflite_model
            
            # Act
            result = service._load_model_sync()
            
            # Assert
            assert result is True
            assert service.is_loaded is True
            assert service.model_loaded is True  # Novo atributo
            assert service.fallback_mode is False
    
    def test_18_fallback_mode_returns_degraded_status(self):
        """
        Teste 18: Modo fallback retorna status 'degraded'
        """
        # Arrange
        service = LLMService(self.test_model_path)
        service.fallback_mode = True
        service.is_loaded = True
        
        # Act
        status = service.get_model_status()
        
        # Assert
        assert status['status'] == 'degraded'
        assert status['fallback_mode'] is True
    
    def test_19_ready_status_when_model_fully_loaded(self):
        """
        Teste 19: Status 'ready' quando modelo está totalmente carregado
        """
        # Arrange
        service = LLMService(self.test_model_path)
        service.is_loaded = True
        service.fallback_mode = False
        service.model = Mock()
        service.tokenizer = Mock()
        
        # Act
        status = service.get_model_status()
        
        # Assert
        assert status['status'] == 'ready'
        assert status['fallback_mode'] is False
    
    def test_20_unavailable_status_when_no_model(self):
        """
        Teste 20: Status 'unavailable' quando nenhum modelo está disponível
        """
        # Arrange
        service = LLMService(self.test_model_path)
        service.is_loaded = False
        service.fallback_mode = False
        
        # Act
        status = service.get_model_status()
        
        # Assert
        assert status['status'] == 'unavailable'
        assert status['fallback_mode'] is False

if __name__ == "__main__":
    # Executar testes
    pytest.main([__file__, "-v"])
