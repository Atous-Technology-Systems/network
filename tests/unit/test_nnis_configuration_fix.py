"""
Teste para validar correção dos problemas de configuração do sistema NNIS
"""
import pytest
import sys
from unittest.mock import Mock, patch

# Adicionar o diretório raiz ao path
sys.path.insert(0, '.')

def test_nnis_system_requires_config():
    """Teste para garantir que NNISSystem requer configuração"""
    
    # Importar fora do patch
    from atous_sec_network.security.nnis_system import NNISSystem
    
    # Mock das dependências
    with patch('atous_sec_network.security.nnis_system.TRANSFORMERS_AVAILABLE', False):
        # Deve falhar sem configuração
        with pytest.raises(TypeError):
            NNISSystem()
        
        # Deve funcionar com configuração
        config = {
            "model_name": "google/gemma-3n-2b",
            "memory_size": 1000,
            "immune_cells_count": 50,
            "memory_cells_count": 100,
            "threat_threshold": 0.8
        }
        
        nnis = NNISSystem(config)
        assert nnis is not None
        assert nnis.config == config

def test_nnis_system_config_validation():
    """Teste para validar validação de configuração do NNIS"""
    
    # Importar fora do patch
    from atous_sec_network.security.nnis_system import NNISSystem
    
    with patch('atous_sec_network.security.nnis_system.TRANSFORMERS_AVAILABLE', False):
        # Configuração mínima
        min_config = {
            "model_name": "google/gemma-3n-2b"
        }
        
        nnis = NNISSystem(min_config)
        assert nnis.model_name == "google/gemma-3n-2b"
        assert nnis.config.get("memory_size", 1000) == 1000  # Valor padrão
        
        # Configuração completa
        full_config = {
            "model_name": "google/gemma-3n-2b",
            "memory_size": 2000,
            "immune_cells_count": 100,
            "memory_cells_count": 200,
            "threat_threshold": 0.9
        }
        
        nnis_full = NNISSystem(full_config)
        assert nnis_full.get_memory_size() == 2000
        assert nnis_full.get_immune_cell_count() == 100
        assert nnis_full.get_memory_cell_count() == 200
        assert nnis_full.get_threat_threshold() == 0.9

def test_nnis_system_initialization_with_config():
    """Teste para validar inicialização completa do NNIS com configuração"""
    
    # Importar fora do patch
    from atous_sec_network.security.nnis_system import NNISSystem
    
    with patch('atous_sec_network.security.nnis_system.TRANSFORMERS_AVAILABLE', False):
        config = {
            "model_name": "google/gemma-3n-2b",
            "memory_size": 1000,
            "immune_cells_count": 50,
            "memory_cells_count": 100,
            "threat_threshold": 0.8
        }
        
        nnis = NNISSystem(config)
        
        # Verificar que os componentes foram inicializados
        assert hasattr(nnis, 'immune_cells')
        assert hasattr(nnis, 'memory_cells')
        assert hasattr(nnis, 'threat_database')
        assert hasattr(nnis, 'learning_history')
        assert hasattr(nnis, 'memory_cells')
        assert hasattr(nnis, 'response_stats')
        assert hasattr(nnis, 'threat_stats')

def test_nnis_system_config_defaults():
    """Teste para validar valores padrão da configuração"""
    
    # Importar fora do patch
    from atous_sec_network.security.nnis_system import NNISSystem
    
    with patch('atous_sec_network.security.nnis_system.TRANSFORMERS_AVAILABLE', False):
        # Configuração mínima
        config = {"model_name": "google/gemma-3n-2b"}
        
        nnis = NNISSystem(config)
        
        # Verificar valores padrão
        assert nnis.get_memory_size() == 1000
        assert nnis.get_immune_cell_count() == 100
        assert nnis.get_memory_cell_count() == 50
        assert nnis.get_threat_threshold() == 0.8

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
