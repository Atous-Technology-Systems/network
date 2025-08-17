"""
Teste para validar correção do erro de recursão no sistema ABISS
"""
import pytest
import sys
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient

# Adicionar o diretório raiz ao path para importar módulos
sys.path.insert(0, '.')

def test_abiss_system_no_recursion():
    """Teste para garantir que não há recursão infinita no sistema ABISS"""
    
    # Mock das dependências
    mock_abiss_config = {
        "model_name": "google/gemma-3n-2b",
        "memory_size": 1000,
        "threat_threshold": 0.7,
        "learning_rate": 0.01,
        "enable_monitoring": True
    }
    
    # Teste 1: Verificar que a função não chama a si mesma
    with patch('atous_sec_network.security.abiss_system.ABISSSystem') as mock_abiss_class:
        mock_instance = Mock()
        mock_abiss_class.return_value = mock_instance
        
        # Importar e testar a função
        from atous_sec_network.api.server import get_abiss_system
        
        # Chamar a função múltiplas vezes para verificar que não há recursão
        result1 = get_abiss_system()
        result2 = get_abiss_system()
        result3 = get_abiss_system()
        
        # Verificar que a função retorna a mesma instância (singleton)
        assert result1 is result2
        assert result2 is result3
        
        # Verificar que ABISSSystem foi instanciado apenas uma vez
        mock_abiss_class.assert_called_once_with(mock_abiss_config)

def test_abiss_system_import_structure():
    """Teste para verificar a estrutura de import correta"""
    
    # Verificar que não há import circular
    try:
        from atous_sec_network.api.server import get_abiss_system
        from atous_sec_network.security.abiss_system import ABISSSystem
        
        # Se chegou aqui, não há import circular
        assert True
    except ImportError as e:
        pytest.fail(f"Import circular detectado: {e}")
    except RecursionError as e:
        pytest.fail(f"Recursão detectada: {e}")

def test_abiss_system_lazy_loading():
    """Teste para verificar que o lazy loading funciona corretamente"""
    
    with patch('atous_sec_network.security.abiss_system.ABISSSystem') as mock_abiss_class:
        mock_instance = Mock()
        mock_abiss_class.return_value = mock_instance
        
        # Reset das variáveis globais
        import atous_sec_network.api.server as server_module
        server_module.abiss_system = None
        
        # Primeira chamada deve criar a instância
        from atous_sec_network.api.server import get_abiss_system
        result1 = get_abiss_system()
        
        # Verificar que ABISSSystem foi instanciado
        mock_abiss_class.assert_called_once()
        
        # Segunda chamada deve retornar a mesma instância
        result2 = get_abiss_system()
        assert result1 is result2
        
        # Verificar que não foi instanciado novamente
        mock_abiss_class.assert_called_once()

def test_abiss_system_error_handling():
    """Teste para verificar tratamento de erros na inicialização"""
    
    with patch('atous_sec_network.security.abiss_system.ABISSSystem') as mock_abiss_class:
        # Simular erro na inicialização
        mock_abiss_class.side_effect = Exception("Erro de inicialização")
        
        # Reset das variáveis globais
        import atous_sec_network.api.server as server_module
        server_module.abiss_system = None
        
        # Deve lançar exceção
        from atous_sec_network.api.server import get_abiss_system
        with pytest.raises(Exception) as exc_info:
            get_abiss_system()
        
        assert "Erro de inicialização" in str(exc_info.value)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
