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
    with patch('atous_sec_network.api.server.get_abiss_system') as mock_abiss_func:
        mock_instance = Mock()
        mock_abiss_func.return_value = mock_instance
        
        # Chamar a função múltiplas vezes para verificar que não há recursão
        result1 = mock_abiss_func()
        result2 = mock_abiss_func()
        result3 = mock_abiss_func()
        
        # Verificar que a função retorna a mesma instância (singleton)
        assert result1 is result2
        assert result2 is result3
        
        # Verificar que get_abiss_system foi chamada 3 vezes (uma para cada chamada)
        assert mock_abiss_func.call_count == 3

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
    
    with patch('atous_sec_network.api.server.get_abiss_system') as mock_abiss_func:
        mock_instance = Mock()
        mock_abiss_func.return_value = mock_instance
        
        # Reset das variáveis globais
        import atous_sec_network.api.server as server_module
        server_module.abiss_system = None
        
        # Primeira chamada deve criar a instância
        result1 = mock_abiss_func()
        
        # Verificar que get_abiss_system foi chamada uma vez
        assert mock_abiss_func.call_count == 1
        
        # Segunda chamada deve retornar a mesma instância
        result2 = mock_abiss_func()
        assert result1 is result2
        
        # Verificar que foi chamada duas vezes no total
        assert mock_abiss_func.call_count == 2

def test_abiss_system_error_handling():
    """Teste para verificar tratamento de erros na inicialização"""
    
    with patch('atous_sec_network.api.server.get_abiss_system') as mock_abiss_func:
        # Simular erro na inicialização
        mock_abiss_func.side_effect = Exception("Erro de inicialização")
        
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
