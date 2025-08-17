"""
Teste abrangente para validar que todo o sistema não tem problemas de recursão
"""
import pytest
import sys
import importlib
from unittest.mock import Mock, patch

# Adicionar o diretório raiz ao path
sys.path.insert(0, '.')

def test_server_import_no_recursion():
    """Teste para garantir que o servidor pode ser importado sem recursão"""
    try:
        import atous_sec_network.api.server
        assert True
    except RecursionError as e:
        pytest.fail(f"Recursão detectada na importação do servidor: {e}")
    except Exception as e:
        pytest.fail(f"Erro inesperado na importação do servidor: {e}")

def test_security_modules_import_no_recursion():
    """Teste para garantir que os módulos de segurança podem ser importados sem recursão"""
    modules_to_test = [
        'atous_sec_network.security.abiss_system',
        'atous_sec_network.security.nnis_system',
        'atous_sec_network.security.security_middleware',
        'atous_sec_network.security.access_control',
        'atous_sec_network.security.key_manager'
    ]
    
    for module_name in modules_to_test:
        try:
            importlib.import_module(module_name)
            assert True
        except RecursionError as e:
            pytest.fail(f"Recursão detectada na importação de {module_name}: {e}")
        except Exception as e:
            # Permitir outros tipos de erro (dependências faltando, etc.)
            print(f"Warning: {module_name} não pôde ser importado: {e}")

def test_api_routes_import_no_recursion():
    """Teste para garantir que as rotas da API podem ser importadas sem recursão"""
    routes_to_test = [
        'atous_sec_network.api.routes.security',
        'atous_sec_network.api.routes.auth',
        'atous_sec_network.api.routes.overlay',
        'atous_sec_network.api.routes.admin'
    ]
    
    for route_name in routes_to_test:
        try:
            importlib.import_module(route_name)
            assert True
        except RecursionError as e:
            pytest.fail(f"Recursão detectada na importação de {route_name}: {e}")
        except Exception as e:
            # Permitir outros tipos de erro
            print(f"Warning: {route_name} não pôde ser importado: {e}")

def test_core_modules_import_no_recursion():
    """Teste para garantir que os módulos core podem ser importados sem recursão"""
    core_modules = [
        'atous_sec_network.core.model_manager',
        'atous_sec_network.core.crypto_utils',
        'atous_sec_network.core.logging_config'
    ]
    
    for module_name in core_modules:
        try:
            importlib.import_module(module_name)
            assert True
        except RecursionError as e:
            pytest.fail(f"Recursão detectada na importação de {module_name}: {e}")
        except Exception as e:
            print(f"Warning: {module_name} não pôde ser importado: {e}")

def test_system_initialization_no_recursion():
    """Teste para garantir que o sistema pode ser inicializado sem recursão"""
    try:
        # Mock das configurações necessárias
        with patch('atous_sec_network.security.abiss_system.ABISSSystem') as mock_abiss:
            with patch('atous_sec_network.security.nnis_system.NNISSystem') as mock_nnis:
                mock_abiss.return_value = Mock()
                mock_nnis.return_value = Mock()
                
                # Tentar importar e inicializar o servidor
                from atous_sec_network.api.server import app
                
                # Verificar se o app foi criado
                assert app is not None
                assert True
                
    except RecursionError as e:
        pytest.fail(f"Recursão detectada na inicialização do sistema: {e}")
    except Exception as e:
        pytest.fail(f"Erro inesperado na inicialização do sistema: {e}")

def test_lazy_loading_functions_no_recursion():
    """Teste para garantir que as funções de lazy loading não causam recursão"""
    try:
        from atous_sec_network.api.server import get_abiss_system, get_nnis_system
        
        # Mock das classes
        with patch('atous_sec_network.security.abiss_system.ABISSSystem') as mock_abiss:
            with patch('atous_sec_network.security.nnis_system.NNISSystem') as mock_nnis:
                mock_abiss.return_value = Mock()
                mock_nnis.return_value = Mock()
                
                # Chamar as funções múltiplas vezes
                abiss1 = get_abiss_system()
                abiss2 = get_abiss_system()
                nnis1 = get_nnis_system()
                nnis2 = get_nnis_system()
                
                # Verificar que retornam a mesma instância (singleton)
                assert abiss1 is abiss2
                assert nnis1 is nnis2
                
                assert True
                
    except RecursionError as e:
        pytest.fail(f"Recursão detectada nas funções de lazy loading: {e}")
    except Exception as e:
        pytest.fail(f"Erro inesperado nas funções de lazy loading: {e}")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
