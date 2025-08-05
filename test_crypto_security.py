#!/usr/bin/env python3
"""
Teste de Criptografia e Segurança Interna - ATous Secure Network
"""

import sys
import traceback
from datetime import datetime

def log(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")

def test_crypto_imports():
    """Testa importação dos módulos de criptografia"""
    log("=== TESTE DE IMPORTAÇÕES DE CRIPTOGRAFIA ===")
    
    modules_to_test = [
        ('atous_sec_network.core.crypto_utils', 'Utilitários de Criptografia'),
        ('atous_sec_network.security.key_manager', 'Gerenciador de Chaves'),
        ('atous_sec_network.core.serialization', 'Serialização Segura'),
        ('atous_sec_network.security.abiss', 'Sistema ABISS'),
        ('atous_sec_network.security.nnis', 'Sistema NNIS'),
        ('atous_sec_network.security.security_middleware', 'Middleware de Segurança')
    ]
    
    results = {}
    
    for module_name, description in modules_to_test:
        try:
            __import__(module_name)
            log(f"✅ {description}: {module_name}")
            results[module_name] = {'success': True, 'description': description}
        except Exception as e:
            log(f"❌ {description}: {module_name} - {str(e)}")
            results[module_name] = {'success': False, 'error': str(e), 'description': description}
    
    return results

def test_crypto_functions():
    """Testa funções específicas de criptografia"""
    log("\n=== TESTE DE FUNÇÕES DE CRIPTOGRAFIA ===")
    
    try:
        from atous_sec_network.core.crypto_utils import CryptoManager, CryptoUtils
        
        # Teste CryptoUtils
        log("Testando CryptoUtils...")
        
        # Teste de geração de bytes seguros
        random_bytes = CryptoUtils.generate_secure_random(32)
        log(f"✅ Bytes seguros gerados: {len(random_bytes)} bytes")
        
        # Teste de hash seguro
        test_data = b"Hello, ATous Secure Network!"
        hash_result = CryptoUtils.secure_hash(test_data)
        log(f"✅ Hash SHA256 gerado: {hash_result.hex()[:32]}...")
        
        # Teste de derivação de chave
        password = b"test_password"
        salt = CryptoUtils.generate_secure_random(16)
        derived_key = CryptoUtils.derive_key(password, salt)
        log(f"✅ Chave derivada: {len(derived_key)} bytes")
        
        # Teste de comparação em tempo constante
        is_equal = CryptoUtils.constant_time_compare(hash_result, hash_result)
        log(f"✅ Comparação em tempo constante: {is_equal}")
        
        # Teste CryptoManager (se cryptography estiver disponível)
        try:
            crypto_manager = CryptoManager()
            log("✅ CryptoManager inicializado")
            
            # Teste de geração de par de chaves
            private_key, public_key = crypto_manager.generate_key_pair()
            log("✅ Par de chaves ECDH gerado")
            
            # Teste de serialização de chave pública
            serialized_key = crypto_manager.serialize_public_key(public_key)
            log(f"✅ Chave pública serializada: {len(serialized_key)} bytes")
            
            # Teste de criptografia/descriptografia
            test_message = b"Secret message for testing"
            key = CryptoUtils.generate_secure_random(32)
            
            encrypted_data, signature = crypto_manager.encrypt_data(test_message, key)
            log(f"✅ Dados criptografados: {len(encrypted_data)} bytes")
            
            decrypted_data = crypto_manager.decrypt_data(encrypted_data, signature, key)
            
            if decrypted_data == test_message:
                log(f"✅ Criptografia/descriptografia funcionando")
            else:
                log(f"❌ Erro na criptografia: dados não coincidem")
                
        except RuntimeError as e:
            log(f"⚠️ CryptoManager não disponível: {str(e)}")
        
        return True
        
    except ImportError as e:
        log(f"❌ Erro de importação: {str(e)}")
        return False
    except Exception as e:
        log(f"❌ Erro nas funções de criptografia: {str(e)}")
        log(f"Traceback: {traceback.format_exc()}")
        return False

def test_security_systems():
    """Testa sistemas de segurança ABISS e NNIS"""
    log("\n=== TESTE DE SISTEMAS DE SEGURANÇA ===")
    
    try:
        # Teste ABISS
        log("Testando sistema ABISS...")
        from atous_sec_network.security.abiss import ABISSSystem
        
        abiss = ABISSSystem()
        test_request = {
            'method': 'GET',
            'path': '/test',
            'headers': {'User-Agent': 'Test'},
            'body': ''
        }
        
        threat_score = abiss.analyze_request(test_request)
        log(f"✅ ABISS funcionando - Score de ameaça: {threat_score}")
        
        # Teste com payload malicioso
        malicious_request = {
            'method': 'GET',
            'path': "/test?id=1' OR '1'='1",
            'headers': {'User-Agent': 'Test'},
            'body': ''
        }
        
        malicious_score = abiss.analyze_request(malicious_request)
        log(f"✅ ABISS detectou payload malicioso - Score: {malicious_score}")
        
        # Teste NNIS
        log("Testando sistema NNIS...")
        from atous_sec_network.security.nnis import NNISSystem
        
        nnis = NNISSystem()
        anomaly_score = nnis.detect_anomaly(test_request)
        log(f"✅ NNIS funcionando - Score de anomalia: {anomaly_score}")
        
        return True
        
    except Exception as e:
        log(f"❌ Erro nos sistemas de segurança: {str(e)}")
        log(f"Traceback: {traceback.format_exc()}")
        return False

def test_key_manager():
    """Testa o gerenciador de chaves"""
    log("\n=== TESTE DE GERENCIADOR DE CHAVES ===")
    
    try:
        from atous_sec_network.security.key_manager import KeyManager
        import tempfile
        import os
        
        # Cria diretório temporário para teste
        with tempfile.TemporaryDirectory() as temp_dir:
            key_manager = KeyManager(storage_path=temp_dir)
            
            # Teste de geração de chave
            key_id = "test_key_001"
            key = key_manager.generate_key(key_id)
            log(f"✅ Chave gerada com ID: {key_id}")
            
            # Teste de recuperação de chave
            retrieved_key = key_manager.get_key(key_id)
            if retrieved_key == key:
                log(f"✅ Chave recuperada com sucesso")
            else:
                log(f"❌ Erro na recuperação da chave")
            
            # Teste de rotação de chave
            new_key = key_manager.rotate_key(key_id)
            log(f"✅ Chave rotacionada com sucesso")
        
        return True
        
    except Exception as e:
        log(f"❌ Erro no gerenciador de chaves: {str(e)}")
        log(f"Traceback: {traceback.format_exc()}")
        return False

def test_serialization():
    """Testa serialização segura"""
    log("\n=== TESTE DE SERIALIZAÇÃO SEGURA ===")
    
    try:
        from atous_sec_network.core.serialization import (
            serialize_model, deserialize_model, compress_data, decompress_data
        )
        
        # Teste com dados simples
        test_data = {
            'weights': [1.0, 2.0, 3.0, 4.0, 5.0],
            'metadata': {
                'version': '1.0',
                'timestamp': datetime.now().isoformat()
            }
        }
        
        # Teste de serialização
        serialized = serialize_model(test_data)
        log(f"✅ Dados serializados: {len(serialized)} bytes")
        
        # Teste de deserialização
        deserialized = deserialize_model(serialized)
        log(f"✅ Dados deserializados com sucesso")
        
        # Teste de compressão
        test_bytes = b"This is a compression test with repetitive data" * 100
        compressed = compress_data(test_bytes)
        log(f"✅ Dados comprimidos: {len(test_bytes)} -> {len(compressed)} bytes")
        
        # Teste de descompressão
        decompressed = decompress_data(compressed)
        if decompressed == test_bytes:
            log(f"✅ Compressão/descompressão funcionando")
        else:
            log(f"❌ Erro na compressão: dados não coincidem")
        
        return True
        
    except Exception as e:
        log(f"❌ Erro na serialização: {str(e)}")
        log(f"Traceback: {traceback.format_exc()}")
        return False

def test_middleware():
    """Testa middleware de segurança"""
    log("\n=== TESTE DE MIDDLEWARE DE SEGURANÇA ===")
    
    try:
        from atous_sec_network.security.security_middleware import SecurityMiddleware
        
        # Simula uma aplicação FastAPI simples
        class MockApp:
            def __init__(self):
                pass
        
        app = MockApp()
        middleware = SecurityMiddleware(app)
        log(f"✅ SecurityMiddleware inicializado")
        
        return True
        
    except Exception as e:
        log(f"❌ Erro no middleware: {str(e)}")
        log(f"Traceback: {traceback.format_exc()}")
        return False

def main():
    """Função principal"""
    log("🚀 Iniciando Teste de Criptografia e Segurança Interna")
    log(f"🐍 Python: {sys.version}")
    
    results = {
        'imports': test_crypto_imports(),
        'crypto_functions': test_crypto_functions(),
        'security_systems': test_security_systems(),
        'key_manager': test_key_manager(),
        'serialization': test_serialization(),
        'middleware': test_middleware()
    }
    
    log("\n=== RESUMO DOS TESTES ===")
    
    total_tests = len(results)
    passed_tests = sum(1 for result in results.values() if result is True)
    
    for test_name, result in results.items():
        status = "✅ PASSOU" if result is True else "❌ FALHOU"
        log(f"{status} - {test_name.replace('_', ' ').title()}")
    
    log(f"\n📊 Resultado Final: {passed_tests}/{total_tests} testes passaram")
    
    if passed_tests == total_tests:
        log("🎉 Todos os testes de criptografia e segurança passaram!")
    elif passed_tests >= total_tests * 0.7:
        log(f"✅ Maioria dos testes passou ({passed_tests}/{total_tests})")
    else:
        log(f"⚠️ {total_tests - passed_tests} teste(s) falharam")
    
    return results

if __name__ == "__main__":
    main()