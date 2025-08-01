import pytest
import os
from unittest.mock import patch

import pytest
import os
from unittest.mock import patch

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

from atous_sec_network.core.model_manager import FederatedModelUpdater


class TestCryptoFunctions:
    
    def setup_method(self):
        """Setup para cada teste."""
        self.model_updater = FederatedModelUpdater("test_node")
        self.test_data = b"test_model_data_for_signature"
    
    @pytest.mark.skipif(not HAS_CRYPTOGRAPHY, reason="cryptography library not available")
    def test_verify_digital_signature_should_fail_with_invalid_signature(self):
        """RED: Teste que deve falhar - _verify_digital_signature deve rejeitar assinaturas inválidas.
        
        Atualmente a função stub retorna sempre True.
        Após implementação real, deve retornar False para assinaturas inválidas.
        """
        # Dados de teste
        model_data = self.test_data
        invalid_signature = b"this_is_clearly_an_invalid_signature"
        
        # A função stub atual retorna sempre True
        # Após implementação real, deve retornar False
        result = self.model_updater._verify_digital_signature(model_data, invalid_signature)
        
        # Este teste deve FALHAR na fase RED porque a função stub retorna True
        # Na fase GREEN, implementaremos verificação real que retornará False
        assert result is False, "Função stub retorna True, mas deveria rejeitar assinatura inválida"
    
    @pytest.mark.skipif(not HAS_CRYPTOGRAPHY, reason="cryptography library not available")
    def test_verify_digital_signature_should_validate_real_signatures(self):
        """RED: Teste que deve falhar - _verify_digital_signature deve validar assinaturas reais.
        
        Atualmente a função não aceita chaves públicas como parâmetro.
        Após implementação, deve aceitar e validar assinaturas RSA/ECDSA reais.
        """
        # Gerar par de chaves RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Criar assinatura real
        signature = private_key.sign(
            self.test_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # A função atual não aceita public_key como parâmetro
        # Este teste deve FALHAR porque a assinatura da função está incorreta
        try:
            result = self.model_updater._verify_digital_signature(
                self.test_data, signature, public_key
            )
            assert result is True, "Assinatura válida deve ser aceita"
        except TypeError:
            # Esperado na fase RED - função não aceita public_key
            pytest.fail("Função _verify_digital_signature não aceita public_key como parâmetro")
    
    def test_generate_key_pair_function_should_exist(self):
        """RED: Teste que deve falhar - função para gerar par de chaves deve existir.
        
        Atualmente não existe função para gerar chaves.
        Na fase GREEN, implementaremos _generate_key_pair().
        """
        # Este teste deve FALHAR porque a função não existe
        assert hasattr(self.model_updater, '_generate_key_pair'), \
            "Função _generate_key_pair deve existir"
        
        # Testar se a função retorna par de chaves válido
        private_key, public_key = self.model_updater._generate_key_pair()
        
        assert private_key is not None, "Chave privada deve ser gerada"
        assert public_key is not None, "Chave pública deve ser gerada"
    
    def test_sign_data_function_should_exist(self):
        """RED: Teste que deve falhar - função para assinar dados deve existir.
        
        Atualmente não existe função para assinar dados.
        Na fase GREEN, implementaremos _sign_data().
        """
        # Este teste deve FALHAR porque a função não existe
        assert hasattr(self.model_updater, '_sign_data'), \
            "Função _sign_data deve existir"
        
        # Gerar chave para teste
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        ) if HAS_CRYPTOGRAPHY else None
        
        if private_key:
            try:
                # Testar assinatura
                signature = self.model_updater._sign_data(self.test_data, private_key)
                assert signature is not None, "Assinatura deve ser gerada"
                assert isinstance(signature, bytes), "Assinatura deve ser bytes"
            except TypeError as e:
                pytest.fail(f"Função _sign_data não está implementada corretamente: {e}")
            except AttributeError:
                pytest.fail("Função _sign_data não existe")
    
    def test_crypto_error_handling(self):
        """RED: Teste que deve falhar - tratamento de erros criptográficos.
        
        Funções criptográficas devem tratar erros adequadamente.
        """
        # Teste com dados None
        with pytest.raises((ValueError, TypeError)):
            self.model_updater._verify_digital_signature(None, b"signature")
        
        # Teste com assinatura None
        with pytest.raises((ValueError, TypeError)):
            self.model_updater._verify_digital_signature(self.test_data, None)
            
        # Teste com dados None na função _sign_data
        if hasattr(self.model_updater, '_sign_data'):
            with pytest.raises((ValueError, TypeError)):
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                ) if HAS_CRYPTOGRAPHY else b"dummy_key"
                self.model_updater._sign_data(None, private_key)
    
    def test_performance_requirements(self):
        """GREEN: Teste de performance - operações criptográficas devem ser eficientes.
        
        Verificação de assinatura deve ser rápida (< 100ms para RSA-2048).
        """
        import time
        
        if not HAS_CRYPTOGRAPHY:
            pytest.skip("cryptography library not available")
        
        # Gerar chaves e assinatura
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        signature = private_key.sign(
            self.test_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Medir tempo de verificação (quando implementado)
        start_time = time.time()
        
        # Usar _verify_signature que já existe
        result = self.model_updater._verify_signature(
            self.test_data, signature, private_key.public_key()
        )
        
        end_time = time.time()
        verification_time = (end_time - start_time) * 1000  # em ms
        
        assert result is True, "Verificação deve ser bem-sucedida"
        assert verification_time < 100, f"Verificação muito lenta: {verification_time:.2f}ms"