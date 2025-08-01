# Plano de Desenvolvimento TDD - Atous Secure Network

Este documento serve como guia principal para o desenvolvimento seguindo metodologia TDD (Test-Driven Development).

## 🎯 **OBJETIVO ATUAL**

Implementar correções críticas de segurança seguindo rigorosamente o ciclo TDD: RED → GREEN → REFACTOR.

## 📋 **TASK ATUAL: Implementar `_sign_data` Real**

### **Informações da Task**
- **ID**: TASK-1.1
- **Branch**: `fix/implement-real-sign-data`
- **Prioridade**: 🔴 CRÍTICA
- **Estimativa**: 1-2 dias
- **Responsável**: Development Team

### **Problema Identificado**
```python
# VULNERABILIDADE CRÍTICA em atous_sec_network/core/model_manager.py
def _sign_data(self, data: bytes) -> bytes:
    """Stub implementation - INSECURE"""
    return b"fake_signature"  # ⚠️ SEMPRE RETORNA VALOR FIXO
```

### **Ciclo TDD - Fase RED 🔴**

#### **Objetivo**: Criar teste que falha para forçar implementação real

#### **Testes a Implementar**:

1. **Teste de Assinatura RSA-PSS**
```python
def test_sign_data_should_create_valid_rsa_signature(self):
    """RED: Teste deve falhar - _sign_data deve criar assinatura RSA válida"""
    # Gerar dados de teste
    test_data = b"test_model_data_for_signature"
    
    # Gerar par de chaves RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # A função atual retorna valor fixo - deve FALHAR
    signature = self.model_updater._sign_data(test_data, private_key)
    
    # Verificar se assinatura é válida
    public_key = private_key.public_key()
    try:
        public_key.verify(
            signature,
            test_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        assert True, "Assinatura RSA válida criada"
    except Exception:
        pytest.fail("Assinatura RSA inválida - implementação necessária")
```

2. **Teste de Assinatura ECDSA**
```python
def test_sign_data_should_create_valid_ecdsa_signature(self):
    """RED: Teste deve falhar - _sign_data deve criar assinatura ECDSA válida"""
    test_data = b"test_model_data_for_ecdsa"
    
    # Gerar par de chaves ECDSA
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    
    # A função atual não aceita private_key como parâmetro - deve FALHAR
    signature = self.model_updater._sign_data(test_data, private_key)
    
    # Verificar assinatura ECDSA
    public_key = private_key.public_key()
    try:
        public_key.verify(signature, test_data, ec.ECDSA(hashes.SHA256()))
        assert True, "Assinatura ECDSA válida criada"
    except Exception:
        pytest.fail("Assinatura ECDSA inválida - implementação necessária")
```

3. **Teste de Validação de Parâmetros**
```python
def test_sign_data_should_validate_parameters(self):
    """RED: Teste deve falhar - _sign_data deve validar parâmetros"""
    # Testar com dados None
    with pytest.raises(ValueError, match="Data cannot be None"):
        self.model_updater._sign_data(None, mock_private_key)
    
    # Testar com chave None
    with pytest.raises(ValueError, match="Private key cannot be None"):
        self.model_updater._sign_data(b"test", None)
    
    # Testar com dados vazios
    with pytest.raises(ValueError, match="Data cannot be empty"):
        self.model_updater._sign_data(b"", mock_private_key)
```

### **Execução da Fase RED**

#### **Comandos para Executar**:
```bash
# 1. Criar branch para a task
git checkout -b fix/implement-real-sign-data

# 2. Executar testes atuais (devem falhar)
pytest tests/security/test_crypto_functions.py::TestCryptoFunctions::test_sign_data_should_create_valid_rsa_signature -v

# 3. Verificar que todos os novos testes falham
pytest tests/security/test_crypto_functions.py -k "sign_data" -v
```

#### **Resultado Esperado**: 🔴 TODOS OS TESTES DEVEM FALHAR

### **Ciclo TDD - Fase GREEN 🟢**

#### **Objetivo**: Implementar código mínimo para fazer os testes passarem

#### **Implementação Necessária**:

```python
def _sign_data(self, data: bytes, private_key, algorithm: str = "RSA-PSS") -> bytes:
    """
    Assina dados usando chave privada.
    
    Args:
        data: Dados para assinar
        private_key: Chave privada (RSA ou ECDSA)
        algorithm: Algoritmo de assinatura ("RSA-PSS" ou "ECDSA")
        
    Returns:
        Assinatura digital dos dados
        
    Raises:
        ValueError: Se parâmetros inválidos
        CryptographicError: Se falha na assinatura
    """
    # Validação de parâmetros
    if data is None:
        raise ValueError("Data cannot be None")
    if private_key is None:
        raise ValueError("Private key cannot be None")
    if len(data) == 0:
        raise ValueError("Data cannot be empty")
    
    try:
        if algorithm == "RSA-PSS":
            # Implementar assinatura RSA-PSS
            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif algorithm == "ECDSA":
            # Implementar assinatura ECDSA
            signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
        return signature
        
    except Exception as e:
        raise CryptographicError(f"Failed to sign data: {str(e)}")
```

### **Execução da Fase GREEN**

#### **Comandos para Executar**:
```bash
# 1. Implementar a função _sign_data
# 2. Executar testes (devem passar)
pytest tests/security/test_crypto_functions.py -k "sign_data" -v

# 3. Verificar que todos os testes passam
pytest tests/security/test_crypto_functions.py -v
```

#### **Resultado Esperado**: 🟢 TODOS OS TESTES DEVEM PASSAR

### **Ciclo TDD - Fase REFACTOR 🔵**

#### **Objetivo**: Melhorar código mantendo testes passando

#### **Melhorias a Implementar**:

1. **Otimização de Performance**
2. **Melhoria da Documentação**
3. **Tratamento de Erros Robusto**
4. **Logging de Auditoria**
5. **Validação Adicional**

### **Execução da Fase REFACTOR**

#### **Comandos para Executar**:
```bash
# 1. Refatorar código
# 2. Executar todos os testes
pytest tests/ -v

# 3. Verificar cobertura
pytest --cov=atous_sec_network tests/

# 4. Executar análise de qualidade
flake8 atous_sec_network/
black atous_sec_network/
```

### **Critérios de Conclusão**

- [ ] ✅ Todos os testes TDD passando
- [ ] ✅ Cobertura de código ≥ 90%
- [ ] ✅ Testes de segurança aprovados
- [ ] ✅ Documentação atualizada
- [ ] ✅ Code review interno aprovado
- [ ] ✅ Performance benchmarks atendidos

### **Commit e Merge**

```bash
# 1. Commit seguindo conventional commits
git add .
git commit -m "fix: implement real digital signature in _sign_data function

- Add RSA-PSS signature implementation
- Add ECDSA signature support
- Add parameter validation
- Add comprehensive error handling
- Add security audit logging
- Fixes critical security vulnerability

Breaking Change: _sign_data now requires private_key parameter
Security: Replaces insecure stub implementation"

# 2. Push branch
git push origin fix/implement-real-sign-data

# 3. Criar Pull Request
# 4. Após aprovação, merge para main
```

## 🔄 **PRÓXIMA TASK**

Após conclusão da TASK-1.1, prosseguir para:
- **TASK-1.2**: Implementar `_verify_digital_signature` Real
- **Branch**: `fix/implement-real-signature-verification`

## 📊 **MÉTRICAS DE PROGRESSO**

- **Tasks Concluídas**: 0/12
- **Vulnerabilidades Críticas Corrigidas**: 0/3
- **Cobertura de Testes**: Atual / Meta: 90%
- **Performance**: Baseline / Meta

---

**⚠️ IMPORTANTE**: Este documento deve ser atualizado após cada task concluída para manter o progresso rastreável.