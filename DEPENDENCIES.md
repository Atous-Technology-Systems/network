# 📦 Dependências do Projeto Atous Secure Network

Este documento explica os diferentes arquivos de dependências e como usá-los.

## 📋 Arquivos de Dependências

### 1. `requirements.txt` - Dependências Completas
**Uso**: `pip install -r requirements.txt`
- **Conteúdo**: Todas as dependências do projeto (desenvolvimento + produção)
- **Recomendado para**: Desenvolvedores que querem o ambiente completo
- **Inclui**: Core, segurança, ML, hardware, desenvolvimento, testes

### 2. `prod-requirements.txt` - Dependências de Produção
**Uso**: `pip install -r prod-requirements.txt`
- **Conteúdo**: Apenas dependências necessárias para produção
- **Recomendado para**: Servidores de produção, containers Docker
- **Exclui**: Ferramentas de desenvolvimento, testes, documentação

### 3. `dev-requirements.txt` - Dependências de Desenvolvimento
**Uso**: `pip install -r dev-requirements.txt`
- **Conteúdo**: Todas as dependências + ferramentas de desenvolvimento
- **Recomendado para**: Desenvolvedores, CI/CD, ambientes de teste
- **Inclui**: Testes, linting, formatação, documentação, profiling

## 🚀 Instalação Rápida

### Para Desenvolvimento (Recomendado)
```bash
# Clone o repositório
git clone <repository-url>
cd atous-network

# Crie um ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

# Instale dependências de desenvolvimento
pip install -r dev-requirements.txt
```

### Para Produção
```bash
# Instale apenas dependências de produção
pip install -r prod-requirements.txt
```

### Para Testes
```bash
# Instale dependências básicas + testes
pip install -r requirements.txt
```

## ⚠️ Problemas Comuns e Soluções

### 1. Erro de Importação: `email-validator`
**Sintoma**: `ModuleNotFoundError: No module named 'email_validator'`
**Solução**: `pip install email-validator`

### 2. Erro de Pydantic: Configuração Deprecated
**Sintoma**: `PydanticDeprecatedSince20: Support for class-based config is deprecated`
**Solução**: Atualizar código para usar `ConfigDict` (Pydantic v2)

### 3. Erro de Mock: `pyserial-mock`
**Sintoma**: `ModuleNotFoundError: No module named 'pyserial_mock'`
**Solução**: `pip install pyserial-mock`

### 4. Incompatibilidade de Versões
**Problema**: Conflitos entre versões de dependências
**Solução**: Usar versões específicas ou atualizar código para versões mais recentes

## 🔧 Dependências Críticas

### Segurança
- `cryptography>=3.4.0` - Criptografia
- `PyJWT>=2.4.0` - Tokens JWT
- `bcrypt>=3.2.0` - Hash de senhas
- `pydantic[email]>=2.0.0` - Validação de dados
- `email-validator>=2.0.0` - Validação de email

### Machine Learning
- `torch>=1.9.0` - PyTorch
- `transformers>=4.11.0` - Hugging Face
- `scikit-learn>=1.0.0` - ML tradicional
- `flwr>=1.0.0` - Federated Learning

### API e Web
- `fastapi==0.115.6` - Framework web
- `uvicorn[standard]==0.34.0` - Servidor ASGI
- `sqlalchemy>=2.0.0` - ORM de banco

## 📊 Verificação de Dependências

### Listar Dependências Instaladas
```bash
pip list
```

### Verificar Dependências Ausentes
```bash
pip check
```

### Atualizar Dependências
```bash
pip install --upgrade -r requirements.txt
```

### Limpar Cache
```bash
pip cache purge
```

## 🐳 Docker

### Para Desenvolvimento
```dockerfile
FROM python:3.12-slim
COPY dev-requirements.txt .
RUN pip install -r dev-requirements.txt
```

### Para Produção
```dockerfile
FROM python:3.12-slim
COPY prod-requirements.txt .
RUN pip install -r prod-requirements.txt
```

## 🔍 Troubleshooting

### 1. Conflitos de Versão
```bash
# Ver versões instaladas
pip freeze

# Desinstalar versão conflitante
pip uninstall <package-name>

# Reinstalar versão específica
pip install <package-name>==<version>
```

### 2. Ambiente Virtual Corrompido
```bash
# Remover ambiente virtual
rm -rf venv/

# Recriar ambiente virtual
python -m venv venv
source venv/bin/activate
pip install -r dev-requirements.txt
```

### 3. Dependências do Sistema
```bash
# Ubuntu/Debian
sudo apt-get install python3-dev build-essential

# CentOS/RHEL
sudo yum install python3-devel gcc

# Windows
# Instalar Visual Studio Build Tools
```

## 📞 Suporte

Se encontrar problemas com dependências:
1. Verifique a versão do Python (>=3.8)
2. Use ambiente virtual limpo
3. Consulte os logs de erro
4. Abra uma issue no repositório
