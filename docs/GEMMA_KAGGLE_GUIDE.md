# 🏆 Guia Completo: Gemma 3N via Kaggle

## 🎯 Pré-requisitos

1. **Conta Kaggle** com telefone verificado
2. **Acesso aprovado** aos modelos Gemma
3. **Credenciais API** configuradas

## 📋 Passo a Passo

### 1. Configurar Conta Kaggle

```bash
# 1. Criar conta em: https://www.kaggle.com/account/login
# 2. Verificar telefone (obrigatório)
# 3. Acessar: https://www.kaggle.com/settings/account
# 4. Seção 'API' -> 'Create New Token'
# 5. Baixar kaggle.json
```

### 2. Aprovar Modelos Gemma

Visite e aceite os termos:
- https://www.kaggle.com/models/google/gemma
- https://www.kaggle.com/models/google/gemma-2  
- https://www.kaggle.com/models/google/gemma-3n

### 3. Configurar Credenciais

**Opção A: Arquivo kaggle.json**
```bash
# Colocar kaggle.json em:
# Linux/Mac: ~/.kaggle/kaggle.json
# Windows: C:\Users\{username}\.kaggle\kaggle.json
```

**Opção B: Variáveis de ambiente**
```bash
export KAGGLE_USERNAME=seu_username
export KAGGLE_KEY=sua_api_key
```

### 4. Baixar Gemma 3N

**Opção A: Script Python (Recomendado)**
```bash
python download_gemma_kaggle.py
```

**Opção B: Script Bash**
```bash
chmod +x download_gemma_kaggle.sh
./download_gemma_kaggle.sh
```

**Opção C: Comando Manual**
```bash
# Baseado no comando fornecido pelo usuário
export KAGGLE_USERNAME=seu_username
export KAGGLE_KEY=sua_api_key

curl -L -u $KAGGLE_USERNAME:$KAGGLE_KEY \
     -o ~/Downloads/gemma-3n.tar.gz \
     https://www.kaggle.com/api/v1/models/google/gemma-3n/transformers/gemma-3n-e2b/2/download
```

## 🔧 Configuração na Aplicação

### Automática (via scripts)
Os scripts fazem automaticamente:
- ✅ Download do modelo
- ✅ Extração dos arquivos
- ✅ Configuração local
- ✅ Atualização da aplicação

### Manual
Se preferir configurar manualmente:

1. **Extrair modelo**:
```bash
mkdir -p models/gemma-3n/extracted
tar -xzf gemma-3n.tar.gz -C models/gemma-3n/extracted
```

2. **Encontrar caminho do modelo**:
```bash
find models/gemma-3n/extracted -name "config.json" | head -1 | xargs dirname
```

3. **Atualizar configuração**:
```json
{
  "model_name": "/caminho/completo/para/modelo",
  "model_params": {
    "local_files_only": true,
    "trust_remote_code": true
  }
}
```

## 🧪 Testar Configuração

```bash
# Testar aplicação
python start_app.py --full

# Verificar logs
# Deve mostrar: "Sistema ABISS inicializado" sem erros
```

## 📊 Estrutura de Arquivos

Após download bem-sucedido:
```
models/
└── gemma-3n/
    ├── gemma-3n-e2b.tar.gz     # Arquivo baixado
    └── extracted/               # Modelo extraído
        └── [arquivos do modelo]
```

## ⚠️ Troubleshooting

### Erro 403 - Acesso Negado
```
❌ Problema: Access denied
✅ Solução: Aceitar termos dos modelos Gemma no Kaggle
```

### Erro 401 - Credenciais Inválidas
```
❌ Problema: Invalid credentials
✅ Solução: Verificar KAGGLE_USERNAME e KAGGLE_KEY
```

### Modelo não carrega
```
❌ Problema: Model loading failed
✅ Solução: Verificar se local_files_only=true na configuração
```

### Arquivo corrompido
```
❌ Problema: Extraction failed
✅ Solução: Baixar novamente o arquivo
```

## 🎉 Sucesso!

Se tudo funcionou, você verá:
```
✅ Sistema ABISS inicializado com modelo Gemma 3N
✅ Sistema NNIS inicializado com modelo Gemma 3N
✅ All systems initialized successfully!
```

## 📞 Suporte

- **Kaggle**: https://www.kaggle.com/contact
- **Documentação**: https://www.kaggle.com/docs/api
- **Modelos Gemma**: https://www.kaggle.com/models/google/gemma-3n

## 💡 Dicas

1. **Tamanho**: Gemma 3N tem ~4-8GB
2. **Tempo**: Download pode demorar 10-30 minutos
3. **Espaço**: Reserve 15GB livres (arquivo + extração)
4. **RAM**: Recomendado 16GB+ para usar o modelo
5. **GPU**: Opcional, mas acelera significativamente

---

**🎯 Comando Original Fornecido:**
```bash
#!/bin/bash
# Export your Kaggle username and API key
# export KAGGLE_USERNAME=<YOUR USERNAME>
# export KAGGLE_KEY=<YOUR KAGGLE KEY>
curl -L -u $KAGGLE_USERNAME:$KAGGLE_KEY \
     -o ~/Downloads/model.tar.gz \
     https://www.kaggle.com/api/v1/models/google/gemma-3n/transformers/gemma-3n-e2b/2/download
```