#!/bin/bash

# Script para baixar Gemma 3N via Kaggle API
# Baseado no comando fornecido pelo usuário

echo "📥 Download Gemma 3N via Kaggle API"
echo "=================================="

# Verificar se curl está disponível
if ! command -v curl &> /dev/null; then
    echo "❌ curl não encontrado. Instale curl primeiro."
    exit 1
fi

# Verificar variáveis de ambiente
if [ -z "$KAGGLE_USERNAME" ] || [ -z "$KAGGLE_KEY" ]; then
    echo "⚠️  Credenciais Kaggle não configuradas"
    echo ""
    echo "📋 Configure suas credenciais:"
    echo "1. Acesse: https://www.kaggle.com/settings/account"
    echo "2. Seção 'API' -> 'Create New Token'"
    echo "3. Baixe kaggle.json ou anote username/key"
    echo ""
    
    # Tentar ler do arquivo kaggle.json
    KAGGLE_JSON="$HOME/.kaggle/kaggle.json"
    if [ -f "$KAGGLE_JSON" ]; then
        echo "✅ Encontrado kaggle.json, extraindo credenciais..."
        
        # Extrair credenciais do JSON (requer jq ou python)
        if command -v jq &> /dev/null; then
            export KAGGLE_USERNAME=$(jq -r '.username' "$KAGGLE_JSON")
            export KAGGLE_KEY=$(jq -r '.key' "$KAGGLE_JSON")
        elif command -v python3 &> /dev/null; then
            export KAGGLE_USERNAME=$(python3 -c "import json; print(json.load(open('$KAGGLE_JSON'))['username'])")
            export KAGGLE_KEY=$(python3 -c "import json; print(json.load(open('$KAGGLE_JSON'))['key'])")
        else
            echo "❌ jq ou python3 necessário para ler kaggle.json"
            echo "📝 Configure manualmente:"
            read -p "Kaggle Username: " KAGGLE_USERNAME
            read -s -p "Kaggle API Key: " KAGGLE_KEY
            echo ""
            export KAGGLE_USERNAME
            export KAGGLE_KEY
        fi
    else
        echo "📝 Digite suas credenciais:"
        read -p "Kaggle Username: " KAGGLE_USERNAME
        read -s -p "Kaggle API Key: " KAGGLE_KEY
        echo ""
        export KAGGLE_USERNAME
        export KAGGLE_KEY
    fi
fi

# Verificar se credenciais foram definidas
if [ -z "$KAGGLE_USERNAME" ] || [ -z "$KAGGLE_KEY" ]; then
    echo "❌ Credenciais não configuradas"
    exit 1
fi

echo "✅ Credenciais configuradas para: $KAGGLE_USERNAME"

# Criar diretório de modelos
MODEL_DIR="models/gemma-3n"
mkdir -p "$MODEL_DIR"

# Arquivo de destino
MODEL_FILE="$MODEL_DIR/gemma-3n-e2b.tar.gz"

echo "📥 Iniciando download..."
echo "📁 Destino: $MODEL_FILE"

# Comando curl baseado no fornecido pelo usuário
# Modificado para usar variáveis de ambiente
curl -L -u "$KAGGLE_USERNAME:$KAGGLE_KEY" \
     -o "$MODEL_FILE" \
     "https://www.kaggle.com/api/v1/models/google/gemma-3n/transformers/gemma-3n-e2b/2/download"

# Verificar se download foi bem-sucedido
if [ $? -eq 0 ] && [ -f "$MODEL_FILE" ] && [ -s "$MODEL_FILE" ]; then
    echo "✅ Download concluído!"
    
    # Mostrar tamanho do arquivo
    FILE_SIZE=$(du -h "$MODEL_FILE" | cut -f1)
    echo "📊 Tamanho: $FILE_SIZE"
    
    # Extrair arquivo
    echo "📦 Extraindo modelo..."
    EXTRACT_DIR="$MODEL_DIR/extracted"
    mkdir -p "$EXTRACT_DIR"
    
    if tar -xzf "$MODEL_FILE" -C "$EXTRACT_DIR"; then
        echo "✅ Modelo extraído!"
        
        # Listar conteúdo
        echo "📋 Conteúdo extraído:"
        find "$EXTRACT_DIR" -type f | head -10
        
        # Encontrar diretório do modelo
        MODEL_PATH=$(find "$EXTRACT_DIR" -name "config.json" -o -name "tokenizer.json" | head -1 | xargs dirname)
        
        if [ -n "$MODEL_PATH" ]; then
            echo "📁 Modelo encontrado em: $MODEL_PATH"
            
            # Criar configuração
            cat > local_gemma_config.json << EOF
{
  "model_name": "$MODEL_PATH",
  "model_params": {
    "torch_dtype": "float16",
    "device_map": "auto",
    "low_cpu_mem_usage": true,
    "trust_remote_code": true,
    "local_files_only": true
  },
  "pipeline_params": {
    "max_length": 512,
    "max_new_tokens": 256,
    "temperature": 0.7,
    "do_sample": true,
    "top_p": 0.9,
    "top_k": 50,
    "repetition_penalty": 1.1,
    "pad_token_id": 0,
    "eos_token_id": 1
  },
  "memory_size": 1000,
  "threat_threshold": 0.7,
  "simulation_mode": false,
  "enable_monitoring": true,
  "learning_rate": 0.01
}
EOF
            
            echo "✅ Configuração salva em: local_gemma_config.json"
            
            # Atualizar arquivo principal (básico)
            if [ -f "atous_sec_network/__main__.py" ]; then
                # Backup
                cp "atous_sec_network/__main__.py" "atous_sec_network/__main__.py.backup"
                
                # Substituir modelo
                sed -i.bak "s|google/gemma-2-2b-it|$MODEL_PATH|g" "atous_sec_network/__main__.py"
                sed -i.bak "s|google/gemma-3n-E4B|$MODEL_PATH|g" "atous_sec_network/__main__.py"
                
                echo "✅ Arquivo principal atualizado!"
            fi
            
            echo ""
            echo "🎉 Gemma 3N configurado com sucesso!"
            echo ""
            echo "🚀 Próximos passos:"
            echo "1. Execute: python start_app.py --full"
            echo "2. Verifique os logs para confirmar carregamento"
            echo "3. Teste os endpoints da API"
            echo ""
            echo "📁 Arquivos criados:"
            echo "   • $MODEL_FILE (arquivo baixado)"
            echo "   • $EXTRACT_DIR (modelo extraído)"
            echo "   • local_gemma_config.json (configuração)"
            
        else
            echo "❌ Estrutura do modelo não encontrada"
            exit 1
        fi
        
    else
        echo "❌ Falha na extração"
        exit 1
    fi
    
else
    echo "❌ Falha no download"
    echo "🔍 Verifique:"
    echo "   • Credenciais Kaggle corretas"
    echo "   • Acesso ao modelo aprovado"
    echo "   • Conexão com internet"
    exit 1
fi