#!/usr/bin/env python3
"""
Script para testar o LLM service com modelo TFLite
"""

import os
import sys
from pathlib import Path

# Adicionar o projeto ao path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

async def test_tflite_llm():
    """Testa o LLM service com modelo TFLite"""
    print(" Testando LLM service com modelo TFLite...")
    print("=" * 50)
    
    try:
        from atous_sec_network.ml.llm_service import LLMService
        
        # Criar instância com caminho TFLite
        llm_service = LLMService("models/gemma-3n/extracted")
        print(f" LLM Service criado com caminho: {llm_service.model_path}")
        
        # Verificar se o diretório existe
        if not os.path.exists(llm_service.model_path):
            print(f" Diretório do modelo não existe: {llm_service.model_path}")
            return False
        
        print(f"Diretório do modelo existe")
        
        # Listar arquivos do modelo
        print("\n Arquivos do modelo:")
        for item in Path(llm_service.model_path).glob("*"):
            if item.is_file():
                size_mb = item.stat().st_size / (1024 * 1024)
                print(f"    {item.name}: {size_mb:.1f} MB")
        
        # Carregar modelo
        print("\n Carregando modelo...")
        success = await llm_service.load_model()
        
        if success:
            print(" Modelo carregado com sucesso!")
            print(f"   Tipo: {type(llm_service.model).__name__}")
            print(f"   Tokenizer: {type(llm_service.tokenizer).__name__}")
            print(f"   Carregado: {llm_service.is_loaded}")
            
            # Testar consulta
            print("\n Testando consulta...")
            response = await llm_service.query("Como está o sistema de segurança?")
            print(f"   Resposta: {response.answer}")
            print(f"   Confiança: {response.confidence}")
            print(f"   Fontes: {response.sources}")
            
            # Ver métricas
            print("\n Métricas:")
            metrics = llm_service.get_metrics()
            for key, value in metrics.items():
                print(f"   {key}: {value}")
            
        else:
            print(" Falha ao carregar modelo")
            return False
        
        return True
        
    except Exception as e:
        print(f" Erro no teste: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Função principal"""
    import asyncio
    
    print(" Iniciando teste do LLM service TFLite...")
    
    # Executar teste assíncrono
    success = asyncio.run(test_tflite_llm())
    
    if success:
        print("\n Teste concluído com sucesso!")
    else:
        print("\n Teste falhou!")
        sys.exit(1)

if __name__ == "__main__":
    main()
