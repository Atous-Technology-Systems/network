#!/usr/bin/env python3
"""
Teste simples de consulta ao LLM
"""

import os
import sys
import asyncio
from pathlib import Path

# Adicionar o projeto ao path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

async def test_simple_query():
    """Testa uma consulta simples ao LLM"""
    print("Teste simples de consulta ao LLM...")
    print("=" * 50)
    
    try:
        from atous_sec_network.ml.llm_service import LLMService
        
        # Criar LLM service
        print("1 Criando LLM service...")
        llm_service = LLMService("models/gemma-3n/extracted")
        print(f" Caminho: {llm_service.model_path}")
        
        # Carregar modelo
        print("\n Carregando modelo...")
        success = await llm_service.load_model()
        
        if not success:
            print(" Falha ao carregar modelo")
            return False
        
        print("  Modelo carregado!")
        print(f" Tipo: {llm_service.get_metrics()['model_type']}")
        
        # Testar consulta
        print("\n Testando consulta...")
        question = "Como está o sistema de segurança?"
        print(f" Pergunta: {question}")
        
        print(" Processando...")
        response = await llm_service.query(question)
        
        print(f"\n Resposta: {response.answer}")
        print(f" Confiança: {response.confidence}")
        print(f" Fontes: {response.sources}")
        
        # Ver métricas
        print("\n Métricas:")
        metrics = llm_service.get_metrics()
        print(f"   Consultas: {metrics['total_queries']}")
        print(f"   Cache: {metrics['cache_size']}")
        print(f"   Tempo médio: {metrics['average_response_time']:.4f}s")
        
        return True
        
    except Exception as e:
        print(f"\n Erro: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Função principal"""
    print(" Iniciando teste simples...")
    
    success = asyncio.run(test_simple_query())
    
    if success:
        print("\n Teste concluído com sucesso!")
    else:
        print("\n Teste falhou!")
        sys.exit(1)

if __name__ == "__main__":
    main()
