#!/usr/bin/env python3
"""
Script simples para testar a integração Gemma 3N TFLite
"""

import os
import sys
import asyncio
from pathlib import Path

# Adicionar o projeto ao path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

async def test_gemma_integration():
    """Testa a integração com Gemma 3N TFLite"""
    print("🚀 Testando integração com Gemma 3N TFLite...")
    print("=" * 50)
    
    try:
        # 1. Testar LLM service
        print("\n1️⃣ Testando LLM service...")
        from atous_sec_network.ml.llm_service import LLMService
        
        llm_service = LLMService("models/gemma-3n/extracted")
        print(f"   ✅ LLM Service criado com caminho: {llm_service.model_path}")
        
        # 2. Carregar modelo
        print("\n2️⃣ Carregando modelo...")
        success = await llm_service.load_model()
        
        if not success:
            print("   ❌ Falha ao carregar modelo")
            return False
        
        print("   ✅ Modelo carregado com sucesso!")
        print(f"   📊 Tipo: {llm_service.get_metrics()['model_type']}")
        print(f"   🔄 Carregado: {llm_service.is_loaded}")
        
        # 3. Testar consultas
        print("\n3️⃣ Testando consultas...")
        
        test_questions = [
            "Como está o sistema de segurança?",
            "Há alguma ameaça detectada?",
            "Quantos usuários estão ativos?",
            "Qual é o status do ABISS?",
            "Como funciona o NNIS?"
        ]
        
        for i, question in enumerate(test_questions, 1):
            print(f"   {i}. Pergunta: {question}")
            response = await llm_service.query(question)
            print(f"      💬 Resposta: {response.answer}")
            print(f"      🎯 Confiança: {response.confidence:.2f}")
            print(f"      📍 Fontes: {', '.join(response.sources)}")
            print()
        
        # 4. Ver métricas finais
        print("\n4️⃣ Métricas finais:")
        metrics = llm_service.get_metrics()
        for key, value in metrics.items():
            print(f"   {key}: {value}")
        
        print("\n🎉 Teste de integração concluído com sucesso!")
        print("\n📝 Resumo:")
        print("   ✅ LLM service funcionando")
        print("   ✅ Modelo TFLite carregado")
        print("   ✅ Consultas respondendo")
        print("   ✅ Sistema integrado")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Erro no teste: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Função principal"""
    print("🔧 Iniciando teste de integração Gemma 3N...")
    
    # Executar teste assíncrono
    success = asyncio.run(test_gemma_integration())
    
    if success:
        print("\n🎉 Integração funcionando perfeitamente!")
    else:
        print("\n❌ Integração falhou!")
        sys.exit(1)

if __name__ == "__main__":
    main()
