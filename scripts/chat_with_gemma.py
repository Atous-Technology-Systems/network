#!/usr/bin/env python3
"""
Chat interativo com Gemma 3N TFLite
"""

import os
import sys
import asyncio
from pathlib import Path

# Adicionar o projeto ao path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

async def chat_with_gemma():
    """Chat interativo com Gemma 3N TFLite"""
    print("🤖 Chat com Gemma 3N TFLite - ATous Secure Network")
    print("=" * 60)
    print("💡 Digite 'sair' para encerrar o chat")
    print("💡 Digite 'ajuda' para ver comandos disponíveis")
    print("💡 Digite 'status' para ver status do sistema")
    print("=" * 60)
    
    try:
        from atous_sec_network.ml.llm_service import LLMService
        
        # Inicializar LLM service
        print("\n🔄 Inicializando Gemma 3N TFLite...")
        llm_service = LLMService("models/gemma-3n/extracted")
        
        # Carregar modelo
        success = await llm_service.load_model()
        if not success:
            print("❌ Falha ao carregar modelo")
            return
        
        print("✅ Gemma 3N TFLite carregado e pronto para conversar!")
        print(f"📊 Modelo: {llm_service.get_metrics()['model_type']}")
        print(f"🎯 Confiança base: 0.70-0.80")
        print()
        
        # Loop de chat
        conversation_history = []
        
        while True:
            try:
                # Input do usuário
                user_input = input("\n👤 Você: ").strip()
                
                if not user_input:
                    continue
                
                # Comandos especiais
                if user_input.lower() == 'sair':
                    print("\n👋 Até logo! Gemma 3N TFLite encerrando...")
                    break
                
                elif user_input.lower() == 'ajuda':
                    print("\n📚 Comandos disponíveis:")
                    print("   sair     - Encerrar o chat")
                    print("   ajuda    - Mostrar esta ajuda")
                    print("   status   - Status do sistema")
                    print("   limpar   - Limpar histórico")
                    print("   métricas - Ver métricas do LLM")
                    print("   contexto - Ver contexto atual")
                    continue
                
                elif user_input.lower() == 'status':
                    print("\n📊 Status do Sistema:")
                    metrics = llm_service.get_metrics()
                    print(f"   Modelo: {metrics['model_type']}")
                    print(f"   Carregado: {metrics['is_loaded']}")
                    print(f"   Consultas: {metrics['total_queries']}")
                    print(f"   Cache: {metrics['cache_size']} entradas")
                    print(f"   Tempo médio: {metrics['average_response_time']:.4f}s")
                    continue
                
                elif user_input.lower() == 'limpar':
                    conversation_history.clear()
                    print("\n🧹 Histórico de conversa limpo!")
                    continue
                
                elif user_input.lower() == 'métricas':
                    print("\n📈 Métricas Detalhadas:")
                    metrics = llm_service.get_metrics()
                    for key, value in metrics.items():
                        print(f"   {key}: {value}")
                    continue
                
                elif user_input.lower() == 'contexto':
                    print("\n🌐 Contexto do Sistema:")
                    context = await llm_service.get_system_context()
                    for key, value in context.items():
                        if isinstance(value, dict):
                            print(f"   {key}:")
                            for sub_key, sub_value in value.items():
                                print(f"     {sub_key}: {sub_value}")
                        else:
                            print(f"   {key}: {value}")
                    continue
                
                # Processar pergunta
                print("\n🤖 Gemma 3N TFLite está pensando...")
                
                # Adicionar ao histórico
                conversation_history.append({"role": "user", "content": user_input})
                
                # Obter resposta
                response = await llm_service.query(user_input)
                
                # Adicionar resposta ao histórico
                conversation_history.append({"role": "assistant", "content": response.answer})
                
                # Exibir resposta
                print(f"\n🤖 Gemma 3N TFLite: {response.answer}")
                print(f"🎯 Confiança: {response.confidence:.2f}")
                print(f"📍 Fontes: {', '.join(response.sources)}")
                
                # Manter histórico limitado
                if len(conversation_history) > 20:
                    conversation_history = conversation_history[-20:]
                
            except KeyboardInterrupt:
                print("\n\n👋 Chat interrompido pelo usuário. Até logo!")
                break
            except Exception as e:
                print(f"\n❌ Erro: {e}")
                continue
        
        # Estatísticas finais
        print("\n📊 Estatísticas da Conversa:")
        metrics = llm_service.get_metrics()
        print(f"   Total de consultas: {metrics['total_queries']}")
        print(f"   Respostas bem-sucedidas: {metrics['successful_responses']}")
        print(f"   Tamanho do cache: {metrics['cache_size']}")
        print(f"   Tempo médio de resposta: {metrics['average_response_time']:.4f}s")
        
    except Exception as e:
        print(f"\n❌ Erro fatal: {e}")
        import traceback
        traceback.print_exc()

def main():
    """Função principal"""
    print("🚀 Iniciando chat com Gemma 3N TFLite...")
    
    # Executar chat assíncrono
    asyncio.run(chat_with_gemma())

if __name__ == "__main__":
    main()
