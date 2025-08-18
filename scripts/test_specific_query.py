#!/usr/bin/env python3
"""
Script para testar a pergunta específica sobre ameaças bloqueadas
"""
import requests
import json

def test_threats_query():
    """Testa a pergunta sobre ameaças bloqueadas"""
    base_url = "http://127.0.0.1:8000"
    
    print("🧪 Testando pergunta específica sobre ameaças bloqueadas...")
    print("=" * 60)
    
    # Payload da pergunta
    payload = {
        "question": "Quais foram as últimas ameaças bloqueadas pelo sistema?",
        "context": {
            "include_security_data": True,
            "include_user_stats": True
        },
        "include_system_context": True
    }
    
    try:
        # Fazer requisição
        response = requests.post(
            f"{base_url}/api/llm/query",
            json=payload,
            timeout=10
        )
        
        if response.status_code == 200:
            print("✅ Sucesso!")
            result = response.json()
            
            print(f"\n📝 Pergunta: {payload['question']}")
            print(f"💬 Resposta: {result.get('answer', 'N/A')}")
            print(f"🎯 Confiança: {result.get('confidence', 0):.2f}")
            print(f"📍 Fontes: {', '.join(result.get('sources', []))}")
            print(f"⏱️  Tempo: {result.get('processing_time', 0):.4f}s")
            
            # Mostrar metadados
            metadata = result.get('metadata', {})
            print(f"📊 Tipo de pergunta: {metadata.get('question_type', 'N/A')}")
            print(f"📏 Tamanho da resposta: {metadata.get('response_length', 0)} caracteres")
            print(f"🔗 Tem contexto: {metadata.get('has_context', False)}")
            
        else:
            print(f"❌ Erro {response.status_code}: {response.text}")
            
    except Exception as e:
        print(f"❌ Falha: {e}")

def main():
    """Função principal"""
    test_threats_query()

if __name__ == "__main__":
    main()
