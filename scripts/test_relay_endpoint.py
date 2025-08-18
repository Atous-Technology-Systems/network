#!/usr/bin/env python3
"""
Script simples para testar o endpoint de status do relay
"""

import requests
import json

def test_relay_status():
    """Testa o endpoint de status do relay"""
    try:
        # Testar endpoint de status
        print("Testando endpoint /v1/relay/status...")
        response = requests.get("http://127.0.0.1:8000/v1/relay/status", timeout=10)
        
        print(f"Status Code: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Resposta: {json.dumps(data, indent=2, ensure_ascii=False)}")
            
            # Verificar campos obrigatórios
            required_fields = [
                "system_status", "active_agents", "total_messages", 
                "ttl_seconds", "last_cleanup", "version", "timestamp"
            ]
            
            print("\nVerificando campos obrigatórios:")
            for field in required_fields:
                if field in data:
                    print(f"✅ {field}: {data[field]} (tipo: {type(data[field]).__name__})")
                else:
                    print(f"❌ {field}: NÃO ENCONTRADO")
            
            # Testar outros endpoints para verificar integração
            print("\nTestando integração com outros endpoints...")
            
            # Testar heartbeat
            print("1. Testando heartbeat...")
            heartbeat_response = requests.post(
                "http://127.0.0.1:8000/v1/relay/heartbeat",
                json={"agent_id": "test-agent-123"},
                timeout=10
            )
            print(f"   Heartbeat status: {heartbeat_response.status_code}")
            
            # Verificar status novamente
            print("2. Verificando status após heartbeat...")
            status_response = requests.get("http://127.0.0.1:8000/v1/relay/status", timeout=10)
            if status_response.status_code == 200:
                status_data = status_response.json()
                print(f"   Agentes ativos: {status_data.get('active_agents', 'N/A')}")
                print(f"   Status do sistema: {status_data.get('system_status', 'N/A')}")
            
            # Testar envio de mensagem
            print("3. Testando envio de mensagem...")
            send_response = requests.post(
                "http://127.0.0.1:8000/v1/relay/send",
                json={
                    "from": "sender-123",
                    "to": "test-agent-123",
                    "payload": {"msg": "Teste de mensagem"}
                },
                timeout=10
            )
            print(f"   Send status: {send_response.status_code}")
            
            # Verificar status final
            print("4. Verificando status final...")
            final_response = requests.get("http://127.0.0.1:8000/v1/relay/status", timeout=10)
            if final_response.status_code == 200:
                final_data = final_response.json()
                print(f"   Agentes ativos: {final_data.get('active_agents', 'N/A')}")
                print(f"   Total de mensagens: {final_data.get('total_messages', 'N/A')}")
                print(f"   Status do sistema: {final_data.get('system_status', 'N/A')}")
            
        else:
            print(f"❌ Erro: {response.status_code}")
            print(f"Conteúdo: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Erro de conexão: Servidor não está rodando")
    except requests.exceptions.Timeout:
        print("❌ Erro de timeout: Servidor não respondeu a tempo")
    except Exception as e:
        print(f"❌ Erro inesperado: {e}")

if __name__ == "__main__":
    test_relay_status()
