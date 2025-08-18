#!/usr/bin/env python3
"""
Script para testar WebSocket simples
"""
import asyncio
import websockets
import json

async def test_websocket():
    """Testa WebSocket simples"""
    uri = "ws://127.0.0.1:8000/api/llm/ws"
    
    print(f" Testando WebSocket em: {uri}")
    
    try:
        async with websockets.connect(uri) as websocket:
            print(" Conectado ao WebSocket!")
            
            # Enviar mensagem de teste
            test_message = "Olá, WebSocket!"
            print(f" Enviando: {test_message}")
            await websocket.send(test_message)
            
            # Receber resposta
            response = await websocket.recv()
            print(f" Recebido: {response}")
            
            # Fechar conexão
            await websocket.close()
            print(" Conexão fechada")
            
    except websockets.exceptions.InvalidURI:
        print("URI inválida")
    except websockets.exceptions.ConnectionClosed:
        print(" Conexão fechada")
    except websockets.exceptions.InvalidStatusCode as e:
        print(f" Status code inválido: {e}")
    except Exception as e:
        print(f" Erro: {e}")

def main():
    """Função principal"""
    asyncio.run(test_websocket())

if __name__ == "__main__":
    main()
