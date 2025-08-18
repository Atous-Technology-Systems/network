#!/usr/bin/env python3
"""
Script para iniciar o servidor com inicialização do database
"""
import sys
import os
import time

# Adicionar o diretório raiz ao path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def initialize_database():
    """Inicializa o database antes de iniciar o servidor"""
    try:
        print(" Inicializando database...")
        
        from atous_sec_network.database.database import initialize_database as init_db
        
        success = init_db()
        if success:
            print(" Database inicializado com sucesso")
            return True
        else:
            print("Falha ao inicializar database")
            return False
            
    except Exception as e:
        print(f" Erro ao inicializar database: {e}")
        return False

def start_server():
    """Inicia o servidor FastAPI"""
    try:
        print(" Iniciando servidor FastAPI...")
        
        # Importar e executar o servidor
        from atous_sec_network.api.server import app
        import uvicorn
        
        # Inicializar variáveis de estado
        app.state.start_time = time.time()
        app.state.total_requests = 0
        app.state.active_connections = 0
        app.state.errors_count = 0
        app.state.threats_blocked = 0
        app.state.anomalies_detected = 0
        app.state.rate_limit_hits = 0
        
        print(" Servidor configurado, iniciando uvicorn...")
        
        # Iniciar servidor
        uvicorn.run(app, host="127.0.0.1", port=8000)
        
    except Exception as e:
        print(f" Erro ao iniciar servidor: {e}")
        return False

def main():
    """Função principal"""
    print(" ATous Secure Network - Inicializando...")
    print("=" * 50)
    
    # 1. Inicializar database
    if not initialize_database():
        print(" Falha na inicialização do database. Abortando.")
        return 1
    
    # 2. Iniciar servidor
    try:
        start_server()
    except KeyboardInterrupt:
        print("\n Servidor interrompido pelo usuário")
        return 0
    except Exception as e:
        print(f" Erro no servidor: {e}")
        return 1

    return 0

if __name__ == "__main__":
    exit(main())
