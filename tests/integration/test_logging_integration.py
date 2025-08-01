#!/usr/bin/env python3
"""
Testes de Integração para Sistema de Logging
FASE REFACTOR: Validação da integração completa
"""
import pytest
import tempfile
import shutil
import os
from pathlib import Path
import subprocess
import sys


class TestLoggingSystemIntegration:
    """Testes de integração do sistema de logging completo"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.log_dir = self.temp_dir / "logs"
    
    def teardown_method(self):
        """Cleanup após cada teste"""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_main_module_logging_integration(self):
        """TESTE REFACTOR: Módulo principal deve usar logging centralizado"""
        # Configurar variáveis de ambiente para teste
        env = {
            "LOG_DIR": str(self.log_dir),
            "LOG_LEVEL": "INFO",
            "PYTHONPATH": str(Path.cwd())
        }
        
        # Executar o módulo principal (vai falhar, mas deve gerar logs)
        result = subprocess.run(
            [sys.executable, "-m", "atous_sec_network"],
            cwd=Path.cwd(),
            env={**dict(os.environ), **env},
            capture_output=True,
            text=True
        )
        
        # Verificar se arquivos de log foram criados
        general_log = self.log_dir / "atous_network.log"
        error_log = self.log_dir / "errors.log"
        
        assert general_log.exists(), "Arquivo de log geral não foi criado"
        assert error_log.exists(), "Arquivo de log de erros não foi criado"
        
        # Verificar conteúdo dos logs
        general_content = general_log.read_text(encoding='utf-8')
        error_content = error_log.read_text(encoding='utf-8')
        
        # Deve conter logs de inicialização
        assert "ATous Secure Network - Starting Application" in general_content
        assert "Testing core imports" in general_content
        
        # Deve conter logs de erro
        assert "Unexpected error" in error_content
    
    def test_module_initialization_logging(self):
        """TESTE REFACTOR: Inicialização do módulo deve gerar logs"""
        import os
        os.environ["LOG_DIR"] = str(self.log_dir)
        os.environ["LOG_LEVEL"] = "DEBUG"
        
        try:
            # Força a reconfiguração do logging
            from atous_sec_network.core.logging_config import setup_logging
            setup_logging()
            
            # Importar o módulo principal (isso deve gerar logs de inicialização)
            import atous_sec_network
            
            # Força flush dos handlers
            import logging
            for handler in logging.getLogger().handlers:
                handler.flush()
            
            # Verificar se logs de inicialização foram criados
            general_log = self.log_dir / "atous_network.log"
            assert general_log.exists(), f"Arquivo de log não foi criado na inicialização em {general_log}"
            
            log_content = general_log.read_text(encoding='utf-8')
            assert "ATous Secure Network - Módulo Principal Inicializado" in log_content or "Sistema de logging configurado" in log_content
            assert "Versão: 1.0.0" in log_content or "DEBUG" in log_content
            
        finally:
            # Limpa variáveis de ambiente
            if "LOG_DIR" in os.environ:
                del os.environ["LOG_DIR"]
            if "LOG_LEVEL" in os.environ:
                del os.environ["LOG_LEVEL"]
    
    def test_security_logging_functionality(self):
        """Testa a funcionalidade específica de logging de segurança."""
        # Configura variável de ambiente
        os.environ["LOG_DIR"] = str(self.log_dir)
        
        try:
            # Força a reconfiguração do logging
            from atous_sec_network.core.logging_config import setup_logging, get_security_logger, log_security_event
            setup_logging()
            
            # Testa logging de evento de segurança
            log_security_event("AUTHENTICATION", "Usuario logado com sucesso - user_id: 123", "INFO")
            
            # Força flush dos handlers
            import logging
            for handler in logging.getLogger('atous_sec_network.security').handlers:
                handler.flush()
            
            # Verifica se o arquivo de log de segurança foi criado
            security_log = self.log_dir / "security.log"
            assert security_log.exists(), f"Arquivo de log de segurança não foi criado em {security_log}"
            
            # Verifica conteúdo
            content = security_log.read_text(encoding='utf-8')
            assert "AUTHENTICATION" in content
            assert "Usuario logado com sucesso" in content
            
        finally:
            # Limpa variável de ambiente
             if "LOG_DIR" in os.environ:
                 del os.environ["LOG_DIR"]
    
    def test_log_rotation_configuration(self):
        """TESTE REFACTOR: Configuração de rotação deve estar ativa"""
        from atous_sec_network.core.logging_config import LoggingConfig
        
        config = LoggingConfig(log_dir=str(self.log_dir), log_level="DEBUG")
        config_dict = config.get_config()
        
        # Verificar configuração de rotação
        file_handlers = ["file_general", "file_security", "file_errors"]
        
        for handler_name in file_handlers:
            handler_config = config_dict["handlers"][handler_name]
            
            assert handler_config["class"] == "logging.handlers.RotatingFileHandler"
            assert handler_config["maxBytes"] == 10485760  # 10MB
            assert handler_config["backupCount"] >= 5
            assert handler_config["encoding"] == "utf-8"
    
    def test_environment_variable_configuration(self):
        """TESTE REFACTOR: Configuração via variáveis de ambiente"""
        import os
        
        # Configurar variáveis de ambiente
        os.environ["LOG_LEVEL"] = "WARNING"
        os.environ["LOG_DIR"] = str(self.log_dir)
        
        from atous_sec_network.core.logging_config import setup_logging
        
        # Limpar configuração anterior
        import atous_sec_network.core.logging_config as log_module
        log_module._is_configured = False
        log_module._logging_config = None
        
        # Configurar logging
        logger = setup_logging()
        
        # Verificar se configuração foi aplicada
        assert log_module._logging_config.log_level == "WARNING"
        assert str(log_module._logging_config.log_dir) == str(self.log_dir)
        
        # Limpar variáveis de ambiente
        del os.environ["LOG_LEVEL"]
        del os.environ["LOG_DIR"]
    
    def test_concurrent_logging_safety(self):
        """TESTE REFACTOR: Logging deve ser seguro para uso concorrente"""
        import threading
        import time
        
        # Configura variável de ambiente
        os.environ["LOG_DIR"] = str(self.log_dir)
        
        try:
            from atous_sec_network.core.logging_config import get_logger, setup_logging
            
            setup_logging()
            
            def log_worker(worker_id):
                """Worker que gera logs concorrentemente"""
                logger = get_logger(f"worker_{worker_id}")
                for i in range(10):
                    logger.info(f"Worker {worker_id} - Message {i}")
                    time.sleep(0.01)
            
            # Criar múltiplas threads
            threads = []
            for i in range(5):
                thread = threading.Thread(target=log_worker, args=(i,))
                threads.append(thread)
                thread.start()
            
            # Aguardar conclusão
            for thread in threads:
                thread.join()
            
            # Força flush dos handlers
            import logging
            for handler in logging.getLogger().handlers:
                handler.flush()
            
            # Verificar se logs foram criados sem corrupção
            general_log = self.log_dir / "atous_network.log"
            assert general_log.exists(), f"Arquivo de log não foi criado em {general_log}"
            
            log_content = general_log.read_text(encoding='utf-8')
            
            # Verificar se todas as mensagens foram logadas
            for worker_id in range(5):
                for msg_id in range(10):
                    assert f"Worker {worker_id} - Message {msg_id}" in log_content
                    
        finally:
            # Limpa variável de ambiente
             if "LOG_DIR" in os.environ:
                 del os.environ["LOG_DIR"]


if __name__ == "__main__":
    import os
    # Executar testes de integração
    pytest.main(["-v", __file__])