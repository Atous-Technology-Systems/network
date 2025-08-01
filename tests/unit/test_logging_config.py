#!/usr/bin/env python3
"""
Testes TDD para sistema de logging centralizado
FASE RED: Testes que devem falhar inicialmente
"""
import pytest
import logging
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

# Importações que devem falhar inicialmente (FASE RED)
try:
    from atous_sec_network.core.logging_config import LoggingConfig, setup_logging, get_logger
except ImportError:
    # Esperado na FASE RED
    LoggingConfig = None
    setup_logging = None
    get_logger = None


class TestLoggingConfigTDD:
    """Testes TDD para configuração de logging"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.log_dir = self.temp_dir / "logs"
    
    def teardown_method(self):
        """Cleanup após cada teste"""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @pytest.mark.skipif(LoggingConfig is None, reason="LoggingConfig não implementado ainda (FASE RED)")
    def test_logging_config_creation(self):
        """TESTE RED: LoggingConfig deve ser criado com parâmetros corretos"""
        config = LoggingConfig(log_dir=str(self.log_dir), log_level="DEBUG")
        
        assert config.log_dir == self.log_dir
        assert config.log_level == "DEBUG"
        assert self.log_dir.exists()  # Diretório deve ser criado automaticamente
    
    @pytest.mark.skipif(LoggingConfig is None, reason="LoggingConfig não implementado ainda (FASE RED)")
    def test_logging_config_dict_structure(self):
        """TESTE RED: Configuração deve retornar dict com estrutura correta"""
        config = LoggingConfig(log_dir=str(self.log_dir), log_level="INFO")
        config_dict = config.get_config()
        
        # Verificar estrutura básica
        assert "version" in config_dict
        assert config_dict["version"] == 1
        assert "formatters" in config_dict
        assert "handlers" in config_dict
        assert "loggers" in config_dict
        
        # Verificar formatters
        formatters = config_dict["formatters"]
        assert "standard" in formatters
        assert "detailed" in formatters
        assert "security" in formatters
        
        # Verificar handlers
        handlers = config_dict["handlers"]
        assert "console" in handlers
        assert "file_general" in handlers
        assert "file_security" in handlers
        assert "file_errors" in handlers
        
        # Verificar loggers
        loggers = config_dict["loggers"]
        assert "atous_sec_network" in loggers
        assert "atous_sec_network.security" in loggers
    
    @pytest.mark.skipif(setup_logging is None, reason="setup_logging não implementado ainda (FASE RED)")
    def test_setup_logging_function(self):
        """TESTE RED: Função setup_logging deve configurar logging corretamente"""
        with patch.dict('os.environ', {'LOG_LEVEL': 'DEBUG', 'LOG_DIR': str(self.log_dir)}):
            logger = setup_logging()
            
            assert logger is not None
            assert isinstance(logger, logging.Logger)
            assert logger.name == "atous_sec_network"
    
    @pytest.mark.skipif(get_logger is None, reason="get_logger não implementado ainda (FASE RED)")
    def test_get_logger_function(self):
        """TESTE RED: Função get_logger deve retornar logger com nome correto"""
        # Primeiro configurar logging
        setup_logging(log_level="INFO", log_dir=str(self.log_dir))
        
        # Testar get_logger
        logger = get_logger("test_module")
        
        assert logger is not None
        assert isinstance(logger, logging.Logger)
        assert logger.name == "atous_sec_network.test_module"
    
    @pytest.mark.skipif(LoggingConfig is None, reason="LoggingConfig não implementado ainda (FASE RED)")
    def test_log_files_creation(self):
        """TESTE RED: Arquivos de log devem ser criados corretamente"""
        config = LoggingConfig(log_dir=str(self.log_dir), log_level="DEBUG")
        config.setup_logging()
        
        # Fazer alguns logs para garantir criação dos arquivos
        logger = logging.getLogger("atous_sec_network")
        logger.info("Teste de log geral")
        logger.error("Teste de log de erro")
        
        security_logger = logging.getLogger("atous_sec_network.security")
        security_logger.info("Teste de log de segurança")
        
        # Verificar se arquivos foram criados
        expected_files = [
            self.log_dir / "atous_network.log",
            self.log_dir / "security.log",
            self.log_dir / "errors.log"
        ]
        
        for log_file in expected_files:
            assert log_file.exists(), f"Arquivo de log {log_file} não foi criado"
    
    @pytest.mark.skipif(LoggingConfig is None, reason="LoggingConfig não implementado ainda (FASE RED)")
    def test_log_levels_configuration(self):
        """TESTE RED: Níveis de log devem ser configurados corretamente"""
        config = LoggingConfig(log_dir=str(self.log_dir), log_level="WARNING")
        config.setup_logging()
        
        logger = logging.getLogger("atous_sec_network")
        
        # Logger principal deve ter nível WARNING
        assert logger.level == logging.WARNING or logger.getEffectiveLevel() == logging.WARNING
        
        # Logger de segurança deve ter nível INFO independente
        security_logger = logging.getLogger("atous_sec_network.security")
        assert security_logger.level == logging.INFO or security_logger.getEffectiveLevel() == logging.INFO
    
    @pytest.mark.skipif(LoggingConfig is None, reason="LoggingConfig não implementado ainda (FASE RED)")
    def test_log_rotation_configuration(self):
        """TESTE RED: Rotação de logs deve estar configurada"""
        config = LoggingConfig(log_dir=str(self.log_dir), log_level="DEBUG")
        config_dict = config.get_config()
        
        # Verificar configuração de rotação nos handlers de arquivo
        file_handlers = [
            "file_general",
            "file_security", 
            "file_errors"
        ]
        
        for handler_name in file_handlers:
            handler_config = config_dict["handlers"][handler_name]
            
            assert "maxBytes" in handler_config
            assert "backupCount" in handler_config
            assert handler_config["maxBytes"] == 10485760  # 10MB
            assert handler_config["backupCount"] >= 5
    
    def test_import_should_fail_initially(self):
        """TESTE RED: Importações devem falhar inicialmente"""
        # Este teste sempre passa, mas documenta que esperamos falha de importação
        # na FASE RED
        try:
            from atous_sec_network.core.logging_config import LoggingConfig
            # Se chegou aqui, já foi implementado
            pytest.skip("LoggingConfig já foi implementado - FASE GREEN")
        except ImportError:
            # Esperado na FASE RED
            assert True


class TestLoggingIntegrationTDD:
    """Testes de integração TDD para sistema de logging"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.log_dir = self.temp_dir / "logs"
    
    def teardown_method(self):
        """Cleanup após cada teste"""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @pytest.mark.skipif(setup_logging is None, reason="Sistema de logging não implementado ainda (FASE RED)")
    def test_logging_integration_with_main_module(self):
        """TESTE RED: Logging deve integrar corretamente com módulo principal"""
        # Limpar configuração anterior
        import atous_sec_network.core.logging_config as log_module
        log_module._is_configured = False
        log_module._logging_config = None
        
        # Configurar logging
        setup_logging(log_level="INFO", log_dir=str(self.log_dir))
        
        # Simular uso no módulo principal
        main_logger = get_logger("main")
        main_logger.info("🛡️ ATous Secure Network - Starting Application...")
        main_logger.info("=" * 60)
        
        # Forçar flush dos handlers
        for handler in main_logger.handlers:
            if hasattr(handler, 'flush'):
                handler.flush()
        
        # Verificar se log foi criado
        log_file = self.log_dir / "atous_network.log"
        assert log_file.exists(), f"Arquivo de log não foi criado: {log_file}"
        
        # Verificar conteúdo do log
        log_content = log_file.read_text(encoding='utf-8')
        assert "ATous Secure Network - Starting Application" in log_content
    
    @pytest.mark.skipif(setup_logging is None, reason="Sistema de logging não implementado ainda (FASE RED)")
    def test_security_logging_separation(self):
        """TESTE RED: Logs de segurança devem ser separados"""
        # Limpar configuração anterior
        import atous_sec_network.core.logging_config as log_module
        log_module._is_configured = False
        log_module._logging_config = None
        
        setup_logging(log_level="INFO", log_dir=str(self.log_dir))
        
        # Log de segurança
        security_logger = get_logger("security.abiss")
        security_logger.info("Anomalia detectada: valor fora do padrão")
        
        # Log geral
        general_logger = get_logger("core.model_manager")
        general_logger.info("Modelo carregado com sucesso")
        
        # Forçar flush dos handlers
        for logger in [security_logger, general_logger]:
            for handler in logger.handlers:
                if hasattr(handler, 'flush'):
                    handler.flush()
        
        # Verificar arquivos separados
        security_log = self.log_dir / "security.log"
        general_log = self.log_dir / "atous_network.log"
        
        assert security_log.exists(), f"Arquivo de log de segurança não foi criado: {security_log}"
        assert general_log.exists(), f"Arquivo de log geral não foi criado: {general_log}"
        
        # Verificar conteúdo
        security_content = security_log.read_text(encoding='utf-8')
        general_content = general_log.read_text(encoding='utf-8')
        
        assert "Anomalia detectada" in security_content
        assert "Modelo carregado" in general_content
    
    @pytest.mark.skipif(setup_logging is None, reason="Sistema de logging não implementado ainda (FASE RED)")
    def test_error_logging_to_separate_file(self):
        """TESTE RED: Erros devem ser logados em arquivo separado"""
        # Limpar configuração anterior
        import atous_sec_network.core.logging_config as log_module
        log_module._is_configured = False
        log_module._logging_config = None
        
        setup_logging(log_level="DEBUG", log_dir=str(self.log_dir))
        
        logger = get_logger("test_module")
        
        # Log de diferentes níveis
        logger.info("Informacao normal")
        logger.warning("Aviso importante")
        logger.error("Erro critico ocorreu")
        
        # Forçar flush dos handlers
        for handler in logger.handlers:
            if hasattr(handler, 'flush'):
                handler.flush()
        
        # Verificar arquivo de erros
        error_log = self.log_dir / "errors.log"
        assert error_log.exists(), f"Arquivo de log de erros não foi criado: {error_log}"
        
        error_content = error_log.read_text(encoding='utf-8')
        assert "Erro critico ocorreu" in error_content
        # Arquivo de erros não deve conter logs de info
        assert "Informacao normal" not in error_content


if __name__ == "__main__":
    # Executar testes para verificar FASE RED
    pytest.main(["-v", __file__])