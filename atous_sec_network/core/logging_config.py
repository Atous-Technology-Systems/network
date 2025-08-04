
import os
import logging
import logging.config
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime


class LoggingConfig:
    """Configuração centralizada de logging para o sistema ATous"""
    
    def __init__(self, log_dir: str = None, log_level: str = "INFO"):
        """
        Inicializa a configuração de logging
        
        Args:
            log_dir: Diretório para arquivos de log
            log_level: Nível de log padrão
        """
        self.log_level = log_level.upper()
        
        # Configurar diretório de logs
        if log_dir:
            self.log_dir = Path(log_dir)
        else:
            # Usar diretório padrão relativo ao projeto
            project_root = Path(__file__).parent.parent.parent
            self.log_dir = project_root / "logs"
        
        # Criar diretório se não existir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configurar caminhos dos arquivos de log
        self.general_log_file = self.log_dir / "atous_network.log"
        self.security_log_file = self.log_dir / "security.log"
        self.error_log_file = self.log_dir / "errors.log"
    
    def get_config(self) -> Dict[str, Any]:
        """
        Retorna a configuração de logging como dicionário
        
        Returns:
            Dict com configuração completa de logging
        """
        return {
            "version": 1,
            "disable_existing_loggers": False,
            
            "formatters": {
                "standard": {
                    "format": "%(asctime)s [%(levelname)8s] %(name)s: %(message)s",
                    "datefmt": "%Y-%m-%d %H:%M:%S"
                },
                "detailed": {
                    "format": "%(asctime)s [%(levelname)8s] %(name)s [%(filename)s:%(lineno)d] %(funcName)s(): %(message)s",
                    "datefmt": "%Y-%m-%d %H:%M:%S"
                },
                "security": {
                    "format": "%(asctime)s [SECURITY] [%(levelname)8s] %(name)s: %(message)s",
                    "datefmt": "%Y-%m-%d %H:%M:%S"
                }
            },
            
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "level": "INFO",
                    "formatter": "standard",
                    "stream": "ext://sys.stdout"
                },
                "file_general": {
                    "class": "logging.handlers.RotatingFileHandler",
                    "level": self.log_level,
                    "formatter": "detailed",
                    "filename": str(self.general_log_file),
                    "maxBytes": 10485760,  # 10MB
                    "backupCount": 5,
                    "encoding": "utf-8"
                },
                "file_security": {
                    "class": "logging.handlers.RotatingFileHandler",
                    "level": "INFO",
                    "formatter": "security",
                    "filename": str(self.security_log_file),
                    "maxBytes": 10485760,  # 10MB
                    "backupCount": 10,
                    "encoding": "utf-8"
                },
                "file_errors": {
                    "class": "logging.handlers.RotatingFileHandler",
                    "level": "WARNING",
                    "formatter": "detailed",
                    "filename": str(self.error_log_file),
                    "maxBytes": 10485760,  # 10MB
                    "backupCount": 10,
                    "encoding": "utf-8"
                }
            },
            
            "loggers": {
                "atous_sec_network": {
                    "level": self.log_level,
                    "handlers": ["console", "file_general", "file_errors"],
                    "propagate": False
                },
                "atous_sec_network.security": {
                    "level": "INFO",
                    "handlers": ["console", "file_security", "file_errors"],
                    "propagate": False
                },
                "atous_sec_network.core.model_manager_impl": {
                    "level": self.log_level,
                    "handlers": ["console", "file_general", "file_errors"],
                    "propagate": False
                },
                "root": {
                    "level": "WARNING",
                    "handlers": ["console", "file_errors"]
                }
            }
        }
    
    def setup_logging(self) -> logging.Logger:
        """
        Configura o sistema de logging
        
        Returns:
            Logger principal do sistema
        """
        config = self.get_config()
        logging.config.dictConfig(config)
        
        # Garantir que os arquivos de log sejam criados
        self._ensure_log_files_created()
        
        # Retornar logger principal
        return logging.getLogger("atous_sec_network")
    
    def _ensure_log_files_created(self) -> None:
        """
        Garante que os arquivos de log sejam criados
        """
        # Criar arquivos vazios se não existirem
        for log_file in [self.general_log_file, self.security_log_file, self.error_log_file]:
            if not log_file.exists():
                log_file.touch()
        
        # Forçar criação dos handlers para garantir que os arquivos sejam inicializados
        test_logger = logging.getLogger("atous_sec_network")
        test_logger.info("Sistema de logging inicializado")
        
        security_logger = logging.getLogger("atous_sec_network.security")
        security_logger.info("Logger de segurança inicializado")
        
        # Forçar flush dos handlers
        for handler in test_logger.handlers:
            if hasattr(handler, 'flush'):
                handler.flush()
        
        for handler in security_logger.handlers:
            if hasattr(handler, 'flush'):
                handler.flush()


# Instância global de configuração
_logging_config: Optional[LoggingConfig] = None
_is_configured: bool = False


def setup_logging(log_level: str = None, log_dir: str = None) -> logging.Logger:
    """
    Configura o sistema de logging globalmente
    
    Args:
        log_level: Nível de log (padrão: INFO ou LOG_LEVEL env var)
        log_dir: Diretório de logs (padrão: ./logs ou LOG_DIR env var)
    
    Returns:
        Logger principal do sistema
    """
    global _logging_config, _is_configured
    
    # Usar variáveis de ambiente se não especificado
    if log_level is None:
        log_level = os.getenv("LOG_LEVEL", "INFO")
    
    if log_dir is None:
        log_dir = os.getenv("LOG_DIR")
    
    # Criar configuração se não existir ou se parâmetros mudaram
    if not _is_configured or _logging_config is None:
        _logging_config = LoggingConfig(log_dir=log_dir, log_level=log_level)
        logger = _logging_config.setup_logging()
        _is_configured = True
        
        # Log inicial do sistema
        logger.info("ATous Secure Network - Sistema de Logging Inicializado")
        logger.info(f"Diretório de logs: {_logging_config.log_dir}")
        logger.info(f"Nível de log: {log_level}")
        
        return logger
    
    return logging.getLogger("atous_sec_network")


def get_logger(name: str) -> logging.Logger:
    """
    Obtém um logger específico do sistema
    
    Args:
        name: Nome do módulo/componente
    
    Returns:
        Logger configurado para o módulo
    """
    global _is_configured
    
    # Configurar logging se ainda não foi feito
    if not _is_configured:
        setup_logging()
    
    # Retornar logger com namespace do sistema
    full_name = f"atous_sec_network.{name}"
    return logging.getLogger(full_name)


def get_security_logger(component: str = "security") -> logging.Logger:
    """
    Obtém logger específico para eventos de segurança
    
    Args:
        component: Componente de segurança (abiss, nnis, etc.)
    
    Returns:
        Logger de segurança configurado
    """
    return get_logger(f"security.{component}")


def log_performance(func_name: str, duration: float, logger: logging.Logger = None) -> None:
    """
    Log de performance para funções críticas
    
    Args:
        func_name: Nome da função
        duration: Duração em segundos
        logger: Logger específico (opcional)
    """
    if logger is None:
        logger = get_logger("performance")
    
    if duration > 1.0:
        logger.warning(f"Performance: {func_name} levou {duration:.2f}s")
    else:
        logger.debug(f"Performance: {func_name} executado em {duration:.3f}s")


def log_security_event(event_type: str, details: str, severity: str = "INFO") -> None:
    """
    Log específico para eventos de segurança
    
    Args:
        event_type: Tipo do evento (ANOMALY, THREAT, ACCESS, etc.)
        details: Detalhes do evento
        severity: Severidade (INFO, WARNING, ERROR, CRITICAL)
    """
    security_logger = get_security_logger()
    
    message = f"[{event_type}] {details}"
    
    if severity.upper() == "CRITICAL":
        security_logger.critical(message)
    elif severity.upper() == "ERROR":
        security_logger.error(message)
    elif severity.upper() == "WARNING":
        security_logger.warning(message)
    else:
        security_logger.info(message)


# Configuração automática se executado como módulo principal
if __name__ == "__main__":
    # Teste básico do sistema de logging
    logger = setup_logging(log_level="DEBUG")
    
    logger.debug("Teste de log DEBUG")
    logger.info("Teste de log INFO")
    logger.warning("Teste de log WARNING")
    logger.error("Teste de log ERROR")
    
    # Teste de logger de segurança
    log_security_event("TEST", "Teste do sistema de logging de segurança")
    
    # Teste de performance
    log_performance("test_function", 0.5)
    
    print(f"Sistema de logging testado. Logs salvos em: {_logging_config.log_dir}")