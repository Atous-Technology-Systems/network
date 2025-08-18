"""
Configuração para o modelo Gemma 3N

Este módulo contém todas as configurações necessárias para:
- Carregamento do modelo
- Parâmetros de inferência
- Configurações de fine-tuning
- Otimizações de performance
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional

# Configurações do modelo
GEMMA_3N_CONFIG = {
    # Caminhos
    "model_path": "models\gemma-3n-hf",
    "tokenizer_path": "models\gemma-3n-hf",
    "config_path": ""models\gemma-3n-hf"/config.json",
    
    # Parâmetros de carregamento
    "torch_dtype": "float16",  # float16 para economia de memória
    "device_map": "auto",      # Mapeamento automático de dispositivo
    "trust_remote_code": True, # Confiar em código remoto do modelo
    
    # Parâmetros de inferência
    "max_length": 2048,        # Comprimento máximo da sequência
    "temperature": 0.7,        # Temperatura para geração (0.0 = determinístico, 1.0 = aleatório)
    "top_p": 0.9,             # Nucleus sampling (0.9 = 90% das probabilidades mais altas)
    "top_k": 50,              # Top-k sampling
    "do_sample": True,         # Habilitar sampling
    "pad_token_id": None,      # ID do token de padding (será definido automaticamente)
    "eos_token_id": None,      # ID do token de fim de sequência
    
    # Configurações de memória
    "low_cpu_mem_usage": True, # Baixo uso de CPU
    "offload_folder": "offload", # Pasta para offload de camadas
    
    # Configurações de fine-tuning
    "learning_rate": 1e-5,     # Taxa de aprendizado para fine-tuning
    "batch_size": 1,           # Tamanho do batch (1 para inferência)
    "gradient_accumulation_steps": 4, # Passos de acumulação de gradiente
    
    # Configurações de cache
    "cache_dir": ".cache",     # Diretório de cache
    "use_cache": True,         # Usar cache de atenção
    
    # Configurações de segurança
    "max_input_length": 1024,  # Comprimento máximo de entrada
    "max_output_length": 512,  # Comprimento máximo de saída
    
    # Configurações de performance
    "num_attention_heads": 32, # Número de cabeças de atenção
    "hidden_size": 2048,       # Tamanho da camada oculta
    "intermediate_size": 8192, # Tamanho da camada intermediária
    "num_hidden_layers": 24,   # Número de camadas ocultas
}

# Configurações de contexto do sistema
SYSTEM_CONTEXT_CONFIG = {
    "max_context_length": 2000,    # Comprimento máximo do contexto
    "include_system_info": True,   # Incluir informações do sistema
    "include_security_data": True, # Incluir dados de segurança
    "include_user_stats": True,    # Incluir estatísticas de usuários
    "include_performance_metrics": True, # Incluir métricas de performance
}

# Configurações de fine-tuning automático
AUTO_FINE_TUNING_CONFIG = {
    "enabled": True,               # Habilitar fine-tuning automático
    "interval_hours": 24,          # Intervalo em horas
    "min_improvement_threshold": 0.01, # Threshold mínimo de melhoria
    "max_training_time_minutes": 30,   # Tempo máximo de treinamento
    "save_checkpoints": True,      # Salvar checkpoints
    "checkpoint_dir": "checkpoints",   # Diretório de checkpoints
}

# Configurações de cache e performance
CACHE_CONFIG = {
    "enabled": True,               # Habilitar cache
    "ttl_seconds": 3600,          # Time-to-live em segundos
    "max_size": 1000,             # Tamanho máximo do cache
    "eviction_policy": "lru",     # Política de evição (LRU)
}

# Configurações de logging
LOGGING_CONFIG = {
    "level": "INFO",               # Nível de logging
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file": "logs/llm_service.log", # Arquivo de log
    "max_file_size_mb": 100,      # Tamanho máximo do arquivo
    "backup_count": 5,            # Número de backups
}

def get_gemma_config() -> Dict[str, Any]:
    """Retorna a configuração completa do Gemma 3N"""
    return GEMMA_3N_CONFIG.copy()

def get_system_context_config() -> Dict[str, Any]:
    """Retorna a configuração de contexto do sistema"""
    return SYSTEM_CONTEXT_CONFIG.copy()

def get_auto_fine_tuning_config() -> Dict[str, Any]:
    """Retorna a configuração de fine-tuning automático"""
    return AUTO_FINE_TUNING_CONFIG.copy()

def get_cache_config() -> Dict[str, Any]:
    """Retorna a configuração de cache"""
    return CACHE_CONFIG.copy()

def get_logging_config() -> Dict[str, Any]:
    """Retorna a configuração de logging"""
    return LOGGING_CONFIG.copy()

def validate_model_path() -> bool:
    """Valida se o caminho do modelo existe"""
    model_path = Path(GEMMA_3N_CONFIG["model_path"])
    return model_path.exists() and model_path.is_dir()

def get_model_info() -> Dict[str, Any]:
    """Retorna informações sobre o modelo"""
    model_path = Path(GEMMA_3N_CONFIG["model_path"])
    
    info = {
        "model_path": str(model_path),
        "exists": model_path.exists(),
        "is_directory": model_path.is_dir() if model_path.exists() else False,
        "size_mb": 0,
        "files": []
    }
    
    if model_path.exists() and model_path.is_dir():
        try:
            # Calcular tamanho total
            total_size = 0
            files = []
            for file_path in model_path.rglob("*"):
                if file_path.is_file():
                    file_size = file_path.stat().st_size
                    total_size += file_size
                    files.append({
                        "name": str(file_path.relative_to(model_path)),
                        "size_mb": round(file_size / (1024 * 1024), 2)
                    })
            
            info["size_mb"] = round(total_size / (1024 * 1024), 2)
            info["files"] = files[:10]  # Primeiros 10 arquivos
            
        except Exception as e:
            info["error"] = str(e)
    
    return info

def get_optimized_config_for_device(device_type: str = "auto") -> Dict[str, Any]:
    """Retorna configuração otimizada para o tipo de dispositivo"""
    config = get_gemma_config()
    
    if device_type == "cpu":
        config.update({
            "torch_dtype": "float32",
            "device_map": "cpu",
            "low_cpu_mem_usage": True,
            "offload_folder": None
        })
    elif device_type == "gpu":
        config.update({
            "torch_dtype": "float16",
            "device_map": "auto",
            "low_cpu_mem_usage": False
        })
    elif device_type == "low_memory":
        config.update({
            "torch_dtype": "float16",
            "device_map": "auto",
            "low_cpu_mem_usage": True,
            "offload_folder": "offload",
            "max_length": 1024,
            "max_input_length": 512,
            "max_output_length": 256
        })
    
    return config

def get_fine_tuning_hyperparameters() -> Dict[str, Any]:
    """Retorna hiperparâmetros para fine-tuning"""
    return {
        "learning_rate": 1e-5,
        "batch_size": 1,
        "gradient_accumulation_steps": 4,
        "warmup_steps": 100,
        "weight_decay": 0.01,
        "max_grad_norm": 1.0,
        "num_train_epochs": 1,
        "save_steps": 500,
        "eval_steps": 500,
        "logging_steps": 100,
        "save_total_limit": 3,
        "fp16": True,
        "dataloader_pin_memory": False
    }
