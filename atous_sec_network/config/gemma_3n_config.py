"""
Configuração Gemma 3N para ATous Secure Network
Modelo: google/gemma-3n-E4B
"""

GEMMA_3N_CONFIG = {
    "model_name": "google/gemma-3n-E4B",
    "model_params": {'torch_dtype': 'float16', 'device_map': 'auto', 'low_cpu_mem_usage': True, 'trust_remote_code': True, 'use_cache': True, 'attn_implementation': 'eager'},
    "pipeline_params": {'max_length': 512, 'max_new_tokens': 256, 'temperature': 0.7, 'do_sample': True, 'top_p': 0.9, 'top_k': 50, 'repetition_penalty': 1.1, 'pad_token_id': 0, 'eos_token_id': 1},
    "memory_size": 1000,
    "threat_threshold": 0.7,
    "simulation_mode": False,
    "enable_monitoring": True,
    "learning_rate": 0.01
}

# Configurações específicas para ABISS
ABISS_CONFIG = GEMMA_3N_CONFIG.copy()

# Configurações específicas para NNIS
NNIS_CONFIG = GEMMA_3N_CONFIG.copy()
NNIS_CONFIG.update({
    "immune_cell_count": 50,
    "memory_cell_count": 100,
    "threat_threshold": 0.8
})
