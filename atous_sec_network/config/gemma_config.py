"""
Configuração Gemma para ATous Secure Network
Gerado automaticamente por configure_gemma.py
"""

GEMMA_CONFIG = {
    "abiss_config": {
        "model_name": "google/gemma-1.1-2b-it",
        "model_params": {'torch_dtype': 'float32', 'device_map': 'auto', 'low_cpu_mem_usage': True, 'trust_remote_code': True},
        "pipeline_params": {'max_length': 256, 'temperature': 0.7, 'do_sample': True, 'top_p': 0.9, 'pad_token_id': 0},
        "memory_size": 1000,
        "threat_threshold": 0.7,
        "simulation_mode": false
    },
    "nnis_config": {
        "model_name": "google/gemma-1.1-2b-it",
        "model_params": {'torch_dtype': 'float32', 'device_map': 'auto', 'low_cpu_mem_usage': True, 'trust_remote_code': True},
        "memory_size": 1000,
        "simulation_mode": false
    }
}
