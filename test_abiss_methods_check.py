#!/usr/bin/env python3
"""
Script simples para verificar métodos disponíveis no sistema ABISS
"""
import sys
import os

# Adicionar o diretório raiz ao path
sys.path.insert(0, '.')

def check_abiss_methods():
    """Verifica métodos disponíveis no sistema ABISS"""
    try:
        from atous_sec_network.security.abiss_system import ABISSSystem
        print("✅ Módulo ABISS importado com sucesso")
        
        # Criar instância
        config = {
            "block_threshold": 0.9,
            "monitor_threshold": 0.75,
            "memory_size": 1000
        }
        
        abiss = ABISSSystem(config)
        print("✅ Instância ABISS criada com sucesso")
        
        # Listar métodos públicos
        methods = [m for m in dir(abiss) if not m.startswith('_')]
        print(f"\n📋 Métodos disponíveis ({len(methods)}):")
        for method in sorted(methods):
            print(f"  - {method}")
        
        # Verificar métodos faltantes
        missing_methods = [
            'detect_threat',
            'analyze_behavior', 
            'learn_threat_pattern',
            'get_behavioral_profile',
            'update_behavioral_profile',
            'get_anomaly_score',
            'get_adaptive_response',
            'get_system_status',
            'get_threat_patterns',
            'get_learning_history',
            'reset_system',
            'export_configuration',
            'import_configuration',
            'update_model',
            'retrain_model',
            'get_model_version',
            'get_performance_metrics',
            'get_resource_usage',
            'get_active_alerts',
            'resolve_alert',
            'get_security_policy',
            'update_security_policy',
            'get_compliance_status',
            'run_compliance_check'
        ]
        
        print(f"\n❌ Métodos faltantes ({len(missing_methods)}):")
        for method in missing_methods:
            if not hasattr(abiss, method):
                print(f"  - {method}")
            else:
                print(f"  ✅ {method} (já existe)")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro ao verificar métodos ABISS: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🔍 Verificando métodos do sistema ABISS...")
    success = check_abiss_methods()
    if success:
        print("\n✅ Verificação concluída com sucesso")
    else:
        print("\n❌ Verificação falhou")
        sys.exit(1)
