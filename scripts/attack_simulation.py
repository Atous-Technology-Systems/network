#!/usr/bin/env python3
"""
Script de Simulação de Ataques - Atous Security Network
Simula 10.000 ataques contra os sistemas de defesa ABISS e NNIS
"""

import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from atous_sec_network.security.abiss_system import ABISSSystem
from atous_sec_network.security.nnis_system import NNISSystem
from owasp_training_system import OWASPTrainingSystem

class AttackSimulator:
    """Simulador de ataques para testar sistemas de defesa"""
    
    def __init__(self):
        """Inicializa o simulador de ataques"""
        self.abiss = ABISSSystem({'model_path': 'test_model'})
        self.nnis = NNISSystem({'memory_size': 1000})
        self.owasp = OWASPTrainingSystem(self.abiss, self.nnis)
        
        # Tipos de ataques
        self.attack_types = [
            'sql_injection',
            'xss_attack', 
            'ddos_attack',
            'malware_infection',
            'data_exfiltration',
            'path_traversal',
            'ssrf_attack',
            'weak_credentials',
            'brute_force',
            'man_in_the_middle'
        ]
        
        # Payloads de exemplo
        self.sql_payloads = [
            "'; DROP TABLE users; --",
            "' OR 1=1; --",
            "' UNION SELECT * FROM passwords; --",
            "admin'--",
            "1' OR '1'='1"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//"
        ]
        
        self.ddos_patterns = [
            {"requests_per_second": 1000, "duration": 60},
            {"requests_per_second": 500, "duration": 120},
            {"requests_per_second": 2000, "duration": 30},
            {"requests_per_second": 100, "duration": 300},
            {"requests_per_second": 5000, "duration": 10}
        ]
        
        self.malware_signatures = [
            "eval(base64_decode",
            "shell_exec(",
            "system(",
            "exec(",
            "passthru("
        ]
        
        self.stats = {
            'total_attacks': 0,
            'detected_attacks': 0,
            'blocked_attacks': 0,
            'false_positives': 0,
            'response_times': [],
            'attack_types': {}
        }
    
    def generate_attack_data(self, attack_type):
        """Gera dados de ataque baseado no tipo"""
        if attack_type == 'sql_injection':
            payload = random.choice(self.sql_payloads)
            return {
                'type': 'sql_injection',
                'payload': payload,
                'source_ip': f"192.168.1.{random.randint(1, 254)}",
                'timestamp': time.time(),
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        
        elif attack_type == 'xss_attack':
            payload = random.choice(self.xss_payloads)
            return {
                'type': 'xss_attack',
                'payload': payload,
                'source_ip': f"10.0.0.{random.randint(1, 254)}",
                'timestamp': time.time(),
                'user_agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            }
        
        elif attack_type == 'ddos_attack':
            pattern = random.choice(self.ddos_patterns)
            return {
                'type': 'ddos_attack',
                'requests_per_second': pattern['requests_per_second'],
                'duration': pattern['duration'],
                'source_ips': [f"172.16.{random.randint(1, 254)}.{random.randint(1, 254)}" for _ in range(10)],
                'timestamp': time.time()
            }
        
        elif attack_type == 'malware_infection':
            signature = random.choice(self.malware_signatures)
            return {
                'type': 'malware_infection',
                'signature': signature,
                'file_hash': f"{random.randint(1000000, 9999999):x}",
                'source_ip': f"203.0.113.{random.randint(1, 254)}",
                'timestamp': time.time()
            }
        
        else:
            return {
                'type': attack_type,
                'payload': f"attack_{attack_type}_{random.randint(1000, 9999)}",
                'source_ip': f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
                'timestamp': time.time()
            }
    
    def simulate_single_attack(self, attack_num):
        """Simula um único ataque"""
        try:
            # Escolhe tipo de ataque aleatório
            attack_type = random.choice(self.attack_types)
            attack_data = self.generate_attack_data(attack_type)
            
            # Registra início do ataque
            start_time = time.time()
            
            # Simula ataque contra ABISS
            abiss_score, abiss_type = self.abiss.detect_threat(attack_data)
            abiss_result = {
                'threat_detected': abiss_score > 0.5,
                'score': abiss_score,
                'threat_type': abiss_type,
                'action': 'block' if abiss_score > 0.7 else 'monitor'
            }
            
            # Simula ataque contra NNIS
            nnis_antigens = self.nnis.detect_antigens(attack_data)
            nnis_result = {
                'threat_detected': len(nnis_antigens) > 0,
                'antigens': nnis_antigens,
                'action': 'block' if len(nnis_antigens) > 0 else 'monitor'
            }
            
            # Simula detecção OWASP
            owasp_result = self.owasp.detect_attack(str(attack_data))
            
            # Calcula tempo de resposta
            response_time = time.time() - start_time
            
            # Atualiza estatísticas
            self.stats['total_attacks'] += 1
            self.stats['response_times'].append(response_time)
            
            if attack_type not in self.stats['attack_types']:
                self.stats['attack_types'][attack_type] = 0
            self.stats['attack_types'][attack_type] += 1
            
            # Verifica se foi detectado
            if abiss_result['threat_detected'] or nnis_result['threat_detected'] or owasp_result.get('attack_detected', False):
                self.stats['detected_attacks'] += 1
                # Verifica se foi bloqueado
                if abiss_result['action'] == 'block' or nnis_result['action'] == 'block':
                    self.stats['blocked_attacks'] += 1
            # Log do ataque
            if attack_num % 1000 == 0:
                print(f"🎯 Ataque #{attack_num:05d} - Tipo: {attack_type} - Tempo: {response_time:.3f}s - Detectado: {abiss_result['threat_detected']}")
            return {
                'attack_num': attack_num,
                'attack_type': attack_type,
                'response_time': response_time,
                'abiss_detected': abiss_result['threat_detected'],
                'nnis_detected': nnis_result['threat_detected'],
                'owasp_detected': owasp_result.get('attack_detected', False),
                'blocked': bool(abiss_result['action'] == 'block' or nnis_result['action'] == 'block')
            }
            
        except Exception as e:
            print(f"❌ Erro no ataque #{attack_num}: {e}")
            return None
    
    def run_attack_simulation(self, num_attacks=10000, max_workers=10):
        """Executa simulação de ataques"""
        print(f"🚀 Iniciando simulação de {num_attacks} ataques...")
        print(f"🛡️ Sistemas de defesa: ABISS, NNIS, OWASP")
        print(f"⚡ Workers paralelos: {max_workers}")
        print("-" * 60)
        
        start_time = time.time()
        
        # Executa ataques em paralelo
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submete todos os ataques
            future_to_attack = {
                executor.submit(self.simulate_single_attack, i): i 
                for i in range(1, num_attacks + 1)
            }
            
            # Processa resultados
            completed_attacks = 0
            for future in as_completed(future_to_attack):
                attack_num = future_to_attack[future]
                try:
                    result = future.result()
                    if result:
                        completed_attacks += 1
                        
                        # Progresso a cada 1000 ataques
                        if completed_attacks % 1000 == 0:
                            elapsed = time.time() - start_time
                            rate = completed_attacks / elapsed
                            print(f"📊 Progresso: {completed_attacks}/{num_attacks} ({completed_attacks/num_attacks*100:.1f}%) - Taxa: {rate:.1f} ataques/s")
                            
                except Exception as e:
                    print(f"❌ Erro no ataque #{attack_num}: {e}")
        
        # Calcula estatísticas finais
        total_time = time.time() - start_time
        avg_response_time = sum(self.stats['response_times']) / len(self.stats['response_times']) if self.stats['response_times'] else 0
        
        print("\n" + "=" * 60)
        print("📊 RESULTADOS DA SIMULAÇÃO DE ATAQUES")
        print("=" * 60)
        print(f"🎯 Total de ataques: {self.stats['total_attacks']}")
        print(f"🛡️ Ataques detectados: {self.stats['detected_attacks']}")
        print(f"🚫 Ataques bloqueados: {self.stats['blocked_attacks']}")
        print(f"⏱️ Tempo total: {total_time:.2f}s")
        print(f"⚡ Taxa média: {self.stats['total_attacks']/total_time:.1f} ataques/s")
        print(f"📈 Tempo médio de resposta: {avg_response_time:.3f}s")
        
        if self.stats['total_attacks'] > 0:
            detection_rate = (self.stats['detected_attacks'] / self.stats['total_attacks']) * 100
            block_rate = (self.stats['blocked_attacks'] / self.stats['total_attacks']) * 100
            print(f"🎯 Taxa de detecção: {detection_rate:.2f}%")
            print(f"🚫 Taxa de bloqueio: {block_rate:.2f}%")
        
        print("\n📋 Distribuição por tipo de ataque:")
        for attack_type, count in sorted(self.stats['attack_types'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / self.stats['total_attacks']) * 100
            print(f"  • {attack_type}: {count} ({percentage:.1f}%)")
        
        return self.stats

if __name__ == "__main__":
    # Inicializa simulador
    simulator = AttackSimulator()
    
    # Executa simulação
    stats = simulator.run_attack_simulation(num_attacks=1000, max_workers=4)
    
    print("\n✅ Simulação concluída!") 