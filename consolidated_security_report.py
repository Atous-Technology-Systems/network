#!/usr/bin/env python3
"""
Relatório Consolidado de Segurança - ATous Secure Network
Consolida e analisa todos os resultados dos testes de penetração
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any


class SecurityReportConsolidator:
    """Classe para consolidar relatórios de segurança"""
    
    def __init__(self):
        self.reports = {}
        self.consolidated_data = {}
        
    def load_reports(self):
        """Carrega todos os relatórios de segurança disponíveis"""
        report_files = [
            "security_test_report_20250802_233554.json",
            "advanced_security_report_20250802_234108.json",
            "stress_test_report_20250802_234624.json"
        ]
        
        for report_file in report_files:
            if os.path.exists(report_file):
                try:
                    with open(report_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        report_type = report_file.split('_')[0]
                        self.reports[report_type] = data
                        print(f"✅ Carregado: {report_file}")
                except Exception as e:
                    print(f"❌ Erro ao carregar {report_file}: {e}")
            else:
                print(f"⚠️ Arquivo não encontrado: {report_file}")
                
    def analyze_owasp_coverage(self):
        """Analisa cobertura dos OWASP Top 10"""
        print("\n🔍 Análise de Cobertura OWASP Top 10")
        print("=" * 40)
        
        owasp_mapping = {
            "A01 - Broken Access Control": ["Path Traversal", "Advanced Path Traversal"],
            "A02 - Cryptographic Failures": [],  # Não testado diretamente
            "A03 - Injection": ["SQL Injection", "Advanced SQL Injection", "XSS", "Advanced XSS", "Command Injection", "LDAP Injection"],
            "A04 - Insecure Design": ["SSRF", "Deserialization"],
            "A05 - Security Misconfiguration": ["XXE", "Header Injection"],
            "A06 - Vulnerable Components": [],  # Não testado diretamente
            "A07 - Authentication Failures": ["Brute Force"],
            "A08 - Software Integrity Failures": ["Deserialization"],
            "A09 - Logging Failures": [],  # Não testado diretamente
            "A10 - Server-Side Request Forgery": ["SSRF"]
        }
        
        coverage_results = {}
        
        for owasp_category, attack_types in owasp_mapping.items():
            if not attack_types:
                coverage_results[owasp_category] = {"tested": False, "detection_rate": 0}
                continue
                
            total_tests = 0
            total_detected = 0
            
            for report_type, report_data in self.reports.items():
                if "attack_types" in report_data.get("summary", {}):
                    for attack_type in attack_types:
                        if attack_type in report_data["summary"]["attack_types"]:
                            stats = report_data["summary"]["attack_types"][attack_type]
                            total_tests += stats["total"]
                            total_detected += stats["detected"]
                            
            detection_rate = (total_detected / total_tests * 100) if total_tests > 0 else 0
            coverage_results[owasp_category] = {
                "tested": total_tests > 0,
                "total_tests": total_tests,
                "detected": total_detected,
                "detection_rate": detection_rate
            }
            
        for category, results in coverage_results.items():
            if results["tested"]:
                status = "✅" if results["detection_rate"] >= 70 else "⚠️" if results["detection_rate"] >= 40 else "❌"
                print(f"{status} {category}: {results['detected']}/{results['total_tests']} ({results['detection_rate']:.1f}%)")
            else:
                print(f"⚪ {category}: Não testado")
                
        return coverage_results
        
    def analyze_attack_vectors(self):
        """Analisa vetores de ataque por categoria"""
        print("\n🎯 Análise por Vetor de Ataque")
        print("=" * 40)
        
        attack_categories = {
            "Injection Attacks": ["SQL Injection", "Advanced SQL Injection", "XSS", "Advanced XSS", "Command Injection", "LDAP Injection"],
            "Access Control": ["Path Traversal", "Advanced Path Traversal"],
            "Network Attacks": ["SSRF", "XXE"],
            "Application Logic": ["Deserialization", "Prototype Pollution", "Header Injection"],
            "Volumetric Attacks": ["Rate Limiting", "Brute Force", "Slowloris", "HTTP Flood", "Resource Exhaustion"]
        }
        
        category_results = {}
        
        for category, attack_types in attack_categories.items():
            total_tests = 0
            total_detected = 0
            
            for report_type, report_data in self.reports.items():
                if "attack_types" in report_data.get("summary", {}):
                    for attack_type in attack_types:
                        if attack_type in report_data["summary"]["attack_types"]:
                            stats = report_data["summary"]["attack_types"][attack_type]
                            total_tests += stats["total"]
                            total_detected += stats["detected"]
                            
            detection_rate = (total_detected / total_tests * 100) if total_tests > 0 else 0
            category_results[category] = {
                "total_tests": total_tests,
                "detected": total_detected,
                "detection_rate": detection_rate
            }
            
            if total_tests > 0:
                status = "🛡️" if detection_rate >= 80 else "⚠️" if detection_rate >= 50 else "🚨"
                print(f"{status} {category}: {total_detected}/{total_tests} ({detection_rate:.1f}%)")
            else:
                print(f"⚪ {category}: Não testado")
                
        return category_results
        
    def generate_recommendations(self, owasp_coverage: Dict, attack_vectors: Dict):
        """Gera recomendações de segurança baseadas nos resultados"""
        print("\n💡 Recomendações de Segurança")
        print("=" * 40)
        
        recommendations = []
        
        # Análise de injection attacks
        injection_rate = attack_vectors.get("Injection Attacks", {}).get("detection_rate", 0)
        if injection_rate < 70:
            recommendations.append({
                "priority": "ALTA",
                "category": "Injection Prevention",
                "description": "Implementar validação de entrada mais rigorosa e sanitização de dados",
                "details": [
                    "Usar prepared statements para SQL",
                    "Implementar Content Security Policy (CSP) para XSS",
                    "Validar e sanitizar todos os inputs do usuário",
                    "Implementar WAF (Web Application Firewall)"
                ]
            })
            
        # Análise de controle de acesso
        access_rate = attack_vectors.get("Access Control", {}).get("detection_rate", 0)
        if access_rate < 80:
            recommendations.append({
                "priority": "ALTA",
                "category": "Access Control",
                "description": "Fortalecer controles de acesso e validação de caminhos",
                "details": [
                    "Implementar whitelist de arquivos/diretórios permitidos",
                    "Usar caminhos absolutos e canonicalização",
                    "Implementar controle de acesso baseado em roles (RBAC)",
                    "Auditar logs de acesso regularmente"
                ]
            })
            
        # Análise de ataques volumétricos
        volumetric_rate = attack_vectors.get("Volumetric Attacks", {}).get("detection_rate", 0)
        if volumetric_rate < 60:
            recommendations.append({
                "priority": "MÉDIA",
                "category": "DDoS Protection",
                "description": "Implementar proteções contra ataques volumétricos",
                "details": [
                    "Configurar rate limiting por IP e usuário",
                    "Implementar CAPTCHA após múltiplas tentativas",
                    "Usar CDN com proteção DDoS",
                    "Configurar timeouts apropriados",
                    "Implementar circuit breakers"
                ]
            })
            
        # Análise de ataques de rede
        network_rate = attack_vectors.get("Network Attacks", {}).get("detection_rate", 0)
        if network_rate < 70:
            recommendations.append({
                "priority": "MÉDIA",
                "category": "Network Security",
                "description": "Melhorar proteções contra ataques de rede",
                "details": [
                    "Implementar whitelist de URLs para SSRF",
                    "Desabilitar processamento de entidades externas XML",
                    "Usar proxy reverso com filtragem",
                    "Implementar network segmentation"
                ]
            })
            
        # Análise de lógica de aplicação
        logic_rate = attack_vectors.get("Application Logic", {}).get("detection_rate", 0)
        if logic_rate < 60:
            recommendations.append({
                "priority": "BAIXA",
                "category": "Application Security",
                "description": "Fortalecer validações de lógica de aplicação",
                "details": [
                    "Implementar validação de tipos de dados",
                    "Usar bibliotecas seguras para serialização",
                    "Validar cabeçalhos HTTP",
                    "Implementar Content-Type validation"
                ]
            })
            
        # Exibir recomendações
        for i, rec in enumerate(recommendations, 1):
            priority_icon = "🔴" if rec["priority"] == "ALTA" else "🟡" if rec["priority"] == "MÉDIA" else "🟢"
            print(f"\n{priority_icon} Recomendação {i} - {rec['category']} (Prioridade: {rec['priority']})")
            print(f"   {rec['description']}")
            for detail in rec["details"]:
                print(f"   • {detail}")
                
        return recommendations
        
    def calculate_overall_security_score(self, owasp_coverage: Dict, attack_vectors: Dict):
        """Calcula pontuação geral de segurança"""
        print("\n📊 Pontuação Geral de Segurança")
        print("=" * 40)
        
        # Pesos por categoria
        weights = {
            "Injection Attacks": 0.3,
            "Access Control": 0.25,
            "Volumetric Attacks": 0.2,
            "Network Attacks": 0.15,
            "Application Logic": 0.1
        }
        
        weighted_score = 0
        total_weight = 0
        
        for category, weight in weights.items():
            if category in attack_vectors and attack_vectors[category]["total_tests"] > 0:
                detection_rate = attack_vectors[category]["detection_rate"]
                weighted_score += detection_rate * weight
                total_weight += weight
                print(f"  {category}: {detection_rate:.1f}% (peso: {weight:.1f})")
                
        overall_score = weighted_score / total_weight if total_weight > 0 else 0
        
        print(f"\n🎯 Pontuação Geral: {overall_score:.1f}/100")
        
        # Classificação
        if overall_score >= 90:
            classification = "🏆 EXCELENTE"
            description = "Sistemas de segurança muito robustos"
        elif overall_score >= 75:
            classification = "✅ BOM"
            description = "Boa proteção, com algumas áreas para melhoria"
        elif overall_score >= 60:
            classification = "⚠️ MODERADO"
            description = "Proteção básica, requer melhorias significativas"
        elif overall_score >= 40:
            classification = "🚨 BAIXO"
            description = "Proteção insuficiente, vulnerabilidades críticas"
        else:
            classification = "💀 CRÍTICO"
            description = "Sistemas altamente vulneráveis, ação imediata necessária"
            
        print(f"\n{classification}")
        print(f"Status: {description}")
        
        return overall_score, classification, description
        
    def generate_consolidated_report(self):
        """Gera relatório consolidado completo"""
        print("🛡️ Relatório Consolidado de Segurança - ATous Secure Network")
        print("=" * 70)
        print(f"Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        
        # Carregar relatórios
        self.load_reports()
        
        if not self.reports:
            print("❌ Nenhum relatório encontrado para consolidação.")
            return
            
        # Análises
        owasp_coverage = self.analyze_owasp_coverage()
        attack_vectors = self.analyze_attack_vectors()
        recommendations = self.generate_recommendations(owasp_coverage, attack_vectors)
        overall_score, classification, description = self.calculate_overall_security_score(owasp_coverage, attack_vectors)
        
        # Estatísticas gerais
        total_tests = sum(report["summary"]["total_tests"] for report in self.reports.values() if "summary" in report)
        total_detected = sum(report["summary"].get("detected_attacks", report["summary"].get("effective_protections", 0)) for report in self.reports.values() if "summary" in report)
        
        print(f"\n📈 Estatísticas Gerais")
        print(f"=" * 25)
        print(f"Total de testes realizados: {total_tests}")
        print(f"Total de ataques detectados: {total_detected}")
        print(f"Taxa geral de detecção: {(total_detected/total_tests*100):.1f}%" if total_tests > 0 else "N/A")
        
        # Salvar relatório consolidado
        consolidated_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "reports_analyzed": list(self.reports.keys()),
                "total_tests": total_tests,
                "total_detected": total_detected
            },
            "owasp_coverage": owasp_coverage,
            "attack_vectors": attack_vectors,
            "recommendations": recommendations,
            "security_score": {
                "score": overall_score,
                "classification": classification,
                "description": description
            }
        }
        
        report_file = f"consolidated_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(consolidated_data, f, indent=2, ensure_ascii=False)
            
        print(f"\n📄 Relatório consolidado salvo em: {report_file}")
        
        print("\n" + "=" * 70)
        print("🏁 Análise de segurança concluída.")
        print("\n⚠️ IMPORTANTE:")
        print("Este relatório deve ser usado para melhorar a postura de segurança.")
        print("Implemente as recomendações de acordo com a prioridade indicada.")


def main():
    """Função principal"""
    consolidator = SecurityReportConsolidator()
    consolidator.generate_consolidated_report()


if __name__ == "__main__":
    main()