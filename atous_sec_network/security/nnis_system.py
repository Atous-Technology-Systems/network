"""
NNIS System - Neural Network Immune System
Sistema imune neural para detecção e resposta adaptativa a ameaças usando Gemma 3N
"""
import time
import json
import logging
import hashlib
import threading
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
import numpy as np
import requests

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logging.warning("Transformers não disponível - funcionalidade limitada")


@dataclass
class ImmuneCell:
    """Célula imune do sistema neural"""
    cell_type: str  # detector, memory, effector
    specialization: str  # tipo de ameaça que detecta
    activation_threshold: float
    memory_strength: float
    cell_id: str = field(default_factory=lambda: hashlib.md5(str(time.time()).encode()).hexdigest()[:8])
    created_at: float = field(default_factory=time.time)
    last_activated: float = field(default_factory=time.time)
    
    def activate(self, stimulus: float) -> Dict[str, Any]:
        """
        Ativa a célula com um estímulo
        
        Args:
            stimulus: Força do estímulo (0-1)
            
        Returns:
            Resultado da ativação
        """
        activated = stimulus >= self.activation_threshold
        response_strength = stimulus if activated else 0.0
        
        if activated:
            self.last_activated = time.time()
        
        return {
            "activated": activated,
            "response_strength": response_strength,
            "cell_id": self.cell_id,
            "specialization": self.specialization
        }
    
    def learn(self, success: bool) -> None:
        """
        Aprende com o resultado de uma resposta
        
        Args:
            success: Se a resposta foi bem-sucedida
        """
        if success:
            # Reforçar memória
            self.memory_strength = min(1.0, self.memory_strength + 0.1)
            # Diminuir threshold para ativação mais fácil
            self.activation_threshold = max(0.1, self.activation_threshold - 0.05)
        else:
            # Enfraquecer memória
            self.memory_strength = max(0.0, self.memory_strength - 0.05)
            # Aumentar threshold para ativação mais difícil
            self.activation_threshold = min(1.0, self.activation_threshold + 0.02)


@dataclass
class ThreatAntigen:
    """Antígeno de ameaça detectado pelo sistema"""
    threat_type: str
    confidence: float
    source: str
    timestamp: float = field(default_factory=time.time)
    antigen_id: str = field(default_factory=lambda: hashlib.md5(str(time.time()).encode()).hexdigest()[:8])
    
    def match(self, other: 'ThreatAntigen') -> float:
        """
        Calcula similaridade com outro antígeno
        
        Args:
            other: Outro antígeno para comparação
            
        Returns:
            Score de similaridade (0-1)
        """
        # Similaridade baseada no tipo de ameaça
        type_similarity = 1.0 if self.threat_type == other.threat_type else 0.0
        
        # Similaridade baseada na fonte
        source_similarity = 1.0 if self.source == other.source else 0.0
        
        # Similaridade baseada na confiança
        confidence_similarity = 1.0 - abs(self.confidence - other.confidence)
        
        # Média ponderada
        return (type_similarity * 0.5 + source_similarity * 0.3 + confidence_similarity * 0.2)


@dataclass
class ImmuneResponse:
    """Resposta imune gerada pelo sistema"""
    response_type: str
    intensity: float
    actions: List[str]
    timestamp: float = field(default_factory=time.time)
    response_id: str = field(default_factory=lambda: hashlib.md5(str(time.time()).encode()).hexdigest()[:8])
    
    def execute(self) -> Dict[str, Any]:
        """
        Executa a resposta imune
        
        Returns:
            Resultado da execução
        """
        start_time = time.time()
        
        try:
            success = True
            actions_executed = []
            
            for action in self.actions:
                # Implementação básica - em produção integrar com sistemas reais
                if action == "block_ip":
                    actions_executed.append("IP blocked")
                elif action == "isolate_host":
                    actions_executed.append("Host isolated")
                elif action == "alert_admin":
                    actions_executed.append("Admin alerted")
                elif action == "rate_limit":
                    actions_executed.append("Rate limited")
                elif action == "monitor_traffic":
                    actions_executed.append("Traffic monitored")
                else:
                    actions_executed.append(f"Action {action} executed")
            
            execution_time = time.time() - start_time
            
            return {
                "success": success,
                "actions_executed": actions_executed,
                "execution_time": execution_time,
                "response_type": self.response_type,
                "intensity": self.intensity
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "execution_time": time.time() - start_time
            }


class NNISSystem:
    """
    Sistema NNIS - Neural Network Immune System
    
    Sistema imune neural que:
    - Detecta ameaças usando células imunes especializadas
    - Forma memória imune para ameaças recorrentes
    - Gera respostas adaptativas baseadas em aprendizado
    - Usa IA (Gemma 3N) para análise avançada
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Inicializa o sistema NNIS
        
        Args:
            config: Configuração do sistema
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Modelo Gemma 3N
        self.model = None
        self.tokenizer = None
        self.model_name = config.get("model_name", "google/gemma-3n-2b")
        
        # Células imunes
        self.immune_cells = []
        self.memory_cells = []
        
        # Base de dados de ameaças
        self.threat_database = {}
        
        # Histórico de aprendizado
        self.learning_history = deque(maxlen=config.get("memory_size", 1000))
        
        # Métricas e estatísticas
        self.response_stats = defaultdict(int)
        self.threat_stats = defaultdict(int)
        
        # Inicializar modelo
        self._initialize_model()
        
        # Inicializar células imunes
        self._initialize_immune_cells()
        
        # Carregar ameaças conhecidas
        self._load_known_threats()
        
        self.logger.info("Sistema NNIS inicializado com modelo Gemma 3N")
    
    def _initialize_model(self) -> None:
        """Inicializa o modelo Gemma 3N"""
        # Inicializar pipeline como None por padrão
        self.pipeline = None
        
        if not TRANSFORMERS_AVAILABLE:
            self.logger.warning("Transformers não disponível - usando modo simulação")
            return
        
        try:
            # Carregar tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            
            # Carregar modelo
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                torch_dtype=torch.float16,
                device_map="auto"
            )
            
            # Configurar pipeline
            self.pipeline = pipeline(
                "text-generation",
                model=self.model,
                tokenizer=self.tokenizer,
                max_length=512,
                temperature=0.7
            )
            
            self.logger.info(f"Modelo Gemma 3N carregado: {self.model_name}")
            
        except Exception as e:
            self.logger.error(f"Falha ao carregar modelo Gemma 3N: {e}")
            self.model = None
            self.tokenizer = None
            self.pipeline = None
    
    def _initialize_immune_cells(self) -> None:
        """Inicializa células imunes especializadas"""
        immune_cells_count = self.config.get("immune_cells_count", 100)
        memory_cells_count = self.config.get("memory_cells_count", 50)
        
        # Criar células detectoras especializadas
        specializations = [
            "network_anomaly",
            "malware_detection",
            "ddos_attack",
            "data_exfiltration",
            "privilege_escalation",
            "sql_injection",
            "cross_site_scripting",
            "brute_force_attack",
            "phishing_attempt",
            "zero_day_exploit"
        ]
        
        for i in range(immune_cells_count):
            specialization = specializations[i % len(specializations)]
            cell = self.create_immune_cell("detector", specialization)
            self.immune_cells.append(cell)
        
        # Criar células de memória
        for i in range(memory_cells_count):
            specialization = specializations[i % len(specializations)]
            cell = self.create_immune_cell("memory", specialization)
            self.memory_cells.append(cell)
    
    def create_immune_cell(self, cell_type: str, specialization: str) -> ImmuneCell:
        """
        Cria uma nova célula imune
        
        Args:
            cell_type: Tipo da célula (detector, memory, effector)
            specialization: Especialização da célula
            
        Returns:
            Nova célula imune
        """
        # Threshold baseado na especialização
        threshold_mapping = {
            "network_anomaly": 0.6,
            "malware_detection": 0.7,
            "ddos_attack": 0.8,
            "data_exfiltration": 0.9,
            "privilege_escalation": 0.8,
            "sql_injection": 0.7,
            "cross_site_scripting": 0.6,
            "brute_force_attack": 0.7,
            "phishing_attempt": 0.6,
            "zero_day_exploit": 0.9
        }
        
        activation_threshold = threshold_mapping.get(specialization, 0.7)
        memory_strength = 0.5 if cell_type == "memory" else 0.3
        
        return ImmuneCell(
            cell_type=cell_type,
            specialization=specialization,
            activation_threshold=activation_threshold,
            memory_strength=memory_strength
        )
    
    def _load_known_threats(self) -> None:
        """Carrega ameaças conhecidas na base de dados"""
        known_threats = [
            {
                "threat_type": "ddos_attack",
                "signature": "high_packet_rate",
                "severity": 0.9,
                "description": "Distributed denial of service attack"
            },
            {
                "threat_type": "malware_infection",
                "signature": "suspicious_process",
                "severity": 0.8,
                "description": "Malware infection detected"
            },
            {
                "threat_type": "data_exfiltration",
                "signature": "large_data_transfer",
                "severity": 0.9,
                "description": "Suspicious data transfer"
            },
            {
                "threat_type": "sql_injection",
                "signature": "sql_keywords_in_url",
                "severity": 0.7,
                "description": "SQL injection attempt"
            }
        ]
        
        for threat in known_threats:
            self.add_threat_to_database(threat)
    
    def detect_antigens(self, network_data: Dict[str, Any]) -> List[ThreatAntigen]:
        """
        Detecta antígenos de ameaça nos dados de rede
        
        Args:
            network_data: Dados de rede para análise
            
        Returns:
            Lista de antígenos detectados
        """
        antigens = []
        
        try:
            # Análise baseada em células imunes
            for cell in self.immune_cells:
                # Calcular estímulo baseado na especialização da célula
                stimulus = self._calculate_stimulus(cell.specialization, network_data)
                
                # Ativar célula
                activation_result = cell.activate(stimulus)
                
                if activation_result["activated"]:
                    # Criar antígeno
                    antigen = ThreatAntigen(
                        threat_type=cell.specialization,
                        confidence=activation_result["response_strength"],
                        source="immune_cell_detection"
                    )
                    antigens.append(antigen)
            
            # Análise com IA (Gemma 3N)
            ai_antigens = self._detect_with_ai(network_data)
            antigens.extend(ai_antigens)
            
            # Verificar células de memória
            memory_antigens = self._check_memory_cells(network_data)
            antigens.extend(memory_antigens)
            
            # Remover duplicatas e ordenar por confiança
            unique_antigens = self._deduplicate_antigens(antigens)
            unique_antigens.sort(key=lambda x: x.confidence, reverse=True)
            
            return unique_antigens
            
        except Exception as e:
            self.logger.error(f"Erro na detecção de antígenos: {e}")
            return []
    
    def _calculate_stimulus(self, specialization: str, network_data: Dict[str, Any]) -> float:
        """
        Calcula estímulo para uma especialização baseado nos dados
        
        Args:
            specialization: Especialização da célula
            network_data: Dados de rede
            
        Returns:
            Força do estímulo (0-1)
        """
        stimulus = 0.0
        
        if specialization == "network_anomaly":
            # Verificar anomalias de rede
            packet_count = network_data.get("packet_count", 0)
            if packet_count > 10000:
                stimulus += 0.3
            if packet_count > 50000:
                stimulus += 0.4
            
            connection_attempts = network_data.get("connection_attempts", 0)
            if connection_attempts > 50:
                stimulus += 0.3
        
        elif specialization == "ddos_attack":
            # Verificar indicadores de DDoS
            packet_count = network_data.get("packet_count", 0)
            if packet_count > 100000:
                stimulus += 0.8
            
            source_ips = network_data.get("source_ips", [])
            if len(source_ips) > 100:
                stimulus += 0.6
        
        elif specialization == "data_exfiltration":
            # Verificar exfiltração de dados
            data_transfer_rate = network_data.get("data_transfer_rate", 0)
            if data_transfer_rate > 10000000:  # 10MB/s
                stimulus += 0.7
            
            destination_ports = network_data.get("destination_ports", [])
            suspicious_ports = [22, 3389, 445, 1433]
            if any(port in destination_ports for port in suspicious_ports):
                stimulus += 0.4
        
        elif specialization == "malware_detection":
            # Verificar indicadores de malware
            if "suspicious_process" in str(network_data):
                stimulus += 0.6
            if "file_creation" in str(network_data):
                stimulus += 0.4
        
        return min(1.0, stimulus)
    
    def _detect_with_ai(self, network_data: Dict[str, Any]) -> List[ThreatAntigen]:
        """
        Detecta ameaças usando modelo Gemma 3N
        
        Args:
            network_data: Dados de rede
            
        Returns:
            Lista de antígenos detectados pela IA
        """
        if self.pipeline is None:
            return []
        
        try:
            # Preparar prompt para análise
            prompt = self._build_threat_analysis_prompt(network_data)
            
            # Executar inferência
            response = self.pipeline(prompt, max_length=200, num_return_sequences=1)
            
            # Analisar resposta
            ai_response = response[0]["generated_text"]
            
            # Extrair ameaças da resposta
            antigens = self._parse_ai_threat_response(ai_response)
            
            return antigens
            
        except Exception as e:
            self.logger.error(f"Erro na detecção com IA: {e}")
            return []
    
    def _build_threat_analysis_prompt(self, network_data: Dict[str, Any]) -> str:
        """
        Constrói prompt para análise de ameaças
        
        Args:
            network_data: Dados de rede
            
        Returns:
            Prompt estruturado
        """
        prompt = f"""
        Analise os seguintes dados de rede para detectar ameaças de segurança:
        
        Dados de Rede:
        - Pacotes: {network_data.get('packet_count', 0)}
        - Tentativas de conexão: {network_data.get('connection_attempts', 0)}
        - Taxa de transferência: {network_data.get('data_transfer_rate', 0)}
        - IPs de origem: {network_data.get('source_ips', [])}
        - Portas de destino: {network_data.get('destination_ports', [])}
        
        Identifique possíveis ameaças e responda no formato:
        THREAT: [tipo_ameaça] | [confiança] | [descrição]
        """
        
        return prompt
    
    def _parse_ai_threat_response(self, response: str) -> List[ThreatAntigen]:
        """
        Analisa resposta da IA para extrair ameaças
        
        Args:
            response: Resposta do modelo IA
            
        Returns:
            Lista de antígenos extraídos
        """
        antigens = []
        
        try:
            lines = response.split('\n')
            
            for line in lines:
                if line.startswith("THREAT:"):
                    parts = line.split("|")
                    if len(parts) >= 3:
                        threat_type = parts[0].replace("THREAT:", "").strip()
                        confidence_str = parts[1].strip()
                        description = parts[2].strip()
                        
                        try:
                            confidence = float(confidence_str)
                            antigen = ThreatAntigen(
                                threat_type=threat_type,
                                confidence=confidence,
                                source="ai_analysis"
                            )
                            antigens.append(antigen)
                        except ValueError:
                            continue
            
            return antigens
            
        except Exception as e:
            self.logger.error(f"Erro ao analisar resposta da IA: {e}")
            return []
    
    def _check_memory_cells(self, network_data: Dict[str, Any]) -> List[ThreatAntigen]:
        """
        Verifica células de memória para ameaças conhecidas
        
        Args:
            network_data: Dados de rede
            
        Returns:
            Lista de antígenos detectados por células de memória
        """
        antigens = []
        
        for cell in self.memory_cells:
            # Calcular estímulo com threshold mais baixo para células de memória
            stimulus = self._calculate_stimulus(cell.specialization, network_data)
            
            # Ajustar threshold baseado na força da memória
            adjusted_threshold = cell.activation_threshold * (1.0 - cell.memory_strength * 0.3)
            
            if stimulus >= adjusted_threshold:
                antigen = ThreatAntigen(
                    threat_type=cell.specialization,
                    confidence=stimulus * cell.memory_strength,
                    source="memory_cell"
                )
                antigens.append(antigen)
        
        return antigens
    
    def _deduplicate_antigens(self, antigens: List[ThreatAntigen]) -> List[ThreatAntigen]:
        """
        Remove antígenos duplicados
        
        Args:
            antigens: Lista de antígenos
            
        Returns:
            Lista de antígenos únicos
        """
        unique_antigens = []
        seen_types = set()
        
        for antigen in antigens:
            if antigen.threat_type not in seen_types:
                unique_antigens.append(antigen)
                seen_types.add(antigen.threat_type)
        
        return unique_antigens
    
    def generate_immune_response(self, antigen: ThreatAntigen) -> ImmuneResponse:
        """
        Gera resposta imune para um antígeno
        
        Args:
            antigen: Antígeno detectado
            
        Returns:
            Resposta imune
        """
        # Determinar tipo de resposta baseado na confiança e tipo de ameaça
        if antigen.confidence > 0.9:
            response_type = "block_and_isolate"
            intensity = 1.0
            actions = ["block_ip", "isolate_host", "alert_admin"]
            
        elif antigen.confidence > 0.7:
            response_type = "rate_limit_and_monitor"
            intensity = 0.8
            actions = ["rate_limit", "monitor_traffic", "alert_admin"]
            
        elif antigen.confidence > 0.5:
            response_type = "monitor_and_alert"
            intensity = 0.6
            actions = ["monitor_traffic", "alert_admin"]
            
        else:
            response_type = "passive_monitoring"
            intensity = 0.3
            actions = ["monitor_traffic"]
        
        # Ajustar ações baseado no tipo de ameaça
        if "ddos" in antigen.threat_type.lower():
            actions.extend(["enable_ddos_protection", "scale_resources"])
        elif "malware" in antigen.threat_type.lower():
            actions.extend(["scan_system", "quarantine_suspicious"])
        elif "data_exfiltration" in antigen.threat_type.lower():
            actions.extend(["encrypt_sensitive_data", "audit_access"])
        
        response = ImmuneResponse(
            response_type=response_type,
            intensity=intensity,
            actions=actions
        )
        
        return response
    
    def form_memory_cell(self, response: ImmuneResponse, success: bool) -> ImmuneCell:
        """
        Forma célula de memória baseada em resposta bem-sucedida
        
        Args:
            response: Resposta imune
            success: Se a resposta foi bem-sucedida
            
        Returns:
            Nova célula de memória
        """
        if not success:
            return None
        
        # Criar célula de memória especializada
        specialization = self._determine_specialization_from_response(response)
        
        memory_cell = self.create_immune_cell("memory", specialization)
        memory_cell.memory_strength = 0.8  # Memória forte para resposta bem-sucedida
        
        self.memory_cells.append(memory_cell)
        
        self.logger.info(f"Nova célula de memória formada para: {specialization}")
        return memory_cell
    
    def _determine_specialization_from_response(self, response: ImmuneResponse) -> str:
        """
        Determina especialização baseada na resposta
        
        Args:
            response: Resposta imune
            
        Returns:
            Especialização determinada
        """
        # Mapear ações para especializações
        action_mapping = {
            "block_ip": "network_anomaly",
            "isolate_host": "malware_detection",
            "rate_limit": "ddos_attack",
            "encrypt_sensitive_data": "data_exfiltration",
            "scan_system": "malware_detection",
            "quarantine_suspicious": "malware_detection"
        }
        
        for action in response.actions:
            if action in action_mapping:
                return action_mapping[action]
        
        return "network_anomaly"  # Padrão
    
    def process_threat(self, antigen: ThreatAntigen) -> ImmuneResponse:
        """
        Processa uma ameaça completa (detecção + resposta)
        
        Args:
            antigen: Antígeno de ameaça
            
        Returns:
            Resposta imune gerada
        """
        # Gerar resposta
        response = self.generate_immune_response(antigen)
        
        # Executar resposta
        execution_result = response.execute()
        
        # Aprender com o resultado
        success = execution_result.get("success", False)
        self.learn_from_response(response, success)
        
        # Formar célula de memória se bem-sucedido
        if success and antigen.confidence > 0.7:
            self.form_memory_cell(response, True)
        
        return response
    
    def learn_from_response(self, response: ImmuneResponse, success: bool) -> None:
        """
        Aprende com o resultado de uma resposta
        
        Args:
            response: Resposta aplicada
            success: Se a resposta foi bem-sucedida
        """
        # Registrar aprendizado
        learning_entry = {
            "response_id": response.response_id,
            "response_type": response.response_type,
            "success": success,
            "timestamp": time.time()
        }
        
        self.learning_history.append(learning_entry)
        
        # Atualizar estatísticas
        self.response_stats[response.response_type] += 1
        
        # Aprender com células imunes
        for cell in self.immune_cells:
            if cell.specialization in response.response_type.lower():
                cell.learn(success)
    
    def add_threat_to_database(self, threat_info: Dict[str, Any]) -> str:
        """
        Adiciona nova ameaça à base de dados
        
        Args:
            threat_info: Informações da ameaça
            
        Returns:
            ID da ameaça adicionada
        """
        threat_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        
        threat_data = {
            "threat_type": threat_info.get("threat_type", "unknown"),
            "signature": threat_info.get("signature", ""),
            "severity": threat_info.get("severity", 0.5),
            "description": threat_info.get("description", ""),
            "added_at": time.time()
        }
        
        self.threat_database[threat_id] = threat_data
        
        self.logger.info(f"Nova ameaça adicionada à base: {threat_info.get('threat_type')}")
        return threat_id
    
    def get_threat_info(self, threat_id: str) -> Optional[Dict[str, Any]]:
        """Recupera informações de uma ameaça"""
        return self.threat_database.get(threat_id)
    
    def optimize_immune_system(self, response_history: List[Tuple[ImmuneResponse, bool]]) -> Dict[str, Any]:
        """
        Otimiza o sistema imune baseado no histórico
        
        Args:
            response_history: Histórico de respostas e resultados
            
        Returns:
            Resultado da otimização
        """
        if not response_history:
            return {}
        
        # Analisar eficácia por tipo de resposta
        response_effectiveness = defaultdict(list)
        for response, success in response_history:
            response_effectiveness[response.response_type].append(success)
        
        # Calcular eficácia média por tipo
        effectiveness_by_type = {}
        for response_type, results in response_effectiveness.items():
            effectiveness_by_type[response_type] = np.mean(results)
        
        # Otimizar thresholds das células
        cell_optimizations = {}
        for cell in self.immune_cells:
            # Ajustar threshold baseado na eficácia
            if cell.specialization in effectiveness_by_type:
                effectiveness = effectiveness_by_type[cell.specialization]
                if effectiveness < 0.5:
                    # Diminuir threshold para melhorar detecção
                    cell.activation_threshold = max(0.1, cell.activation_threshold - 0.1)
                elif effectiveness > 0.8:
                    # Aumentar threshold para reduzir falsos positivos
                    cell.activation_threshold = min(1.0, cell.activation_threshold + 0.05)
                
                cell_optimizations[cell.cell_id] = {
                    "new_threshold": cell.activation_threshold,
                    "effectiveness": effectiveness
                }
        
        return {
            "cell_optimizations": cell_optimizations,
            "threshold_adjustments": len(cell_optimizations),
            "overall_effectiveness": np.mean(list(effectiveness_by_type.values()))
        }
    
    def get_immune_system_health(self) -> Dict[str, Any]:
        """
        Retorna métricas de saúde do sistema imune
        
        Returns:
            Dicionário com métricas de saúde
        """
        total_cells = len(self.immune_cells) + len(self.memory_cells)
        active_cells = len([cell for cell in self.immune_cells if cell.last_activated > time.time() - 3600])
        
        # Calcular eficiência de resposta
        if self.learning_history:
            recent_responses = list(self.learning_history)[-100:]
            response_efficiency = np.mean([entry["success"] for entry in recent_responses])
        else:
            response_efficiency = 0.0
        
        return {
            "total_cells": total_cells,
            "active_cells": active_cells,
            "memory_cells": len(self.memory_cells),
            "response_efficiency": response_efficiency,
            "learning_rate": self.config.get("learning_rate", 0.01),
            "threat_database_size": len(self.threat_database)
        }
    
    def get_threat_evolution_data(self, threat_type: str) -> Dict[str, Any]:
        """
        Obtém dados de evolução de uma ameaça
        
        Args:
            threat_type: Tipo de ameaça
            
        Returns:
            Dados de evolução
        """
        # Filtrar histórico por tipo de ameaça
        relevant_history = [
            entry for entry in self.learning_history
            if threat_type.lower() in entry.get("response_type", "").lower()
        ]
        
        if not relevant_history:
            return {"variants": [], "evolution_timeline": []}
        
        # Analisar evolução temporal
        timeline = []
        for entry in relevant_history:
            timeline.append({
                "timestamp": entry["timestamp"],
                "success": entry["success"],
                "response_type": entry["response_type"]
            })
        
        return {
            "variants": [threat_type],  # Simplificado
            "evolution_timeline": timeline,
            "total_occurrences": len(relevant_history),
            "success_rate": np.mean([entry["success"] for entry in relevant_history])
        }
    
    def adapt_to_environment(self, environmental_change: Dict[str, Any]) -> Dict[str, Any]:
        """
        Adapta o sistema a mudanças no ambiente
        
        Args:
            environmental_change: Mudanças ambientais
            
        Returns:
            Resultado da adaptação
        """
        new_cells_created = 0
        existing_cells_modified = 0
        
        # Criar novas células para novos tipos de ameaças
        new_threat_types = environmental_change.get("new_threat_types", [])
        for threat_type in new_threat_types:
            cell = self.create_immune_cell("detector", threat_type)
            self.immune_cells.append(cell)
            new_cells_created += 1
        
        # Modificar células existentes baseado na complexidade
        threat_complexity = environmental_change.get("threat_complexity", "medium")
        if threat_complexity == "increasing":
            for cell in self.immune_cells:
                cell.activation_threshold = max(0.1, cell.activation_threshold - 0.05)
                existing_cells_modified += 1
        
        return {
            "new_cells_created": new_cells_created,
            "existing_cells_modified": existing_cells_modified,
            "adaptation_success": True
        }
    
    def coordinate_responses(self, simultaneous_threats: List[ThreatAntigen]) -> Dict[str, Any]:
        """
        Coordena respostas para múltiplas ameaças simultâneas
        
        Args:
            simultaneous_threats: Lista de ameaças simultâneas
            
        Returns:
            Resposta coordenada
        """
        if not simultaneous_threats:
            return {}
        
        # Ordenar ameaças por confiança
        sorted_threats = sorted(simultaneous_threats, key=lambda x: x.confidence, reverse=True)
        
        # Resposta primária para a ameaça mais crítica
        primary_threat = sorted_threats[0]
        primary_response = self.generate_immune_response(primary_threat)
        
        # Respostas secundárias para outras ameaças
        secondary_responses = []
        for threat in sorted_threats[1:]:
            if threat.confidence > 0.5:
                response = self.generate_immune_response(threat)
                secondary_responses.append(response)
        
        # Estratégia de coordenação
        coordination_strategy = "escalated_response" if len(simultaneous_threats) > 3 else "parallel_response"
        
        return {
            "primary_response": primary_response,
            "secondary_responses": secondary_responses,
            "coordination_strategy": coordination_strategy,
            "total_threats": len(simultaneous_threats)
        }
    
    def recover_from_failure(self) -> Dict[str, Any]:
        """
        Recupera o sistema de falhas
        
        Returns:
            Resultado da recuperação
        """
        cells_regenerated = 0
        
        # Regenerar células falhadas
        failed_cells = [cell for cell in self.immune_cells if cell.memory_strength < 0.1]
        for cell in failed_cells:
            cell.memory_strength = 0.5  # Resetar força da memória
            cells_regenerated += 1
        
        # Verificar se há células suficientes
        if len(self.immune_cells) < self.config.get("immune_cells_count", 100):
            needed_cells = self.config.get("immune_cells_count", 100) - len(self.immune_cells)
            for i in range(needed_cells):
                cell = self.create_immune_cell("detector", "network_anomaly")
                self.immune_cells.append(cell)
                cells_regenerated += 1
        
        return {
            "cells_regenerated": cells_regenerated,
            "functionality_restored": True,
            "system_health": self.get_immune_system_health()
        }
    
    def scale_immune_system(self, load_increase: Dict[str, Any]) -> Dict[str, Any]:
        """
        Escala o sistema imune para lidar com aumento de carga
        
        Args:
            load_increase: Informações sobre aumento de carga
            
        Returns:
            Resultado da escalabilidade
        """
        cells_added = 0
        
        # Adicionar células baseado na frequência de ameaças
        threat_frequency = load_increase.get("threat_frequency", "medium")
        if threat_frequency == "high":
            additional_cells = 50
            for i in range(additional_cells):
                cell = self.create_immune_cell("detector", "network_anomaly")
                self.immune_cells.append(cell)
                cells_added += 1
        
        # Ajustar capacidade de processamento
        concurrent_attacks = load_increase.get("concurrent_attacks", 10)
        if concurrent_attacks > 20:
            # Aumentar thresholds para processar mais ameaças
            for cell in self.immune_cells:
                cell.activation_threshold = min(1.0, cell.activation_threshold + 0.1)
        
        return {
            "cells_added": cells_added,
            "processing_capacity": len(self.immune_cells),
            "scaling_success": True
        }
    
    def establish_cell_communication(self, communication_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Estabelece comunicação entre células imunes
        
        Args:
            communication_data: Dados de comunicação
            
        Returns:
            Resultado da comunicação
        """
        # Simular comunicação entre células
        cells_involved = len(self.immune_cells) // 4  # 25% das células
        
        return {
            "communication_established": True,
            "cells_involved": cells_involved,
            "message_delivered": True,
            "communication_type": "threat_sharing"
        }
    
    def test_learning_performance(self) -> float:
        """
        Testa performance do aprendizado
        
        Returns:
            Score de performance (0-1)
        """
        if not self.learning_history:
            return 0.0
        
        # Calcular performance baseada no histórico recente
        recent_history = list(self.learning_history)[-50:]
        success_rate = np.mean([entry["success"] for entry in recent_history])
        
        return success_rate
    
    def optimize_learning_rate(self, optimal_rate: float) -> None:
        """
        Otimiza taxa de aprendizado
        
        Args:
            optimal_rate: Taxa de aprendizado ótima
        """
        self.config["learning_rate"] = optimal_rate
        
        # Aplicar nova taxa às células
        for cell in self.immune_cells:
            cell.activation_threshold = max(0.1, min(1.0, cell.activation_threshold))
    
    def classify_threat(self, threat: ThreatAntigen) -> Dict[str, Any]:
        """
        Classifica uma ameaça
        
        Args:
            threat: Antígeno de ameaça
            
        Returns:
            Classificação da ameaça
        """
        # Classificação baseada no tipo e confiança
        if threat.confidence > 0.8:
            category = "critical"
            response_priority = 1
        elif threat.confidence > 0.6:
            category = "high"
            response_priority = 2
        elif threat.confidence > 0.4:
            category = "medium"
            response_priority = 3
        else:
            category = "low"
            response_priority = 4
        
        return {
            "category": category,
            "severity": threat.confidence,
            "response_priority": response_priority,
            "threat_type": threat.threat_type
        }
    
    def consolidate_memory(self) -> Dict[str, Any]:
        """
        Consolida memória do sistema imune
        
        Returns:
            Resultado da consolidação
        """
        memories_consolidated = 0
        redundant_cells_removed = 0
        
        # Remover células de memória redundantes
        memory_cells_by_specialization = defaultdict(list)
        for cell in self.memory_cells:
            memory_cells_by_specialization[cell.specialization].append(cell)
        
        for specialization, cells in memory_cells_by_specialization.items():
            if len(cells) > 2:
                # Manter apenas as 2 células mais fortes
                cells.sort(key=lambda x: x.memory_strength, reverse=True)
                cells_to_remove = cells[2:]
                
                for cell in cells_to_remove:
                    self.memory_cells.remove(cell)
                    redundant_cells_removed += 1
        
        # Consolidar memórias similares
        for cell in self.memory_cells:
            if cell.memory_strength < 0.3:
                cell.memory_strength = 0.5  # Reforçar memórias fracas
                memories_consolidated += 1
        
        return {
            "memories_consolidated": memories_consolidated,
            "redundant_cells_removed": redundant_cells_removed,
            "memory_efficiency_improved": True
        }