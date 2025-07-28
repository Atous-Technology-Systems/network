"""
LLM Integration - Cognitive Pipeline
Pipeline integrado para transferência de contexto entre LLM e SLM
"""
import json
import logging
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import requests
import numpy as np

try:
    from transformers import pipeline, AutoTokenizer, AutoModel
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logging.warning("Transformers não disponível - funcionalidade limitada")


@dataclass
class CognitiveContext:
    """Contexto cognitivo para transferência entre modelos"""
    embeddings: List[float]
    context_summary: str
    metadata: Dict[str, Any]
    timestamp: float
    confidence: float


class CognitivePipeline:
    """
    Pipeline cognitivo integrado LLM-SLM
    
    Gerencia transferência de contexto entre modelos de linguagem
    pequenos (SLM) em dispositivos edge e modelos grandes (LLM)
    em servidores centrais.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Inicializa o pipeline cognitivo
        
        Args:
            config: Configuração do pipeline
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Configurações de modelo
        self.slm_model = config.get("slm_model", "distilbert-base-uncased")
        self.llm_endpoint = config.get("llm_endpoint", "http://localhost:8000/llm")
        self.hardware_class = config.get("hardware_class", "low")
        
        # Inicializar modelos
        self.slm = None
        self.tokenizer = None
        self._initialize_models()
        
        # Cache de contexto
        self.context_cache = {}
        self.max_cache_size = 100
        
        # Métricas
        self.processing_times = []
        self.transfer_sizes = []
    
    def _initialize_models(self) -> None:
        """Inicializa modelos SLM baseado no hardware"""
        if not TRANSFORMERS_AVAILABLE:
            self.logger.warning("Transformers não disponível - usando modo simulação")
            return
        
        try:
            # Selecionar modelo apropriado para o hardware
            model_mapping = {
                "ultra_low": "prajjwal1/bert-tiny",
                "low": "distilbert-base-uncased",
                "medium": "bert-base-uncased",
                "high": "bert-large-uncased"
            }
            
            selected_model = model_mapping.get(self.hardware_class, "distilbert-base-uncased")
            
            # Carregar tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(selected_model)
            
            # Carregar modelo para embeddings
            self.slm = AutoModel.from_pretrained(selected_model)
            
            self.logger.info(f"Modelo SLM carregado: {selected_model}")
            
        except Exception as e:
            self.logger.error(f"Falha ao carregar modelo SLM: {e}")
            self.slm = None
            self.tokenizer = None
    
    def process_data(self, text_data: str) -> str:
        """
        Processa dados localmente e prepara para envio
        
        Args:
            text_data: Dados de texto para processamento
            
        Returns:
            Payload JSON compacto para transmissão
        """
        start_time = time.time()
        
        try:
            # Gerar embeddings locais
            embeddings = self._generate_embeddings(text_data)
            
            # Sumarizar contexto para transmissão eficiente
            summary = self._summarize_context(text_data)
            
            # Calcular confiança da análise local
            confidence = self._calculate_confidence(embeddings, summary)
            
            # Criar contexto cognitivo
            context = CognitiveContext(
                embeddings=embeddings.tolist() if hasattr(embeddings, 'tolist') else embeddings,
                context_summary=summary,
                metadata={
                    "model": self.slm_model,
                    "hardware": self.hardware_class,
                    "timestamp": time.time(),
                    "data_length": len(text_data)
                },
                timestamp=time.time(),
                confidence=confidence
            )
            
            # Preparar payload compacto
            payload = {
                "embeddings": context.embeddings,
                "context_summary": context.context_summary,
                "metadata": context.metadata,
                "confidence": context.confidence
            }
            
            # Calcular métricas
            processing_time = time.time() - start_time
            transfer_size = len(json.dumps(payload))
            
            self.processing_times.append(processing_time)
            self.transfer_sizes.append(transfer_size)
            
            # Manter apenas as últimas métricas
            if len(self.processing_times) > 100:
                self.processing_times = self.processing_times[-100:]
                self.transfer_sizes = self.transfer_sizes[-100:]
            
            self.logger.debug(f"Processamento concluído em {processing_time:.3f}s, "
                            f"tamanho: {transfer_size} bytes")
            
            return json.dumps(payload)
            
        except Exception as e:
            self.logger.error(f"Erro no processamento local: {e}")
            return json.dumps({"error": str(e)})
    
    def _generate_embeddings(self, text: str) -> np.ndarray:
        """
        Gera embeddings para o texto
        
        Args:
            text: Texto para gerar embeddings
            
        Returns:
            Array de embeddings
        """
        if self.slm is None or self.tokenizer is None:
            # Modo simulação
            return np.random.rand(768)  # Embedding simulado
        
        try:
            # Tokenizar texto
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                max_length=512,
                truncation=True,
                padding=True
            )
            
            # Gerar embeddings
            with torch.no_grad():
                outputs = self.slm(**inputs)
                embeddings = outputs.last_hidden_state.mean(dim=1)
            
            return embeddings.numpy().flatten()
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar embeddings: {e}")
            return np.random.rand(768)  # Fallback
    
    def _summarize_context(self, text: str) -> str:
        """
        Sumariza texto para reduzir tamanho de transmissão
        
        Args:
            text: Texto original
            
        Returns:
            Texto sumarizado
        """
        if self.tokenizer is None:
            # Sumarização simples sem tokenizer
            words = text.split()
            if len(words) > 100:
                return " ".join(words[:50] + words[-50:])
            return text
        
        try:
            # Tokenizar texto
            tokens = self.tokenizer.tokenize(text)
            
            # Resumo simples: primeiras, últimas e palavras-chave
            if len(tokens) > 100:
                # Pegar primeiras e últimas tokens
                summary_tokens = tokens[:50] + tokens[-50:]
                summary = self.tokenizer.convert_tokens_to_string(summary_tokens)
            else:
                summary = text
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Erro na sumarização: {e}")
            return text[:500]  # Fallback simples
    
    def _calculate_confidence(self, embeddings: np.ndarray, summary: str) -> float:
        """
        Calcula confiança da análise local
        
        Args:
            embeddings: Embeddings gerados
            summary: Resumo do contexto
            
        Returns:
            Valor de confiança (0-1)
        """
        try:
            # Métricas de confiança baseadas em:
            # 1. Variância dos embeddings (maior variância = mais informação)
            # 2. Comprimento do resumo
            # 3. Qualidade do texto (simplificado)
            
            embedding_variance = np.var(embeddings)
            summary_length = len(summary)
            
            # Normalizar métricas
            variance_score = min(embedding_variance / 0.1, 1.0)  # Normalizar variância
            length_score = min(summary_length / 1000, 1.0)  # Normalizar comprimento
            
            # Calcular confiança combinada
            confidence = (variance_score * 0.6 + length_score * 0.4)
            
            return max(0.0, min(1.0, confidence))
            
        except Exception as e:
            self.logger.error(f"Erro no cálculo de confiança: {e}")
            return 0.5  # Confiança neutra
    
    def get_llm_analysis(self, aggregated_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Obtém análise do LLM central
        
        Args:
            aggregated_data: Dados agregados de múltiplos dispositivos
            
        Returns:
            Análise do LLM ou None se falhar
        """
        try:
            # Construir prompt para o LLM
            prompt = self._build_prompt(aggregated_data)
            
            # Preparar payload para o LLM
            llm_payload = {
                "prompt": prompt,
                "max_tokens": 1000,
                "temperature": 0.7,
                "context": aggregated_data
            }
            
            # Fazer requisição para o LLM
            response = requests.post(
                self.llm_endpoint,
                json=llm_payload,
                timeout=30,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "analysis": result.get("analysis", ""),
                    "recommendations": result.get("recommendations", []),
                    "confidence": result.get("confidence", 0.0),
                    "model_updates": result.get("model_updates", {})
                }
            else:
                self.logger.error(f"Erro na requisição ao LLM: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Falha na consulta ao LLM: {e}")
            return None
    
    def _build_prompt(self, data: Dict[str, Any]) -> str:
        """
        Constrói prompt para o LLM
        
        Args:
            data: Dados agregados
            
        Returns:
            Prompt estruturado
        """
        # Contar dispositivos
        device_count = len(data.get("devices", []))
        
        # Extrair métricas principais
        avg_confidence = np.mean([d.get("confidence", 0.0) for d in data.get("devices", [])])
        
        # Construir prompt estruturado
        prompt = f"""
        Analise os seguintes dados agregados de {device_count} dispositivos IoT:
        
        **Métricas Gerais:**
        - Número de dispositivos: {device_count}
        - Confiança média: {avg_confidence:.3f}
        - Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}
        
        **Dados dos Dispositivos:**
        {json.dumps(data, indent=2)}
        
        **Tarefas de Análise:**
        1. Identifique padrões anômalos nos dados
        2. Detecte tendências significativas
        3. Sugira recomendações de ação
        4. Proponha atualizações para modelos locais
        5. Avalie a qualidade geral dos dados
        
        **Formato de Resposta:**
        - Análise: Resumo das descobertas principais
        - Recomendações: Lista de ações sugeridas
        - Atualizações de Modelo: Sugestões para melhorar modelos SLM
        - Confiança: Nível de confiança na análise (0-1)
        """
        
        return prompt
    
    def aggregate_contexts(self, contexts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Agrega contextos de múltiplos dispositivos
        
        Args:
            contexts: Lista de contextos de dispositivos
            
        Returns:
            Dados agregados
        """
        try:
            if not contexts:
                return {"error": "Nenhum contexto fornecido"}
            
            # Extrair embeddings
            all_embeddings = []
            all_summaries = []
            all_confidences = []
            
            for context in contexts:
                if "embeddings" in context:
                    all_embeddings.append(context["embeddings"])
                if "context_summary" in context:
                    all_summaries.append(context["context_summary"])
                if "confidence" in context:
                    all_confidences.append(context["confidence"])
            
            # Calcular estatísticas
            aggregated_data = {
                "device_count": len(contexts),
                "avg_confidence": np.mean(all_confidences) if all_confidences else 0.0,
                "std_confidence": np.std(all_confidences) if all_confidences else 0.0,
                "total_embeddings": len(all_embeddings),
                "summary_count": len(all_summaries),
                "timestamp": time.time(),
                "devices": contexts
            }
            
            # Calcular embeddings agregados se disponíveis
            if all_embeddings:
                embeddings_array = np.array(all_embeddings)
                aggregated_data.update({
                    "avg_embedding": embeddings_array.mean(axis=0).tolist(),
                    "embedding_variance": embeddings_array.var(axis=0).tolist(),
                    "embedding_correlation": np.corrcoef(embeddings_array.T).tolist()
                })
            
            return aggregated_data
            
        except Exception as e:
            self.logger.error(f"Erro na agregação de contextos: {e}")
            return {"error": str(e)}
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Retorna métricas de desempenho do pipeline
        
        Returns:
            Dicionário com métricas
        """
        if not self.processing_times:
            return {"error": "Nenhuma métrica disponível"}
        
        return {
            "avg_processing_time": np.mean(self.processing_times),
            "std_processing_time": np.std(self.processing_times),
            "avg_transfer_size": np.mean(self.transfer_sizes),
            "total_processed": len(self.processing_times),
            "hardware_class": self.hardware_class,
            "model": self.slm_model,
            "cache_size": len(self.context_cache)
        }
    
    def optimize_for_hardware(self, hardware_config: Dict[str, Any]) -> None:
        """
        Otimiza pipeline para hardware específico
        
        Args:
            hardware_config: Configuração do hardware
        """
        # Atualizar classe de hardware
        self.hardware_class = hardware_config.get("class", "low")
        
        # Reconfigurar modelo se necessário
        if hardware_config.get("memory_mb", 1024) < 512:
            self.hardware_class = "ultra_low"
        elif hardware_config.get("memory_mb", 1024) > 2048:
            self.hardware_class = "medium"
        
        # Reinicializar modelos
        self._initialize_models()
        
        self.logger.info(f"Pipeline otimizado para hardware: {self.hardware_class}")
    
    def clear_cache(self) -> None:
        """Limpa cache de contexto"""
        self.context_cache.clear()
        self.logger.info("Cache de contexto limpo")
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Retorna informações sobre os modelos
        
        Returns:
            Dicionário com informações dos modelos
        """
        return {
            "slm_model": self.slm_model,
            "hardware_class": self.hardware_class,
            "transformers_available": TRANSFORMERS_AVAILABLE,
            "model_loaded": self.slm is not None,
            "tokenizer_loaded": self.tokenizer is not None,
            "llm_endpoint": self.llm_endpoint
        }


# Função utilitária para criar pipeline
def create_cognitive_pipeline(config: Dict[str, Any]) -> CognitivePipeline:
    """
    Cria pipeline cognitivo com configuração padrão
    
    Args:
        config: Configuração personalizada
        
    Returns:
        Instância do pipeline cognitivo
    """
    default_config = {
        "slm_model": "distilbert-base-uncased",
        "llm_endpoint": "http://localhost:8000/llm",
        "hardware_class": "low",
        "max_cache_size": 100
    }
    
    # Mesclar configurações
    final_config = {**default_config, **config}
    
    return CognitivePipeline(final_config)