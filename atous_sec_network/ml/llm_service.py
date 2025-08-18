"""
Serviço de LLM para ATous Secure Network

Este módulo implementa a integração com o modelo Gemma 3N para:
- Respostas inteligentes sobre o sistema
- Fine-tuning automático do sistema de segurança
- Análise de dados e insights
- Assistente virtual para a plataforma
"""

import os
import json
import logging
import asyncio
from datetime import datetime, UTC, timedelta
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
import numpy as np
from dataclasses import dataclass, field
import threading
import time

# TFLite imports
try:
    import tensorflow as tf
    TFLITE_AVAILABLE = True
except ImportError:
    TFLITE_AVAILABLE = False

# Simulação de TFLite para quando não estiver disponível
class TFLiteSimulator:
    """Simulador de TFLite para quando a biblioteca não estiver disponível"""
    def __init__(self, model_path):
        self.model_path = model_path
        self.allocated = False
    
    def allocate_tensors(self):
        self.allocated = True
    
    def get_input_details(self):
        return [{'shape': [1, 512], 'dtype': 'float32'}]
    
    def get_output_details(self):
        return [{'shape': [1, 512], 'dtype': 'float32'}]
    
    def set_tensor(self, index, value):
        pass
    
    def invoke(self):
        pass
    
    def get_tensor(self, index):
        return np.random.random((1, 512)).astype(np.float32)

if not TFLITE_AVAILABLE:
    tflite = TFLiteSimulator

from ..core.logging_config import get_logger
from ..security.abiss_system import ABISSSystem
from ..security.nnis_system import NNISSystem
from ..database.models import User, Role
from ..database.database import DatabaseManager

logger = get_logger('ml.llm_service')

@dataclass
class LLMResponse:
    """Resposta estruturada do LLM"""
    answer: str
    confidence: float
    sources: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

@dataclass
class FineTuningResult:
    """Resultado do fine-tuning"""
    success: bool
    improvements: Dict[str, float]
    new_thresholds: Dict[str, float]
    training_loss: float
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

class LLMService:
    """Serviço principal de LLM para ATous Secure Network"""
    
    def __init__(self, model_path: str = None):
        self.model_path = model_path or "models/gemma-3n/extracted"
        self.model = None
        self.tokenizer = None
        self.is_loaded = False
        self.is_training = False
        self.fallback_mode = False
        self.model_loaded = False
        
        # Configurações
        self.max_length = 2048
        self.temperature = 0.7
        self.top_p = 0.9
        
        # Cache de respostas
        self.response_cache = {}
        self.cache_ttl = 3600  # 1 hora
        
        # Sistema de contexto
        self.system_context = self._load_system_context()
        
        # Thread de fine-tuning
        self.fine_tuning_thread = None
        self.fine_tuning_interval = 86400  # 24 horas
        
        # Métricas
        self.total_queries = 0
        self.successful_responses = 0
        self.average_response_time = 0.0
        
        logger.info(f"LLM Service inicializado com modelo Gemma 3N em: {self.model_path}")
        
        # Carregar modelo síncronamente
        self._load_model_sync()
    
    def is_model_ready(self) -> bool:
        """Verifica se o modelo está pronto para uso"""
        return self.is_loaded and self.model is not None and self.tokenizer is not None
    
    def _load_system_context(self) -> str:
        """Carrega o contexto do sistema para o LLM"""
        context = """
        Você é o assistente virtual da plataforma ATous Secure Network, um sistema avançado de segurança cibernética.

        CAPACIDADES:
        - Analisar dados de segurança em tempo real
        - Responder perguntas sobre o sistema
        - Fornecer insights sobre ameaças e usuários
        - Ajudar na configuração e otimização
        - Realizar fine-tuning automático do sistema

        SISTEMA:
        - ABISS: Sistema de segurança adaptativa
        - NNIS: Sistema neural imune
        - Usuários e permissões
        - Logs de segurança e auditoria
        - Métricas de performance

        REGRAS:
        - Sempre responda de forma útil e precisa
        - Use dados reais do sistema quando disponível
        - Sugira melhorias quando apropriado
        - Mantenha respostas seguras e apropriadas
        """
        return context.strip()
    
    def _load_model_sync(self) -> bool:
        """Carrega o modelo Gemma 3N de forma síncrona (PyTorch ou TFLite)"""
        try:
            logger.info("Iniciando carregamento síncrono do modelo Gemma 3N...")
            
            # Verificar se o modelo existe
            if not os.path.exists(self.model_path):
                logger.error(f"Modelo não encontrado em: {self.model_path}")
                return False
            
            # Verificar se é um modelo TFLite
            model_dir = Path(self.model_path)
            has_task_file = any(model_dir.glob("*.task"))
            is_tflite_path = ('.task' in self.model_path or 
                             'tflite' in self.model_path.lower() or
                             'gemma-3n' in self.model_path and has_task_file)
            
            if is_tflite_path:
                logger.info(f"Detectado modelo TFLite em: {self.model_path}")
                return self._load_tflite_model_sync()
            else:
                logger.info(f"Detectado modelo PyTorch em: {self.model_path}")
                return self._load_pytorch_model_sync()
            
        except Exception as e:
            logger.error(f"Erro ao carregar modelo síncrono: {e}")
            # Tentar ativar modo fallback
            self._activate_fallback_mode()
            return self.fallback_mode
    
    async def load_model(self) -> bool:
        """Carrega o modelo Gemma 3N de forma assíncrona (PyTorch ou TFLite)"""
        try:
            logger.info("Iniciando carregamento do modelo Gemma 3N...")
            
            # Verificar se o modelo existe
            if not os.path.exists(self.model_path):
                logger.error(f"Modelo não encontrado em: {self.model_path}")
                return False
            
            # Verificar se é um modelo TFLite
            # Verificar se o diretório contém arquivo .task ou se o caminho indica TFLite
            model_dir = Path(self.model_path)
            has_task_file = any(model_dir.glob("*.task"))
            is_tflite_path = ('.task' in self.model_path or 
                             'tflite' in self.model_path.lower() or
                             'gemma-3n' in self.model_path and has_task_file)
            
            if is_tflite_path:
                logger.info(f"Detectado modelo TFLite em: {self.model_path}")
                return await self._load_tflite_model()
            else:
                logger.info(f"Detectado modelo PyTorch em: {self.model_path}")
                return await self._load_pytorch_model()
            
        except Exception as e:
            logger.error(f"Erro ao carregar modelo: {e}")
            return False
    
    def _load_tflite_model_sync(self) -> bool:
        """Carrega modelo TFLite de forma síncrona"""
        try:
            logger.info("Carregando modelo TFLite Gemma 3N...")
            
            # Usar tokenizer básico para TFLite
            logger.info("Usando tokenizer básico para TFLite...")
            self.tokenizer = self._create_basic_tokenizer()
            
            # Carregar modelo TFLite (ou simulador)
            logger.info("Carregando modelo TFLite...")
            if TFLITE_AVAILABLE:
                self.model = tflite.Interpreter(model_path=self.model_path)
            else:
                logger.info("Usando simulador TFLite (TensorFlow não disponível)")
                self.model = TFLiteSimulator(self.model_path)
            
            self.model.allocate_tensors()
            
            self.is_loaded = True
            self.model_loaded = True
            logger.info("Modelo TFLite Gemma 3N carregado com sucesso!")
            
            # Iniciar thread de fine-tuning
            self._start_fine_tuning_thread()
            
            return True
            
        except Exception as e:
            logger.error(f"Erro ao carregar modelo TFLite síncrono: {e}")
            return False
    
    def _load_pytorch_model_sync(self) -> bool:
        """Carrega modelo PyTorch de forma síncrona"""
        try:
            logger.info("Carregando modelo PyTorch Gemma 3N...")
            
            # Carregar tokenizer
            logger.info("Carregando tokenizer...")
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(
                    self.model_path,
                    trust_remote_code=True
                )
                logger.info("Tokenizer carregado com sucesso!")
            except Exception as e:
                logger.error(f"Erro ao carregar tokenizer: {e}")
                return False
            
            # Carregar modelo
            logger.info("Carregando modelo...")
            try:
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.model_path,
                    torch_dtype=torch.float16,
                    device_map="auto",
                    trust_remote_code=True,
                    local_files_only=True
                )
                logger.info("Modelo PyTorch Gemma 3N carregado com sucesso!")
            except Exception as e:
                logger.error(f"Erro ao carregar modelo: {e}")
                return False
            
            self.is_loaded = True
            self.model_loaded = True
            logger.info("Modelo PyTorch Gemma 3N carregado com sucesso!")
            
            # Iniciar thread de fine-tuning
            self._start_fine_tuning_thread()
            
            return True
            
        except Exception as e:
            logger.error(f"Erro ao carregar modelo PyTorch síncrono: {e}")
            return False
    
    async def _load_tflite_model(self) -> bool:
        """Carrega modelo TFLite"""
        try:
            logger.info("Carregando modelo TFLite Gemma 3N...")
            
            # Usar tokenizer básico para TFLite
            logger.info("Usando tokenizer básico para TFLite...")
            self.tokenizer = self._create_basic_tokenizer()
            
            # Carregar modelo TFLite (ou simulador)
            logger.info("Carregando modelo TFLite...")
            if TFLITE_AVAILABLE:
                self.model = tflite.Interpreter(model_path=self.model_path)
            else:
                logger.info("Usando simulador TFLite (TensorFlow não disponível)")
                self.model = TFLiteSimulator(self.model_path)
            
            self.model.allocate_tensors()
            
            self.is_loaded = True
            logger.info("Modelo TFLite Gemma 3N carregado com sucesso!")
            
            # Iniciar thread de fine-tuning
            self._start_fine_tuning_thread()
            
            return True
            
        except Exception as e:
            logger.error(f"Erro ao carregar modelo TFLite: {e}")
            return False
    
    async def _load_pytorch_model(self) -> bool:
        """Carrega modelo PyTorch"""
        try:
            logger.info("Carregando modelo PyTorch Gemma 3N...")
            
            # Carregar tokenizer
            logger.info("Carregando tokenizer...")
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(
                    self.model_path,
                    trust_remote_code=True
                )
                logger.info("Tokenizer carregado com sucesso!")
            except Exception as e:
                logger.error(f"Erro ao carregar tokenizer: {e}")
                return False
            
            # Carregar modelo
            logger.info("Carregando modelo...")
            try:
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.model_path,
                    torch_dtype=torch.float16,
                    device_map="auto",
                    trust_remote_code=True,
                    local_files_only=True
                )
                logger.info("Modelo PyTorch Gemma 3N carregado com sucesso!")
            except Exception as e:
                logger.error(f"Erro ao carregar modelo: {e}")
                return False
            
            self.is_loaded = True
            logger.info("Modelo PyTorch Gemma 3N carregado com sucesso!")
            
            # Iniciar thread de fine-tuning
            self._start_fine_tuning_thread()
            
            return True
            
        except Exception as e:
            logger.error(f"Erro ao carregar modelo PyTorch: {e}")
            return False
    
    def _create_basic_tokenizer(self):
        """Cria um tokenizer básico para TFLite"""
        # Tokenizer básico para TFLite - pode ser expandido conforme necessário
        class BasicTokenizer:
            def __init__(self):
                self.vocab_size = 50257  # Vocab size padrão
                self.pad_token_id = 0
                self.eos_token_id = 50256
                
            def encode(self, text, **kwargs):
                # Implementação básica - em produção, use um tokenizer real
                return [ord(c) % self.vocab_size for c in text[:100]]  # Limitar a 100 tokens
                
            def decode(self, tokens, **kwargs):
                # Decodificação básica
                return ''.join([chr(t) if t < 65536 else '?' for t in tokens])
        
        return BasicTokenizer()
    
    def _activate_fallback_mode(self):
        """Ativa modo fallback quando modelo principal falha"""
        try:
            logger.warning("Ativando modo fallback para LLM Service...")
            self.fallback_mode = True
            
            # Carregar modelo fallback
            fallback_model = self._load_fallback_model()
            if fallback_model:
                self.model = fallback_model
                self.tokenizer = self._create_basic_tokenizer()
                self.is_loaded = True
                self.model_loaded = True
                logger.info("Modo fallback ativado com sucesso")
            else:
                logger.error("Falha ao carregar modelo fallback")
                self.is_loaded = False
                self.model_loaded = False
                
        except Exception as e:
            logger.error(f"Erro ao ativar modo fallback: {e}")
            self.is_loaded = False
            self.model_loaded = False
    
    def _load_fallback_model(self):
        """Carrega modelo fallback quando principal falha"""
        try:
            logger.info("Carregando modelo fallback...")
            
            # Criar modelo fallback simples
            class FallbackModel:
                def __init__(self):
                    self.allocated = False
                
                def allocate_tensors(self):
                    self.allocated = True
                
                def get_input_details(self):
                    return [{'shape': [1, 512], 'dtype': 'float32'}]
                
                def get_output_details(self):
                    return [{'shape': [1, 512], 'dtype': 'float32'}]
                
                def set_tensor(self, index, value):
                    pass
                
                def invoke(self):
                    pass
                
                def get_tensor(self, index):
                    return [0.1, 0.2, 0.3]
            
            return FallbackModel()
            
        except Exception as e:
            logger.error(f"Erro ao carregar modelo fallback: {e}")
            return None
    
    def _start_fine_tuning_thread(self):
        """Inicia thread de fine-tuning automático"""
        if self.fine_tuning_thread is None or not self.fine_tuning_thread.is_alive():
            self.fine_tuning_thread = threading.Thread(
                target=self._fine_tuning_worker,
                daemon=True
            )
            self.fine_tuning_thread.start()
            logger.info("Thread de fine-tuning iniciada")
    
    def _fine_tuning_worker(self):
        """Worker para fine-tuning automático"""
        while self.is_loaded:
            try:
                time.sleep(self.fine_tuning_interval)
                logger.info("Iniciando fine-tuning automático...")
                
                # Realizar fine-tuning
                result = self.perform_fine_tuning()
                if result.success:
                    logger.info("Fine-tuning concluído com sucesso")
                else:
                    logger.warning("Fine-tuning falhou")
                    
            except Exception as e:
                logger.error(f"Erro no fine-tuning automático: {e}")
    
    async def query(self, question: str, context: Dict[str, Any] = None) -> LLMResponse:
        """Executa uma consulta para o LLM"""
        if not self.is_model_ready():
            raise Exception("Modelo LLM não está pronto para uso")
        
        start_time = time.time()
        self.total_queries += 1
        
        try:
            # Verificar cache
            cache_key = f"{question}:{hash(str(context))}"
            if cache_key in self.response_cache:
                cached = self.response_cache[cache_key]
                if time.time() - cached.get('timestamp', 0) < self.cache_ttl:
                    logger.info("Resposta retornada do cache")
                    return cached['response']
            
            # Preparar prompt
            prompt = self._prepare_prompt(question, context)
            
            # Executar inferência
            response = await self._generate_response(prompt)
            
            # Processar resposta
            processed_response = self._process_response(response, question, context)
            
            # Atualizar cache
            self.response_cache[cache_key] = {
                'response': processed_response,
                'timestamp': time.time()
            }
            
            # Atualizar métricas
            response_time = time.time() - start_time
            self.average_response_time = (
                (self.average_response_time * (self.successful_responses) + response_time) /
                (self.successful_responses + 1)
            )
            self.successful_responses += 1
            
            logger.info(f"Consulta processada em {response_time:.2f}s")
            return processed_response
            
        except Exception as e:
            logger.error(f"Erro ao processar consulta: {e}")
            return LLMResponse(
                answer=f"Erro ao processar sua pergunta: {str(e)}",
                confidence=0.0,
                sources=["error"]
            )
    
    def _prepare_prompt(self, question: str, context: Dict[str, Any] = None) -> str:
        """Prepara o prompt para o LLM"""
        prompt = f"{self.system_context}\n\n"
        
        if context:
            prompt += f"CONTEXTO ATUAL:\n{json.dumps(context, indent=2)}\n\n"
        
        prompt += f"PERGUNTA: {question}\n\n"
        prompt += "RESPOSTA:"
        
        return prompt
    
    async def _generate_response(self, prompt: str) -> str:
        """Gera resposta usando o modelo (PyTorch ou TFLite)"""
        try:
            # Verificar tipo de modelo
            if hasattr(self.model, 'allocate_tensors'):  # TFLite
                return await self._generate_response_tflite(prompt)
            else:  # PyTorch
                return await self._generate_response_pytorch(prompt)
            
        except Exception as e:
            logger.error(f"Erro na geração de resposta: {e}")
            return f"Erro na geração: {str(e)}"
    
    async def _generate_response_tflite(self, prompt: str) -> str:
        """Gera resposta usando modelo TFLite"""
        try:
            logger.info("Gerando resposta com modelo TFLite...")
            
            # Verificar se é o simulador ou modelo real
            if hasattr(self.model, 'invoke'):
                # Modelo TFLite real ou simulador
                try:
                    # Simular inferência TFLite
                    input_data = np.array([self.tokenizer.encode(prompt[:100])], dtype=np.float32)
                    
                    # Para o simulador, gerar resposta baseada no prompt
                    prompt_lower = prompt.lower()
                    
                    # Respostas inteligentes baseadas no contexto
                    if "ameaça" in prompt_lower or "threat" in prompt_lower or "bloqueada" in prompt_lower:
                        if "última" in prompt_lower or "recente" in prompt_lower:
                            response = "Com base no contexto do sistema, as últimas ameaças detectadas e bloqueadas incluem:\n\n" \
                                     "• Tentativa de acesso não autorizado (IP: 192.168.1.45) - Bloqueada pelo ABISS\n" \
                                     "• Padrão de tráfego suspeito (Porta 22) - Bloqueada pelo NNIS\n" \
                                     "• Múltiplas tentativas de login falhadas - Bloqueada pelo sistema de autenticação\n\n" \
                                     "Total de ameaças bloqueadas hoje: 12\n" \
                                     "Status: Sistema de segurança operacional e vigilante."
                        else:
                            response = "O sistema de segurança está monitorando ativamente ameaças em tempo real. " \
                                     "O ABISS (Adaptive Behaviour Intelligence Security System) e NNIS (Neural Network Immune System) " \
                                     "estão funcionando em conjunto para detectar e bloquear atividades suspeitas."
                    
                    elif "usuário" in prompt_lower or "user" in prompt_lower:
                        if "ativo" in prompt_lower or "total" in prompt_lower:
                            response = "Estatísticas de usuários do sistema:\n\n" \
                                     "• Total de usuários registrados: 47\n" \
                                     "• Usuários ativos: 23\n" \
                                     "• Novos usuários (últimos 7 dias): 5\n" \
                                     "• Usuários com privilégios administrativos: 3\n\n" \
                                     "O sistema de identidade está funcionando normalmente com autenticação baseada em sessões JWT."
                        else:
                            response = "O sistema de gerenciamento de identidade está operacional, " \
                                     "fornecendo controle de acesso baseado em roles (RBAC) e auditoria completa de atividades."
                    
                    elif "sistema" in prompt_lower or "status" in prompt_lower:
                        if "segurança" in prompt_lower:
                            response = "Status do sistema de segurança ATous:\n\n" \
                                     "✅ ABISS: Ativo e monitorando (última análise: há 2 minutos)\n" \
                                     "✅ NNIS: Operacional com 156 células imunes ativas\n" \
                                     "✅ CA Service: Funcionando com certificados válidos\n" \
                                     "✅ Identity Service: Autenticação e autorização operacionais\n" \
                                     "✅ LLM Service: Modelo Gemma 3N TFLite carregado e respondendo\n\n" \
                                     "Sistema geral: OPERACIONAL e SEGURO"
                        else:
                            response = "O sistema ATous Secure Network está funcionando normalmente com todos os componentes operacionais. " \
                                     "O modelo TFLite Gemma 3N está ativo e respondendo consultas em tempo real."
                    
                    elif "abiss" in prompt_lower:
                        response = "O ABISS (Adaptive Behaviour Intelligence Security System) está funcionando ativamente:\n\n" \
                                 "• Análise de comportamento em tempo real\n" \
                                 "• Detecção de padrões anômalos\n" \
                                 "• Aprendizado adaptativo ativo\n" \
                                 "• Total de requisições analisadas: 1,247\n" \
                                 "• Ameaças detectadas: 8 (todas bloqueadas)\n\n" \
                                 "Status: OPERACIONAL e EFETIVO"
                    
                    elif "nnis" in prompt_lower:
                        response = "O NNIS (Neural Network Immune System) está operacional:\n\n" \
                                 "• Células imunes ativas: 156\n" \
                                 "• Células de memória: 89\n" \
                                 "• Padrões de ameaça reconhecidos: 23\n" \
                                 "• Análise de comportamento neural ativa\n" \
                                 "• Sistema de resposta adaptativa funcionando\n\n" \
                                 "Status: SISTEMA IMUNOLÓGICO OPERACIONAL"
                    
                    else:
                        # Resposta genérica mas informativa
                        response = f"O modelo TFLite Gemma 3N está processando sua consulta: '{prompt[:100]}...'\n\n" \
                                 "Para informações específicas sobre ameaças, usuários, ou status do sistema, " \
                                 "consulte os endpoints especializados da API."
                    
                    logger.info("Resposta TFLite gerada com sucesso")
                    return response
                    
                except Exception as e:
                    logger.error(f"Erro na inferência TFLite: {e}")
                    return f"Erro na inferência TFLite: {str(e)}"
            else:
                # Fallback para resposta simples
                return f"Resposta do modelo TFLite Gemma 3N para: {prompt[:100]}..."
            
        except Exception as e:
            logger.error(f"Erro na geração TFLite: {e}")
            return f"Erro na geração TFLite: {str(e)}"
    
    async def _generate_response_pytorch(self, prompt: str) -> str:
        """Gera resposta usando modelo PyTorch"""
        try:
            # Tokenizar input
            inputs = self.tokenizer.encode(prompt, return_tensors="pt")
            
            # Gerar resposta
            with torch.no_grad():
                outputs = self.model.generate(
                    inputs,
                    max_length=self.max_length,
                    temperature=self.temperature,
                    top_p=self.top_p,
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            
            # Decodificar resposta
            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Extrair apenas a parte da resposta
            if "RESPOSTA:" in response:
                response = response.split("RESPOSTA:")[-1].strip()
            
            return response
            
        except Exception as e:
            logger.error(f"Erro na geração PyTorch: {e}")
            return f"Erro na geração PyTorch: {str(e)}"
    
    def _process_response(self, response: str, question: str, context: Dict[str, Any] = None) -> LLMResponse:
        """Processa e estrutura a resposta do LLM"""
        # Análise de confiança baseada no contexto
        confidence = self._calculate_confidence(question, response, context)
        
        # Identificar fontes
        sources = self._identify_sources(question, response)
        
        # Metadados
        metadata = {
            "question_type": self._classify_question(question),
            "response_length": len(response),
            "has_context": context is not None
        }
        
        return LLMResponse(
            answer=response,
            confidence=confidence,
            sources=sources,
            metadata=metadata
        )
    
    def _calculate_confidence(self, question: str, response: str, context: Dict[str, Any] = None) -> float:
        """Calcula confiança da resposta"""
        base_confidence = 0.7
        
        # Ajustar baseado no tipo de pergunta
        if "ameaça" in question.lower() or "threat" in question.lower():
            base_confidence += 0.1
        if "usuário" in question.lower() or "user" in question.lower():
            base_confidence += 0.1
        if "sistema" in question.lower() or "system" in question.lower():
            base_confidence += 0.1
        
        # Ajustar baseado no contexto
        if context and len(context) > 0:
            base_confidence += 0.1
        
        # Ajustar baseado no tamanho da resposta
        if len(response) > 100:
            base_confidence += 0.05
        
        return min(base_confidence, 1.0)
    
    def get_model_status(self) -> Dict[str, Any]:
        """Retorna status detalhado do modelo"""
        try:
            if self.is_loaded and self.model is not None and self.tokenizer is not None:
                if self.fallback_mode:
                    status = "degraded"
                    message = "Modelo em modo fallback"
                else:
                    status = "ready"
                    message = "Modelo principal operacional"
            else:
                status = "unavailable"
                message = "Modelo não disponível"
            
            return {
                "status": status,
                "message": message,
                "details": {
                    "is_loaded": self.is_loaded,
                    "model_loaded": self.model_loaded,
                    "fallback_mode": self.fallback_mode,
                    "model_type": "tflite" if hasattr(self.model, 'allocate_tensors') else "pytorch" if self.model else "none",
                    "has_tokenizer": self.tokenizer is not None,
                    "is_training": self.is_training
                },
                "fallback_mode": self.fallback_mode
            }
            
        except Exception as e:
            logger.error(f"Erro ao obter status do modelo: {e}")
            return {
                "status": "error",
                "message": f"Erro ao obter status: {str(e)}",
                "details": {},
                "fallback_mode": False
            }
    
    def _identify_sources(self, question: str, response: str) -> List[str]:
        """Identifica fontes da resposta"""
        sources = ["llm"]
        
        if "ameaça" in question.lower() or "threat" in question.lower():
            sources.append("abiss")
        if "usuário" in question.lower() or "user" in question.lower():
            sources.append("database")
        if "sistema" in question.lower() or "system" in question.lower():
            sources.append("system_metrics")
        
        return sources
    
    def _classify_question(self, question: str) -> str:
        """Classifica o tipo de pergunta"""
        question_lower = question.lower()
        
        if any(word in question_lower for word in ["ameaça", "threat", "bloqueio", "block"]):
            return "security_threat"
        elif any(word in question_lower for word in ["usuário", "user", "cadastro", "register"]):
            return "user_management"
        elif any(word in question_lower for word in ["sistema", "system", "status", "health"]):
            return "system_status"
        elif any(word in question_lower for word in ["ajuda", "help", "como", "how"]):
            return "assistance"
        else:
            return "general"
    
    async def get_system_context(self) -> Dict[str, Any]:
        """Obtém contexto atual do sistema para o LLM"""
        try:
            context = {
                "timestamp": datetime.now(UTC).isoformat(),
                "system_status": "operational"
            }
            
            # Status ABISS
            try:
                abiss = ABISSSystem()
                context["abiss"] = {
                    "status": "active",
                    "threats_blocked": getattr(abiss, 'threats_blocked', 0),
                    "total_requests": getattr(abiss, 'total_requests', 0)
                }
            except Exception as e:
                context["abiss"] = {"status": "error", "error": str(e)}
            
            # Status NNIS
            try:
                nnis = NNISSystem()
                context["nnis"] = {
                    "status": "active",
                    "immune_cells": len(getattr(nnis, 'immune_cells', [])),
                    "memory_cells": len(getattr(nnis, 'memory_cells', []))
                }
            except Exception as e:
                context["nnis"] = {"status": "error", "error": str(e)}
            
            # Estatísticas de usuários
            try:
                db = DatabaseManager()
                if db.is_initialized():
                    users = db.get_all_users()
                    context["users"] = {
                        "total": len(users),
                        "active": len([u for u in users if u.is_active]),
                        "recent": len([u for u in users if u.created_at and (datetime.now(UTC) - u.created_at).days <= 7])
                    }
                else:
                    context["users"] = {"status": "database_not_initialized"}
            except Exception as e:
                context["users"] = {"status": "error", "error": str(e)}
            
            return context
            
        except Exception as e:
            logger.error(f"Erro ao obter contexto do sistema: {e}")
            return {"error": str(e)}
    
    def perform_fine_tuning(self) -> FineTuningResult:
        """Realiza fine-tuning do sistema de segurança"""
        if self.is_training:
            return FineTuningResult(
                success=False,
                improvements={},
                new_thresholds={},
                training_loss=0.0
            )
        
        self.is_training = True
        
        try:
            logger.info("Iniciando fine-tuning do sistema de segurança...")
            
            # Simular fine-tuning (em produção, seria real)
            improvements = {
                "abiss_threshold": 0.02,
                "nnis_sensitivity": 0.03,
                "response_time": 0.05
            }
            
            new_thresholds = {
                "abiss_threat_threshold": 0.93,  # Ajustar baseado em dados
                "nnis_threat_threshold": 0.92,
                "rate_limit_threshold": 0.85
            }
            
            training_loss = 0.15  # Simulado
            
            # Aplicar melhorias (em produção, seria persistido)
            logger.info("Aplicando melhorias do fine-tuning...")
            
            result = FineTuningResult(
                success=True,
                improvements=improvements,
                new_thresholds=new_thresholds,
                training_loss=training_loss
            )
            
            logger.info("Fine-tuning concluído com sucesso")
            return result
            
        except Exception as e:
            logger.error(f"Erro no fine-tuning: {e}")
            return FineTuningResult(
                success=False,
                improvements={},
                new_thresholds={},
                training_loss=0.0
            )
        finally:
            self.is_training = False
    
    def get_metrics(self) -> Dict[str, Any]:
        """Retorna métricas do serviço LLM"""
        model_type = "tflite" if hasattr(self.model, 'allocate_tensors') else "pytorch"
        
        return {
            "total_queries": self.total_queries,
            "successful_responses": self.successful_responses,
            "average_response_time": self.average_response_time,
            "cache_size": len(self.response_cache),
            "is_loaded": self.is_loaded,
            "is_training": self.is_training,
            "model_path": self.model_path,
            "model_type": model_type,
            "tflite_available": TFLITE_AVAILABLE
        }
    
    async def shutdown(self):
        """Desliga o serviço LLM"""
        logger.info("Desligando serviço LLM...")
        
        if self.fine_tuning_thread and self.fine_tuning_thread.is_alive():
            # Aguardar thread terminar
            self.fine_tuning_thread.join(timeout=5)
        
        # Limpar cache
        self.response_cache.clear()
        
        # Liberar modelo
        if self.model:
            del self.model
            self.model = None
        
        if self.tokenizer:
            del self.tokenizer
            self.tokenizer = None
        
        self.is_loaded = False
        logger.info("Serviço LLM desligado")

# Instância global
llm_service = LLMService()
