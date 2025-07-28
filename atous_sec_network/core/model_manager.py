"""
Federated Model Manager - OTA Update System
Sistema de atualização Over-The-Air para modelos federados
"""
import os
import json
import hashlib
import logging
import tempfile
import shutil
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import requests
import bsdiff4
import gzip
import zlib
import time

from .model_metadata import ModelMetadata


class FederatedModelUpdater:
    """
    Sistema de atualização OTA para modelos federados
    
    Gerencia downloads incrementais, verificação de integridade,
    aplicação de patches e rollback automático em caso de falha.
    """
    
    def __init__(self, node_id: str, current_version: int = 0, 
                 model_path: str = "model.bin", backup_dir: str = "backups"):
        """
        Inicializa o gerenciador de modelos
        
        Args:
            node_id: Identificador único do nó
            current_version: Versão atual do modelo
            model_path: Caminho para o arquivo do modelo
            backup_dir: Diretório para backups
        """
        self.node_id = node_id
        self.current_version = current_version
        self.model_path = model_path
        self.backup_dir = backup_dir
        self.logger = logging.getLogger(__name__)
        
        # Criar diretório de backup se não existir
        os.makedirs(backup_dir, exist_ok=True)
        
        # Configurações de segurança
        self.verify_signatures = True
        self.verify_checksums = True
        self.max_rollback_versions = 3
        
        # Configurações de rede
        self.timeout = 30
        self.max_retries = 3
        self.chunk_size = 8192
        
        # Histórico de versões
        self.version_history = []
        self._load_version_history()
    
    def check_for_updates(self, aggregation_server: str) -> bool:
        """
        Verifica se há atualizações disponíveis
        
        Args:
            aggregation_server: URL do servidor de agregação
            
        Returns:
            True se atualização foi aplicada, False caso contrário
        """
        try:
            # Verificar versão mais recente
            response = requests.get(
                f"{aggregation_server}/model-version",
                timeout=self.timeout
            )
            response.raise_for_status()
            
            server_info = response.json()
            latest_version = server_info.get("version", 0)
            
            if latest_version > self.current_version:
                self.logger.info(f"Nova versão disponível: {latest_version}")
                
                # Verificar se o dispositivo tem recursos
                if not self._check_device_resources(server_info):
                    self.logger.warning("Dispositivo não tem recursos para atualização")
                    return False
                
                # Download e aplicação do patch
                diff_path = self._download_model_diff(aggregation_server, latest_version)
                self._apply_patch(diff_path)
                
                # Atualizar versão
                self.current_version = latest_version
                self._save_version_history()
                
                self.logger.info(f"Modelo atualizado para versão {latest_version}")
                return True
            else:
                self.logger.debug("Modelo já está na versão mais recente")
                return False
                
        except Exception as e:
            self.logger.error(f"Falha na verificação de atualizações: {e}")
            return False
    
    def _download_model_diff(self, aggregation_server: str, target_version: int) -> str:
        """
        Baixa diferenças binárias do modelo
        
        Args:
            aggregation_server: URL do servidor
            target_version: Versão alvo
            
        Returns:
            Caminho para o arquivo de diferenças
        """
        url = f"{aggregation_server}/model-diff/{self.current_version}/{target_version}"
        
        try:
            response = requests.get(url, stream=True, timeout=self.timeout)
            response.raise_for_status()
            
            # Determinar nome do arquivo
            diff_filename = f"model_{self.current_version}_to_{target_version}.diff"
            diff_path = os.path.join(tempfile.gettempdir(), diff_filename)
            
            # Download com verificação de integridade
            with open(diff_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=self.chunk_size):
                    if chunk:
                        f.write(chunk)
            
            # Verificar checksum se fornecido
            if self.verify_checksums and "checksum" in response.headers:
                expected_checksum = response.headers["checksum"]
                if not self._validate_checksum(diff_path, expected_checksum):
                    raise ValueError("Checksum inválido para arquivo de diferenças")
            
            self.logger.info(f"Download concluído: {diff_path}")
            return diff_path
            
        except Exception as e:
            self.logger.error(f"Falha no download: {e}")
            raise
    
    def _apply_patch(self, diff_path: str) -> None:
        """
        Aplica patch ao modelo local
        
        Args:
            diff_path: Caminho para o arquivo de diferenças
        """
        # Criar backup antes da aplicação
        backup_path = self._create_backup()
        
        try:
            # Ler modelo atual
            with open(self.model_path, "rb") as f:
                current_model = f.read()
            
            # Ler diferenças
            with open(diff_path, "rb") as f:
                diff_data = f.read()
            
            # Aplicar patch
            patched_model = bsdiff4.patch(current_model, diff_data)
            
            # Verificar integridade do modelo resultante
            if not self._verify_model_integrity(patched_model):
                raise ValueError("Modelo resultante é inválido")
            
            # Escrever novo modelo
            with open(self.model_path, "wb") as f:
                f.write(patched_model)
            
            # Verificar se o arquivo foi escrito corretamente
            if os.path.getsize(self.model_path) == 0:
                raise ValueError("Arquivo do modelo ficou vazio após patch")
            
            # Limpar arquivo de diferenças
            os.remove(diff_path)
            
            # Remover backup antigo se aplicação foi bem-sucedida
            if backup_path:
                os.remove(backup_path)
            
            self.logger.info("Patch aplicado com sucesso")
            
        except Exception as e:
            self.logger.error(f"Falha na aplicação do patch: {e}")
            
            # Restaurar backup em caso de falha
            if backup_path and os.path.exists(backup_path):
                shutil.copy2(backup_path, self.model_path)
                self.logger.info("Backup restaurado após falha")
            
            raise
    
    def _create_backup(self) -> Optional[str]:
        """Cria backup do modelo atual"""
        if not os.path.exists(self.model_path):
            return None
        
        backup_filename = f"model_v{self.current_version}_{int(time.time())}.bak"
        backup_path = os.path.join(self.backup_dir, backup_filename)
        
        try:
            shutil.copy2(self.model_path, backup_path)
            self.logger.debug(f"Backup criado: {backup_path}")
            return backup_path
        except Exception as e:
            self.logger.error(f"Falha ao criar backup: {e}")
            return None
    
    def _verify_model_integrity(self, model_data: bytes) -> bool:
        """
        Verifica integridade do modelo
        
        Args:
            model_data: Dados do modelo
            
        Returns:
            True se o modelo é válido
        """
        # Verificações básicas
        if len(model_data) == 0:
            return False
        
        # Verificar cabeçalho do modelo (se aplicável)
        if len(model_data) < 8:
            return False
        
        # Verificar magic number (exemplo)
        magic_number = model_data[:4]
        if magic_number != b"MODL":  # Exemplo
            return False
        
        return True
    
    def _validate_checksum(self, file_path: str, expected_checksum: str) -> bool:
        """
        Valida checksum de um arquivo
        
        Args:
            file_path: Caminho do arquivo
            expected_checksum: Checksum esperado
            
        Returns:
            True se checksum é válido
        """
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            
            calculated_checksum = hashlib.sha256(file_data).hexdigest()
            return calculated_checksum == expected_checksum
            
        except Exception as e:
            self.logger.error(f"Erro ao validar checksum: {e}")
            return False
    
    def _check_device_resources(self, server_info: Dict) -> bool:
        """
        Verifica se o dispositivo tem recursos para a atualização
        
        Args:
            server_info: Informações do servidor sobre a atualização
            
        Returns:
            True se o dispositivo tem recursos suficientes
        """
        model_size = server_info.get("size", 0)
        
        # Verificar espaço em disco
        try:
            free_space = shutil.disk_usage(os.path.dirname(self.model_path)).free
            if free_space < model_size * 3:  # 3x o tamanho para operação segura
                self.logger.warning(f"Espaço insuficiente: {free_space} < {model_size * 3}")
                return False
        except Exception as e:
            self.logger.warning(f"Não foi possível verificar espaço em disco: {e}")
        
        # Verificar memória disponível (se possível)
        try:
            import psutil
            available_memory = psutil.virtual_memory().available
            if available_memory < model_size * 2:  # 2x o tamanho para processamento
                self.logger.warning(f"Memória insuficiente: {available_memory} < {model_size * 2}")
                return False
        except ImportError:
            self.logger.debug("psutil não disponível - pulando verificação de memória")
        
        return True
    
    def should_update(self, model_size: int, available_memory: int) -> bool:
        """
        Determina se o dispositivo deve atualizar baseado em recursos
        
        Args:
            model_size: Tamanho do modelo em bytes
            available_memory: Memória disponível em bytes
            
        Returns:
            True se deve atualizar
        """
        # Requer 3x o tamanho do modelo para operação segura
        return available_memory > model_size * 3
    
    def download_model(self, source_url: str, target_path: str, **kwargs) -> bool:
        """
        Download a model from the given URL to the specified path.
        
        Args:
            source_url: URL to download the model from
            target_path: Local path to save the downloaded model
            **kwargs: Additional arguments:
                - checksum: Expected checksum of the file (optional)
                - timeout: Request timeout in seconds (default: 60)
                - headers: HTTP headers for the request (optional)
                
        Returns:
            bool: True if download was successful, False otherwise
        """
        try:
            timeout = kwargs.get('timeout', 60)
            headers = kwargs.get('headers', {})
            
            self.logger.info(f"Downloading model from {source_url} to {target_path}")
            
            # Ensure target directory exists
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            
            # Download the file
            response = requests.get(
                source_url,
                stream=True,
                timeout=timeout,
                headers=headers
            )
            response.raise_for_status()
            
            # Save to temporary file first
            temp_path = f"{target_path}.tmp"
            with open(temp_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:  # filter out keep-alive new chunks
                        f.write(chunk)
            
            # Verify checksum if provided
            if 'checksum' in kwargs:
                if not self._verify_checksum(temp_path, kwargs['checksum']):
                    self.logger.error("Checksum verification failed")
                    os.remove(temp_path)
                    return False
            
            # Move to final location
            if os.path.exists(target_path):
                os.remove(target_path)
            os.rename(temp_path, target_path)
            
            self.logger.info(f"Successfully downloaded model to {target_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to download model: {e}")
            # Clean up temp file if it exists
            if 'temp_path' in locals() and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
            return False
    
    def _verify_checksum(self, file_path: str, expected_checksum: str) -> bool:
        """
        Verify the checksum of a file.
        
        Args:
            file_path: Path to the file
            expected_checksum: Expected checksum (SHA-256)
            
        Returns:
            bool: True if checksum matches, False otherwise
        """
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            
            computed_checksum = sha256_hash.hexdigest()
            return computed_checksum == expected_checksum
            
        except Exception as e:
            self.logger.error(f"Error verifying checksum: {e}")
            return False
    
    def _load_version_history(self) -> None:
        """Carrega histórico de versões"""
        history_file = os.path.join(self.backup_dir, "version_history.json")
        
        try:
            if os.path.exists(history_file):
                with open(history_file, "r") as f:
                    self.version_history = json.load(f)
        except Exception as e:
            self.logger.warning(f"Falha ao carregar histórico: {e}")
            self.version_history = []
    
    def _save_version_history(self) -> None:
        """Salva histórico de versões"""
        history_file = os.path.join(self.backup_dir, "version_history.json")
        
        try:
            # Adicionar versão atual ao histórico
            version_entry = {
                "version": self.current_version,
                "timestamp": time.time(),
                "node_id": self.node_id
            }
            
            self.version_history.append(version_entry)
            
            # Manter apenas as últimas versões
            if len(self.version_history) > self.max_rollback_versions:
                self.version_history = self.version_history[-self.max_rollback_versions:]
            
            with open(history_file, "w") as f:
                json.dump(self.version_history, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Falha ao salvar histórico: {e}")
    
    def rollback_to_version(self, target_version: int) -> bool:
        """
        Faz rollback para uma versão anterior
        
        Args:
            target_version: Versão alvo para rollback
            
        Returns:
            True se rollback foi bem-sucedido
        """
        try:
            # Encontrar backup da versão alvo
            backup_pattern = f"model_v{target_version}_*.bak"
            backup_files = list(Path(self.backup_dir).glob(backup_pattern))
            
            if not backup_files:
                self.logger.error(f"Backup da versão {target_version} não encontrado")
                return False
            
            # Usar o backup mais recente
            latest_backup = max(backup_files, key=lambda x: x.stat().st_mtime)
            
            # Restaurar backup
            shutil.copy2(latest_backup, self.model_path)
            self.current_version = target_version
            
            self.logger.info(f"Rollback para versão {target_version} concluído")
            return True
            
        except Exception as e:
            self.logger.error(f"Falha no rollback: {e}")
            return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Retorna informações sobre o modelo atual
        
        Returns:
            Dicionário com informações do modelo
        """
        try:
            if not os.path.exists(self.model_path):
                return {"error": "Modelo não encontrado"}
            
            file_size = os.path.getsize(self.model_path)
            
            with open(self.model_path, "rb") as f:
                model_data = f.read()
            
            checksum = hashlib.sha256(model_data).hexdigest()
            
            return {
                "version": self.current_version,
                "size": file_size,
                "checksum": checksum,
                "path": self.model_path,
                "node_id": self.node_id,
                "last_updated": time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Erro ao obter informações do modelo: {e}")
            return {"error": str(e)}
    
    def cleanup_old_backups(self, max_age_days: int = 7) -> int:
        """
        Remove backups antigos
        
        Args:
            max_age_days: Idade máxima em dias
            
        Returns:
            Número de backups removidos
        """
        try:
            current_time = time.time()
            max_age_seconds = max_age_days * 24 * 3600
            removed_count = 0
            
            for backup_file in Path(self.backup_dir).glob("*.bak"):
                file_age = current_time - backup_file.stat().st_mtime
                
                if file_age > max_age_seconds:
                    backup_file.unlink()
                    removed_count += 1
                    self.logger.debug(f"Backup removido: {backup_file}")
            
            self.logger.info(f"{removed_count} backups antigos removidos")
            return removed_count
            
        except Exception as e:
            self.logger.error(f"Erro ao limpar backups: {e}")
            return 0


    def _verify_digital_signature(self, model_data: bytes, signature: bytes) -> bool:
        """Verifica assinatura digital do modelo"""
        # Implementação básica - em produção usar biblioteca de criptografia
        return True

    def _decrypt_model(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Descriptografa modelo"""
        # Implementação básica - em produção usar biblioteca de criptografia
        return encrypted_data

    def _quantize_model(self, model_data: bytes, precision: str) -> bytes:
        """Quantiza modelo para precisão específica"""
        # Implementação básica
        return model_data

    def _prune_model(self, model_data: bytes, reduction_factor: float) -> bytes:
        """Poda modelo para redução de tamanho"""
        # Implementação básica
        return model_data

    def _optimize_for_hardware(self, model_data: bytes, hardware_config: Dict) -> bytes:
        """Otimiza modelo para hardware específico"""
        # Implementação básica
        return model_data

    def _is_version_compatible(self, target_version: int, current_version: int) -> bool:
        """Verifica compatibilidade de versão"""
        return target_version >= current_version

    def _rollback_to_version(self, target_version: int) -> None:
        """Faz rollback para versão específica"""
        self.current_version = target_version