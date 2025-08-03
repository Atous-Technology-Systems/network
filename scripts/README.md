# Scripts Utilitários 🛠️

Este diretório contém scripts utilitários para desenvolvimento, teste e manutenção do sistema ATous Secure Network.

## Scripts Disponíveis

### `run_app_lite.py`
**Descrição**: Executor leve da aplicação para testes sem dependências pesadas de ML.

**Uso**:
```bash
python scripts/run_app_lite.py
```

**Funcionalidades**:
- Testa importações básicas do pacote
- Valida estrutura do projeto
- Executa verificações de saúde dos módulos
- Ideal para desenvolvimento e CI/CD

**Quando usar**:
- Durante desenvolvimento para testes rápidos
- Em ambientes com recursos limitados
- Para validação de estrutura do projeto
- Em pipelines de CI/CD

## Estrutura dos Scripts

```
scripts/
├── README.md              # Este arquivo
├── run_app_lite.py        # Executor leve da aplicação
└── [futuros scripts]      # Scripts adicionais
```

## Diretrizes para Novos Scripts

### Convenções de Nomenclatura
- Use nomes descritivos em snake_case
- Prefixe com a funcionalidade principal (ex: `test_`, `deploy_`, `monitor_`)
- Inclua extensão `.py` para scripts Python

### Estrutura Recomendada
```python
#!/usr/bin/env python3
"""
Descrição do script.

Este script faz X, Y e Z.
"""

import sys
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Função principal do script."""
    logger.info("Iniciando script...")
    # Implementação aqui
    logger.info("Script concluído.")

if __name__ == "__main__":
    main()
```

### Documentação
- Inclua docstring detalhada no início
- Documente parâmetros e opções
- Adicione exemplos de uso
- Mantenha este README atualizado

## Scripts Planejados

### `deploy_production.py`
- Automatizar deploy em produção
- Validar configurações
- Executar testes de smoke

### `monitor_security.py`
- Monitoramento contínuo de segurança
- Geração de alertas
- Coleta de métricas

### `backup_system.py`
- Backup automático de configurações
- Backup de modelos ML
- Versionamento de dados

### `test_hardware.py`
- Testes de hardware LoRa
- Validação de GPIO
- Testes de conectividade

## Execução de Scripts

### Ambiente Virtual
Sempre execute scripts dentro do ambiente virtual:
```bash
# Ativar ambiente virtual
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Executar script
python scripts/nome_do_script.py
```

### Permissões
Em sistemas Unix, torne os scripts executáveis:
```bash
chmod +x scripts/*.py
./scripts/nome_do_script.py
```

### Logs
Todos os scripts devem usar o sistema de logging configurado:
- Logs de INFO para operações normais
- Logs de WARNING para situações inesperadas
- Logs de ERROR para falhas
- Logs de DEBUG para informações detalhadas

## Contribuindo

Ao adicionar novos scripts:
1. Siga as convenções estabelecidas
2. Teste thoroughly antes de commit
3. Atualize este README
4. Adicione testes se aplicável
5. Documente dependências especiais

---

**Nota**: Todos os scripts devem ser compatíveis com Python 3.11+ e seguir as práticas de segurança do projeto.