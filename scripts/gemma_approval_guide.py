#!/usr/bin/env python3
"""
Guia completo para obter aprovação do Gemma 3N
"""

import webbrowser
import time
from pathlib import Path

def show_approval_steps():
    """Mostra os passos para obter aprovação"""
    print("🔐 Guia Completo: Como Obter Aprovação para Gemma 3N")
    print("=" * 60)
    
    print("\n📋 OPÇÕES DISPONÍVEIS:")
    print("1. Hugging Face (Recomendado)")
    print("2. Kaggle (Alternativa)")
    print("3. Ambos (Máxima compatibilidade)")

def huggingface_approval_steps():
    """Passos para aprovação no Hugging Face"""
    print("\n🤗 APROVAÇÃO NO HUGGING FACE")
    print("=" * 40)
    
    steps = [
        {
            "step": 1,
            "title": "Criar/Verificar Conta Hugging Face",
            "actions": [
                "Acesse: https://huggingface.co/join",
                "Crie uma conta ou faça login",
                "Verifique seu email se necessário"
            ],
            "url": "https://huggingface.co/join"
        },
        {
            "step": 2,
            "title": "Acessar Página do Modelo Gemma 3N",
            "actions": [
                "Visite: https://huggingface.co/google/gemma-3n-E4B",
                "Leia a descrição do modelo",
                "Verifique os requisitos de uso"
            ],
            "url": "https://huggingface.co/google/gemma-3n-E4B"
        },
        {
            "step": 3,
            "title": "Solicitar Acesso",
            "actions": [
                "Clique no botão 'Request access'",
                "Preencha o formulário de solicitação",
                "Descreva seu caso de uso (pesquisa/desenvolvimento)",
                "Aguarde aprovação (geralmente 1-7 dias)"
            ],
            "url": "https://huggingface.co/google/gemma-3n-E4B"
        },
        {
            "step": 4,
            "title": "Configurar Token de Acesso",
            "actions": [
                "Vá para: https://huggingface.co/settings/tokens",
                "Crie um novo token (se não tiver)",
                "Copie o token gerado",
                "Configure na aplicação"
            ],
            "url": "https://huggingface.co/settings/tokens"
        }
    ]
    
    for step_info in steps:
        print(f"\n📌 PASSO {step_info['step']}: {step_info['title']}")
        print("-" * 30)
        for action in step_info['actions']:
            print(f"   • {action}")
        
        if 'url' in step_info:
            choice = input(f"\n   Abrir URL agora? (y/n): ").lower().strip()
            if choice in ['y', 'yes', 'sim']:
                try:
                    webbrowser.open(step_info['url'])
                    print(f"   🌐 Abrindo: {step_info['url']}")
                    time.sleep(2)
                except:
                    print(f"   ⚠️  Não foi possível abrir automaticamente")
                    print(f"   📋 Copie manualmente: {step_info['url']}")

def kaggle_approval_steps():
    """Passos para aprovação no Kaggle"""
    print("\n🏆 APROVAÇÃO NO KAGGLE")
    print("=" * 30)
    
    steps = [
        {
            "step": 1,
            "title": "Criar/Verificar Conta Kaggle",
            "actions": [
                "Acesse: https://www.kaggle.com/account/login",
                "Crie uma conta ou faça login",
                "Verifique seu número de telefone (obrigatório)"
            ],
            "url": "https://www.kaggle.com/account/login"
        },
        {
            "step": 2,
            "title": "Acessar Gemma 3N no Kaggle",
            "actions": [
                "Visite: https://www.kaggle.com/models/google/gemma-3n",
                "Leia os termos de uso",
                "Verifique a documentação"
            ],
            "url": "https://www.kaggle.com/models/google/gemma-3n"
        },
        {
            "step": 3,
            "title": "Aceitar Termos de Uso",
            "actions": [
                "Clique em 'Accept Terms'",
                "Leia e aceite os termos do Google",
                "Confirme seu caso de uso",
                "Acesso geralmente liberado imediatamente"
            ],
            "url": "https://www.kaggle.com/models/google/gemma-3n"
        },
        {
            "step": 4,
            "title": "Configurar API Token",
            "actions": [
                "Vá para: https://www.kaggle.com/settings/account",
                "Seção 'API' -> 'Create New Token'",
                "Baixe o arquivo kaggle.json",
                "Configure na aplicação"
            ],
            "url": "https://www.kaggle.com/settings/account"
        }
    ]
    
    for step_info in steps:
        print(f"\n📌 PASSO {step_info['step']}: {step_info['title']}")
        print("-" * 30)
        for action in step_info['actions']:
            print(f"   • {action}")
        
        if 'url' in step_info:
            choice = input(f"\n   Abrir URL agora? (y/n): ").lower().strip()
            if choice in ['y', 'yes', 'sim']:
                try:
                    webbrowser.open(step_info['url'])
                    print(f"   🌐 Abrindo: {step_info['url']}")
                    time.sleep(2)
                except:
                    print(f"   ⚠️  Não foi possível abrir automaticamente")
                    print(f"   📋 Copie manualmente: {step_info['url']}")

def configure_huggingface_token():
    """Configura token do Hugging Face"""
    print("\n🔑 CONFIGURAR TOKEN HUGGING FACE")
    print("=" * 40)
    
    print("Opções para configurar o token:")
    print("1. Configuração automática (recomendado)")
    print("2. Configuração manual")
    print("3. Variável de ambiente")
    
    choice = input("\nEscolha (1-3): ").strip()
    
    if choice == "1":
        try:
            from huggingface_hub import login
            print("\n🌐 Abrindo login do Hugging Face...")
            login()
            print("✅ Token configurado com sucesso!")
            return True
        except Exception as e:
            print(f"❌ Erro: {e}")
            return False
    
    elif choice == "2":
        token = input("\n🔑 Cole seu token do Hugging Face: ").strip()
        if token:
            try:
                from huggingface_hub import login
                login(token=token)
                print("✅ Token configurado com sucesso!")
                return True
            except Exception as e:
                print(f"❌ Erro: {e}")
                return False
        else:
            print("❌ Token não fornecido")
            return False
    
    elif choice == "3":
        print("\n📝 Configuração via variável de ambiente:")
        print("1. Crie um arquivo .env na raiz do projeto")
        print("2. Adicione: HUGGINGFACE_TOKEN=seu_token_aqui")
        print("3. Ou execute: export HUGGINGFACE_TOKEN=seu_token")
        
        # Criar arquivo .env
        token = input("\n🔑 Cole seu token (ou Enter para pular): ").strip()
        if token:
            with open(".env", "w") as f:
                f.write(f"HUGGINGFACE_TOKEN={token}\n")
            print("✅ Token salvo em .env")
            return True
        else:
            print("⚠️  Token não configurado")
            return False
    
    return False

def configure_kaggle_token():
    """Configura token do Kaggle"""
    print("\n🏆 CONFIGURAR TOKEN KAGGLE")
    print("=" * 30)
    
    print("Para usar modelos do Kaggle:")
    print("1. Baixe kaggle.json das configurações da conta")
    print("2. Coloque em ~/.kaggle/kaggle.json (Linux/Mac)")
    print("3. Ou em C:\\Users\\{username}\\.kaggle\\kaggle.json (Windows)")
    
    choice = input("\nJá baixou o kaggle.json? (y/n): ").lower().strip()
    
    if choice in ['y', 'yes', 'sim']:
        kaggle_path = Path.home() / ".kaggle"
        kaggle_path.mkdir(exist_ok=True)
        
        print(f"\n📁 Coloque o arquivo kaggle.json em: {kaggle_path}")
        print("   Ou configure manualmente:")
        
        username = input("   Username Kaggle (ou Enter para pular): ").strip()
        key = input("   API Key (ou Enter para pular): ").strip()
        
        if username and key:
            kaggle_config = {
                "username": username,
                "key": key
            }
            
            import json
            with open(kaggle_path / "kaggle.json", "w") as f:
                json.dump(kaggle_config, f)
            
            # Definir permissões no Linux/Mac
            try:
                import os
                os.chmod(kaggle_path / "kaggle.json", 0o600)
            except:
                pass
            
            print("✅ Configuração Kaggle salva!")
            return True
    
    print("⚠️  Configure manualmente o kaggle.json")
    return False

def test_access():
    """Testa acesso aos modelos"""
    print("\n🧪 TESTAR ACESSO AOS MODELOS")
    print("=" * 35)
    
    # Testar Hugging Face
    print("🤗 Testando Hugging Face...")
    try:
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained("google/gemma-3n-E4B")
        print("✅ Hugging Face: Acesso liberado!")
        hf_success = True
    except Exception as e:
        print(f"❌ Hugging Face: {str(e)[:100]}...")
        hf_success = False
    
    # Testar Kaggle (se disponível)
    print("\n🏆 Testando Kaggle...")
    try:
        import kaggle
        # Tentar listar modelos (teste básico)
        print("✅ Kaggle: API configurada!")
        kaggle_success = True
    except Exception as e:
        print(f"❌ Kaggle: {str(e)[:100]}...")
        kaggle_success = False
    
    return hf_success, kaggle_success

def create_approval_checklist():
    """Cria checklist de aprovação"""
    checklist = """
# ✅ Checklist de Aprovação Gemma 3N

## 🤗 Hugging Face
- [ ] Conta criada/verificada
- [ ] Acesso solicitado em: https://huggingface.co/google/gemma-3n-E4B
- [ ] Token de acesso criado
- [ ] Token configurado na aplicação
- [ ] Teste de acesso realizado

## 🏆 Kaggle (Alternativa)
- [ ] Conta criada/verificada
- [ ] Telefone verificado
- [ ] Termos aceitos em: https://www.kaggle.com/models/google/gemma-3n
- [ ] API token baixado (kaggle.json)
- [ ] Token configurado no sistema
- [ ] Teste de acesso realizado

## 🔧 Configuração da Aplicação
- [ ] Token configurado
- [ ] Modelo testado: python start_app.py --full
- [ ] Logs verificados (sem erros de acesso)
- [ ] Sistema funcionando com Gemma 3N

## 📞 Suporte
Se tiver problemas:
- Hugging Face: https://huggingface.co/support
- Kaggle: https://www.kaggle.com/contact
- Documentação Gemma: https://ai.google.dev/gemma

## ⏱️ Tempo Esperado
- Hugging Face: 1-7 dias úteis
- Kaggle: Imediato (após verificação telefônica)
"""
    
    with open("gemma_approval_checklist.md", "w", encoding="utf-8") as f:
        f.write(checklist)
    
    print("📋 Checklist salvo em: gemma_approval_checklist.md")

def main():
    """Função principal"""
    print("🚀 Guia de Aprovação Gemma 3N - ATous Secure Network")
    print("=" * 60)
    
    show_approval_steps()
    
    choice = input("\nEscolha uma opção (1-3): ").strip()
    
    if choice == "1":
        huggingface_approval_steps()
        print("\n🔑 Configurar token agora?")
        if input("(y/n): ").lower().strip() in ['y', 'yes', 'sim']:
            configure_huggingface_token()
    
    elif choice == "2":
        kaggle_approval_steps()
        print("\n🔑 Configurar token agora?")
        if input("(y/n): ").lower().strip() in ['y', 'yes', 'sim']:
            configure_kaggle_token()
    
    elif choice == "3":
        print("\n🎯 Configurando ambas as plataformas...")
        huggingface_approval_steps()
        configure_huggingface_token()
        print("\n" + "="*40)
        kaggle_approval_steps()
        configure_kaggle_token()
    
    else:
        print("❌ Opção inválida")
    
    # Testar acesso
    print("\n🧪 Testar acesso agora?")
    if input("(y/n): ").lower().strip() in ['y', 'yes', 'sim']:
        test_access()
    
    # Criar checklist
    create_approval_checklist()
    
    print("\n🎉 Guia de aprovação concluído!")
    print("\n📋 Próximos passos:")
    print("1. Siga os passos mostrados acima")
    print("2. Aguarde aprovação (se necessário)")
    print("3. Configure o token na aplicação")
    print("4. Teste: python start_app.py --full")
    
    print("\n💡 Dicas importantes:")
    print("• Hugging Face: Mais comum, pode demorar alguns dias")
    print("• Kaggle: Mais rápido, mas requer verificação telefônica")
    print("• Use caso de uso legítimo (pesquisa/desenvolvimento)")
    print("• Mantenha tokens seguros e privados")

if __name__ == "__main__":
    main()