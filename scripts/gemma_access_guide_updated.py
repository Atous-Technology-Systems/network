#!/usr/bin/env python3
"""
Guia atualizado para obter acesso aos modelos Gemma
Baseado na verificação real de que não há botão "Request Access"
"""

import webbrowser
import json

def explain_gemma_access_reality():
    """Explica a situação real do acesso aos modelos Gemma"""
    print("🔍 SITUAÇÃO REAL DOS MODELOS GEMMA")
    print("=" * 50)
    
    print("❌ PROBLEMA IDENTIFICADO:")
    print("   • Todos os modelos Gemma estão restritos")
    print("   • Não há botão 'Request Access' visível")
    print("   • Acesso controlado pelo Google")
    
    print("\n✅ SOLUÇÕES REAIS:")
    print("   1. Kaggle (mais fácil)")
    print("   2. Google AI Studio")
    print("   3. Hugging Face com aprovação especial")
    print("   4. Modelos alternativos")

def kaggle_solution():
    """Solução via Kaggle - mais fácil"""
    print("\n🏆 SOLUÇÃO 1: KAGGLE (RECOMENDADO)")
    print("=" * 40)
    
    print("✅ VANTAGENS:")
    print("   • Acesso mais fácil")
    print("   • Aprovação mais rápida")
    print("   • Interface amigável")
    
    print("\n📋 PASSOS:")
    print("1. Criar conta no Kaggle")
    print("2. Verificar telefone (obrigatório)")
    print("3. Aceitar termos dos modelos Gemma")
    print("4. Baixar via Kaggle API")
    
    print("\n🔗 LINKS IMPORTANTES:")
    kaggle_links = [
        "https://www.kaggle.com/account/login",
        "https://www.kaggle.com/models/google/gemma",
        "https://www.kaggle.com/models/google/gemma-2",
        "https://www.kaggle.com/models/google/gemma-3n"
    ]
    
    for link in kaggle_links:
        print(f"   • {link}")
    
    choice = input("\n🌐 Abrir links do Kaggle? (y/n): ").lower().strip()
    if choice in ['y', 'yes', 'sim']:
        for link in kaggle_links:
            try:
                webbrowser.open(link)
                print(f"   Abrindo: {link}")
            except:
                print(f"   ⚠️  Copie manualmente: {link}")

def google_ai_studio_solution():
    """Solução via Google AI Studio"""
    print("\n🤖 SOLUÇÃO 2: GOOGLE AI STUDIO")
    print("=" * 35)
    
    print("✅ VANTAGENS:")
    print("   • Acesso direto do Google")
    print("   • Interface web")
    print("   • API disponível")
    
    print("\n📋 PASSOS:")
    print("1. Acessar Google AI Studio")
    print("2. Fazer login com conta Google")
    print("3. Aceitar termos de uso")
    print("4. Obter API key")
    print("5. Usar via API")
    
    print("\n🔗 LINK:")
    ai_studio_url = "https://aistudio.google.com/"
    print(f"   • {ai_studio_url}")
    
    choice = input("\n🌐 Abrir Google AI Studio? (y/n): ").lower().strip()
    if choice in ['y', 'yes', 'sim']:
        try:
            webbrowser.open(ai_studio_url)
            print(f"   Abrindo: {ai_studio_url}")
        except:
            print(f"   ⚠️  Copie manualmente: {ai_studio_url}")

def huggingface_special_access():
    """Processo especial para Hugging Face"""
    print("\n🤗 SOLUÇÃO 3: HUGGING FACE (PROCESSO ESPECIAL)")
    print("=" * 50)
    
    print("⚠️  REALIDADE:")
    print("   • Não há botão 'Request Access' público")
    print("   • Acesso controlado por lista de aprovação")
    print("   • Processo não documentado publicamente")
    
    print("\n📧 POSSÍVEIS ABORDAGENS:")
    print("1. Contatar suporte do Hugging Face")
    print("2. Aplicar via formulário de pesquisa")
    print("3. Ter afiliação acadêmica/empresarial")
    
    print("\n🔗 CONTATOS:")
    contacts = [
        "https://huggingface.co/support",
        "https://huggingface.co/contact",
        "support@huggingface.co"
    ]
    
    for contact in contacts:
        print(f"   • {contact}")
    
    print("\n📝 TEMPLATE DE EMAIL:")
    email_template = """
Assunto: Request for Gemma Model Access - Research/Development Purpose

Dear Hugging Face Team,

I am requesting access to the Gemma models (specifically google/gemma-3n-E4B) 
for research and development purposes.

Project: ATous Secure Network - AI-powered cybersecurity system
Use case: Threat detection and behavioral analysis
Institution: [Your institution/company]
Purpose: [Academic research/Commercial development/Personal project]

I understand and agree to comply with Google's terms of use for Gemma models.

Thank you for your consideration.

Best regards,
[Your name]
[Your email]
[Your affiliation]
"""
    
    print(email_template)
    
    choice = input("\n📧 Abrir links de contato? (y/n): ").lower().strip()
    if choice in ['y', 'yes', 'sim']:
        for contact in contacts:
            if contact.startswith('http'):
                try:
                    webbrowser.open(contact)
                    print(f"   Abrindo: {contact}")
                except:
                    print(f"   ⚠️  Copie manualmente: {contact}")

def alternative_models_solution():
    """Modelos alternativos que funcionam"""
    print("\n🔄 SOLUÇÃO 4: MODELOS ALTERNATIVOS")
    print("=" * 40)
    
    print("✅ MODELOS PÚBLICOS SIMILARES:")
    alternatives = [
        {
            "name": "microsoft/DialoGPT-medium",
            "description": "Conversacional, boa qualidade",
            "size": "~1GB",
            "access": "Público"
        },
        {
            "name": "microsoft/DialoGPT-large", 
            "description": "Versão maior, melhor qualidade",
            "size": "~3GB",
            "access": "Público"
        },
        {
            "name": "distilgpt2",
            "description": "Pequeno e rápido",
            "size": "~300MB", 
            "access": "Público"
        },
        {
            "name": "gpt2",
            "description": "Clássico, confiável",
            "size": "~500MB",
            "access": "Público"
        }
    ]
    
    for i, model in enumerate(alternatives, 1):
        print(f"\n{i}. {model['name']}")
        print(f"   📝 {model['description']}")
        print(f"   💾 Tamanho: {model['size']}")
        print(f"   🔓 Acesso: {model['access']}")
    
    choice = input(f"\n🔧 Configurar um destes modelos? (1-{len(alternatives)}): ").strip()
    
    try:
        choice_idx = int(choice) - 1
        if 0 <= choice_idx < len(alternatives):
            selected = alternatives[choice_idx]
            configure_alternative_model(selected['name'])
            return selected['name']
    except:
        pass
    
    return None

def configure_alternative_model(model_name):
    """Configura modelo alternativo"""
    print(f"\n🔧 Configurando {model_name}...")
    
    config = {
        "model_name": model_name,
        "model_params": {
            "torch_dtype": "float32",
            "device_map": "auto",
            "low_cpu_mem_usage": True,
            "trust_remote_code": False
        },
        "pipeline_params": {
            "max_length": 256,
            "temperature": 0.7,
            "do_sample": True,
            "top_p": 0.9,
            "pad_token_id": 50256
        },
        "memory_size": 1000,
        "threat_threshold": 0.7,
        "simulation_mode": False
    }
    
    # Salvar configuração
    with open("alternative_model_config.json", "w") as f:
        json.dump(config, f, indent=2)
    
    print(f"✅ Configuração salva para {model_name}")
    
    # Atualizar arquivo principal
    update_main_file_with_alternative(model_name)

def update_main_file_with_alternative(model_name):
    """Atualiza arquivo principal com modelo alternativo"""
    from pathlib import Path
    
    main_file = Path("atous_sec_network/__main__.py")
    
    if main_file.exists():
        with open(main_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Substituir modelo
        content = content.replace('google/gemma-2-2b-it', model_name)
        content = content.replace('google/gemma-3n-E4B', model_name)
        
        with open(main_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"✅ Arquivo principal atualizado com {model_name}")

def create_comprehensive_guide():
    """Cria guia abrangente"""
    guide = """
# 🔓 Guia Completo: Como Acessar Modelos Gemma

## 🎯 SITUAÇÃO ATUAL
- ❌ Todos os modelos Gemma estão restritos no Hugging Face
- ❌ Não há botão "Request Access" público
- ✅ Existem alternativas viáveis

## 🏆 OPÇÃO 1: KAGGLE (MAIS FÁCIL)

### Passos:
1. **Criar conta**: https://www.kaggle.com/account/login
2. **Verificar telefone** (obrigatório)
3. **Acessar modelos**:
   - https://www.kaggle.com/models/google/gemma
   - https://www.kaggle.com/models/google/gemma-2
   - https://www.kaggle.com/models/google/gemma-3n
4. **Aceitar termos** de cada modelo
5. **Configurar API**: Baixar kaggle.json

### Vantagens:
- ✅ Processo mais simples
- ✅ Aprovação mais rápida
- ✅ Interface amigável

## 🤖 OPÇÃO 2: GOOGLE AI STUDIO

### Passos:
1. **Acessar**: https://aistudio.google.com/
2. **Login** com conta Google
3. **Aceitar termos** de uso
4. **Obter API key**
5. **Usar via API**

### Vantagens:
- ✅ Direto do Google
- ✅ Interface web
- ✅ API oficial

## 🤗 OPÇÃO 3: HUGGING FACE (DIFÍCIL)

### Realidade:
- ❌ Sem processo público
- ❌ Lista de aprovação restrita
- ⚠️  Requer contato direto

### Tentativas:
1. **Contatar suporte**: support@huggingface.co
2. **Formulário de pesquisa**
3. **Afiliação institucional**

## 🔄 OPÇÃO 4: MODELOS ALTERNATIVOS (RECOMENDADO)

### Modelos Públicos:
- ✅ microsoft/DialoGPT-medium
- ✅ microsoft/DialoGPT-large
- ✅ distilgpt2
- ✅ gpt2

### Vantagens:
- ✅ Acesso imediato
- ✅ Sem restrições
- ✅ Boa qualidade

## 🚀 RECOMENDAÇÃO FINAL

1. **Imediato**: Use modelo alternativo (DialoGPT-medium)
2. **Médio prazo**: Configure Kaggle para Gemma
3. **Longo prazo**: Tente Google AI Studio

## 📞 SUPORTE
- Kaggle: https://www.kaggle.com/contact
- Google AI: https://aistudio.google.com/
- Hugging Face: support@huggingface.co
"""
    
    with open("gemma_access_complete_guide.md", "w", encoding="utf-8") as f:
        f.write(guide)
    
    print("📄 Guia completo salvo em: gemma_access_complete_guide.md")

def main():
    """Função principal"""
    print("🔓 Guia Atualizado: Como Realmente Acessar Modelos Gemma")
    print("=" * 60)
    
    explain_gemma_access_reality()
    
    print("\n❓ Escolha sua abordagem:")
    print("1. Kaggle (mais fácil)")
    print("2. Google AI Studio")
    print("3. Hugging Face (processo especial)")
    print("4. Modelos alternativos (imediato)")
    print("5. Ver todas as opções")
    
    choice = input("\nEscolha (1-5): ").strip()
    
    if choice == "1":
        kaggle_solution()
    elif choice == "2":
        google_ai_studio_solution()
    elif choice == "3":
        huggingface_special_access()
    elif choice == "4":
        model_name = alternative_models_solution()
        if model_name:
            print(f"\n🎉 Modelo {model_name} configurado!")
            print("🚀 Teste com: python start_app.py --full")
    elif choice == "5":
        kaggle_solution()
        google_ai_studio_solution()
        huggingface_special_access()
        alternative_models_solution()
    else:
        print("❌ Opção inválida")
    
    create_comprehensive_guide()
    
    print("\n🎯 RESUMO DAS OPÇÕES:")
    print("   🏆 Kaggle: Mais fácil, requer verificação telefônica")
    print("   🤖 Google AI Studio: Direto do Google, via API")
    print("   🤗 Hugging Face: Difícil, sem processo público")
    print("   🔄 Alternativos: Imediato, boa qualidade")
    
    print("\n💡 RECOMENDAÇÃO:")
    print("   1. Use modelo alternativo AGORA")
    print("   2. Configure Kaggle em paralelo")
    print("   3. Teste Google AI Studio")

if __name__ == "__main__":
    main()