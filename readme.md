# CTF Recon Suite 🛡️

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Contributors](https://img.shields.io/github/contributors/Guilhermemury/ctfhero)](https://github.com/Guilhermemury/ctfhero/graphs/contributors)

CTF Recon Suite é um framework de automação otimizado para desafios CTF e testes de penetração. Foca em tarefas essenciais de reconhecimento com uma abordagem simplificada, sendo perfeito tanto para iniciantes quanto para profissionais experientes em segurança.

## 🌟 Características

- **Escaneamento Inteligente de Portas**: Descoberta eficiente de portas com nmap
- **Análise de Serviços Web**: Detecção automatizada de tecnologias web e enumeração de diretórios
- **Gerenciamento de Hosts**: Modificação temporária e segura do arquivo /etc/hosts
- **Avaliação de Vulnerabilidades**: Busca automatizada por exploits conhecidos
- **Saída Padronizada**: Relatórios limpos e organizados com Rich
- **Performance Otimizada**: Uso inteligente de recursos e gerenciamento de timeout
- **Modo Rápido**: Opção para escaneamento mais rápido e menos detalhado

## 📋 Pré-requisitos

- Python 3.8 ou superior
- Sistema Linux/Unix
- Privilégios de root (para algumas operações)
- Ferramentas necessárias:
  - nmap
  - ffuf
  - whatweb
  - curl
  - searchsploit

## 🚀 Instalação

1. Clone o repositório:
```bash
git clone https://github.com/Guilhermemury/ctfhero.git
cd ctfhero
```

2. Instale as dependências Python:
```bash
pip install -r requirements.txt
```

3. Instale os pacotes do sistema necessários:
```bash
sudo apt update
sudo apt install -y nmap ffuf whatweb curl exploitdb
```

4. Torne o script executável:
```bash
chmod +x ctf-hero2.py
```

## 💻 Uso

Uso básico:
```bash
sudo ./ctf-hero2.py <target_ip>
```

Opções avançadas:
```bash
sudo ./ctf-hero2.py <target_ip> [opções]

Opções básicas:
  -n HOSTNAME, --hostname HOSTNAME
                      Nome de host personalizado para usar (ex: 'precious.htb')
  -q, --quick         Modo rápido - mais rápido mas menos detalhado
  -o OUTPUT, --output OUTPUT
                      Diretório de saída (padrão: output)

Opções de performance:
  -t THREADS, --threads THREADS
                      Máximo de threads paralelas (padrão: 4)
  --ffuf-threads THREADS
                      Threads para ffuf (padrão: 40)
  --nmap-timing {0,1,2,3,4,5}
                      Template de timing do nmap 0-5 (padrão: 4)
  --no-cache          Desabilitar cache de comandos
  --aggressive         Usar configurações de escaneamento agressivas

Exemplos:
  # Modo rápido com configurações otimizadas
  sudo ./ctf-hero2.py 192.168.1.100 -q --nmap-timing 5

  # Modo agressivo com muitas threads
  sudo ./ctf-hero2.py 192.168.1.100 --aggressive -t 8 --ffuf-threads 80

  # Scan completo com cache desabilitado
  sudo ./ctf-hero2.py 192.168.1.100 --no-cache
```

## 📁 Estrutura do Projeto

```
ctfhero/
├── ctf-hero2.py          # Script principal
├── requirements.txt      # Dependências Python
├── LICENSE              # Licença MIT
├── CONTRIBUTING.md      # Guia de contribuição
└── tests/               # Arquivos de teste
    └── test_ctfhero.py  # Testes unitários
```

## ⚡ Otimizações de Performance

O CTF Recon Suite inclui várias otimizações para maximizar a velocidade e eficiência:

### 🚀 Execução Paralela
- **Threads configuráveis**: Execute múltiplas operações simultaneamente
- **Scan paralelo de portas**: Para alvos com muitas portas abertas
- **Operações independentes**: Web scanning e busca de exploits em paralelo

### 💾 Cache Inteligente
- **Cache de comandos**: Evita re-execução de comandos idênticos
- **Resultados persistentes**: Acelera scans subsequentes
- **Gerenciamento automático**: Cache é limpo automaticamente

### ⚙️ Configurações Otimizadas
- **Timing templates do nmap**: Configurações 0-5 para diferentes velocidades
- **Threads do ffuf**: Ajuste fino para enumeração de diretórios
- **Timeouts dinâmicos**: Baseados no modo de execução e conectividade
- **Rate limiting**: Evita sobrecarga do servidor alvo

### 📊 Modos de Execução
- **Modo Rápido (`-q`)**: Configurações agressivas para scans rápidos
- **Modo Agressivo (`--aggressive`)**: Máxima velocidade com mais recursos
- **Modo Normal**: Balanceamento entre velocidade e precisão

### 🎯 Dicas de Performance
```bash
# Para CTFs com tempo limitado
sudo ./ctf-hero2.py target -q --nmap-timing 5 --ffuf-threads 60

# Para redes locais rápidas
sudo ./ctf-hero2.py target --aggressive -t 6

# Para evitar detecção
sudo ./ctf-hero2.py target --nmap-timing 2 --ffuf-threads 20
```

## 📊 Estrutura de Saída

```
output/
├── scans/             # Resultados detalhados dos escaneamentos
    ├── nmap/         # Resultados dos escaneamentos nmap
    ├── ffuf/         # Resultados da enumeração de diretórios
    ├── whatweb/      # Detecção de tecnologias web
    └── exploits/     # Exploits potenciais encontrados
```

## 🤝 Contribuindo

Contribuições são bem-vindas! Sinta-se à vontade para enviar um Pull Request. Para mudanças maiores, abra uma issue primeiro para discutir o que você gostaria de mudar.

1. Faça um fork do repositório
2. Crie sua branch de feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📝 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## ⚠️ Aviso Legal

Esta ferramenta é apenas para fins educacionais e testes de segurança autorizados. Sempre garanta que você tem permissão para testar o sistema alvo. Os autores não são responsáveis por qualquer uso indevido ou dano causado por este programa.

## 🙏 Agradecimentos

- Inspirado por vários desafios CTF e metodologias de teste de penetração
- Obrigado a todos os contribuidores e à comunidade de segurança
- Agradecimento especial aos desenvolvedores das ferramentas usadas neste projeto

## 📞 Contato

Guilherme Mury - [@kilserv](https://twitter.com/kilserv)

Link do Projeto: [https://github.com/Guilhermemury/ctfhero](https://github.com/Guilhermemury/ctfhero)
