# Man-in-the-Middle-Detection-Lab
# Lab de Detecção de Man-in-the-Middle (MitM)

> **Plataforma:** TryHackMe  
> **Ferramentas:** Wireshark · Splunk (SPL)  
> **Técnicas analisadas:** ARP Spoofing · DNS Spoofing · SSL Stripping  
> **Objetivo:** Investigar um ataque MITM encadeado dentro de uma LAN corporativa, identificando evidências de interceptação de rede, redirecionamento de tráfego e captura de credenciais em texto puro.
---

## Cenário

Um alerta de monitoramento de rotina na **Acme Corp** revelou padrões de tráfego incomuns dentro da LAN corporativa. Ao longo de vários dias, um invasor interceptou silenciosamente as comunicações, redirecionou conexões e capturou credenciais de usuários.

O ataque foi executado em **três técnicas encadeadas:**

```
[1] ARP Spoofing     →  Interceptação de rede (posicionamento MITM)
[2] DNS Spoofing     →  Redirecionamento de tráfego para o atacante
[3] SSL Stripping    →  Rebaixamento HTTPS→HTTP e captura de credenciais
```

---

## O que é um Ataque MITM?

Um ataque Man-in-the-Middle ocorre quando um invasor se **posiciona secretamente entre dois pontos de comunicação legítimos** — como um usuário e um servidor — para interceptar, modificar ou redirecionar o tráfego, sem que nenhuma das partes perceba.

### Como funciona

```
NORMAL:
  [Usuário] ─────────────────────────► [Servidor]

MITM:
  [Usuário] ──► [Atacante intercepta] ──► [Servidor]
                      ↑
               Lê, modifica ou
               bloqueia o tráfego
```

### Etapas principais

**1. Interceptação:** O atacante se insere no fluxo de comunicação explorando vulnerabilidades em protocolos de rede (ARP, DNS, IP).

**2. Manipulação/Decriptação:** O atacante acessa ou modifica a comunicação — decriptando dados, injetando conteúdo malicioso ou capturando credenciais.

### Tipos comuns de MITM

| Tipo | Descrição |
|---|---|
| **Captura de pacotes** | Captura de dados não criptografados em redes Wi-Fi abertas |
| **Sequestro de sessão** | Roubo de tokens de sessão para se passar por usuários legítimos |
| **SSL Stripping** | Rebaixamento de HTTPS para HTTP para capturar dados em texto puro |
| **DNS Spoofing** | Redirecionamento de tráfego para domínios fraudulentos via respostas DNS falsas |
| **ARP Spoofing** | Envenenamento de cache ARP para interceptar tráfego de rede local |
| **Rogue AP** | Criação de ponto de acesso Wi-Fi falso para interceptar tráfego |

---

## MITM e a Cyber Kill Chain

O ataque MITM é uma técnica versátil que opera principalmente nas fases de **Exploração** e **Instalação** da Cyber Kill Chain.

```
[1] Reconhecimento    → Coleta de informações sobre a rede alvo
[2] Armamentização    → Preparação das ferramentas (arpspoof, dnsspoof, sslstrip)
[3] Entrega           → Posicionamento na rede local (acesso físico ou Wi-Fi)
[4] Exploração    ◄── MITM: Abusa das limitações de ARP e DNS (sem autenticação)
[5] Instalação    ◄── MITM: Canal de entrega de payloads maliciosos via HTTP injetado
[6] C2                → Canal de controle estabelecido
[7] Ações             → Exfiltração de credenciais, dados sensíveis
```

**Como técnica de exploração:** O MITM explora as limitações inerentes de confiança dos protocolos ARP e DNS — ambos sem autenticação nativa. Ao manipulá-los, o atacante intercepta o canal de comunicação e obtém o ponto de apoio inicial para espionagem ou manipulação ativa.

**Como vetor de instalação:** Uma vez na posição MITM, o atacante controla o fluxo de dados e pode injetar exploits de navegador, droppers de malware ou RATs em downloads legítimos não criptografados.

---

## Informações da Rede

| Papel | IP | MAC | Notas |
|---|---|---|---|
| **Gateway** | `192.168.10.1` | `02:aa:bb:cc:00:01` | Roteador legítimo |
| **Atacante** | `192.168.10.55` | `02:fe:fe:fe:55:55` | Identificado durante análise |
| **Vítima** | `192.168.10.10` | `02:aa:bb:14:b6:8b` | Identificado durante análise |
| **Domínio alvo** | `corp-login.acme-corp.local` | — | Portal corporativo |

---

## Fase 1 — ARP Spoofing

### Conceito

O **ARP (Address Resolution Protocol)** mapeia endereços IP para endereços MAC em uma rede local. Quando um dispositivo quer enviar dados para outro IP, ele pergunta via broadcast: *"Quem tem este IP?"* — e o dono responde com seu MAC.

**O problema:** ARP não possui autenticação. Qualquer dispositivo pode enviar respostas ARP não solicitadas (*Gratuitous ARP*), e os outros hosts confiarão nelas automaticamente.

### Como o atacante explora isso

```
Atacante envia:
  "192.168.10.1 está em 02:fe:fe:fe:55:55"  →  para a vítima
  "192.168.10.10 está em 02:fe:fe:fe:55:55" →  para o gateway

Resultado:
  Cache ARP da vítima: gateway → MAC do atacante  (ENVENENADO)
  Cache ARP do gateway: vítima → MAC do atacante  (ENVENENADO)

Todo tráfego entre vítima ↔ gateway passa agora pelo atacante.
```

### Indicadores de Ataque (IoAs)

- Múltiplos MACs reivindicando o mesmo IP (*duplicate address detected*)
- Alto volume de respostas ARP não solicitadas (*Gratuitous ARP*)
- Respostas ARP sem solicitações correspondentes (*who-has*)
- Volume anormal de pacotes ARP em intervalos curtos
- Mesmo IP do gateway sendo anunciado por MACs diferentes

---

### Wireshark — Análise do `network-traffic.pcap`

**Passo 1 — Isolar todo tráfego ARP**
```
arp
```
> Ponto de partida. Exibe todas as solicitações (`who-has`) e respostas (`is-at`). Permite observar o volume geral e identificar padrões repetitivos ou origens suspeitas.

---

**Passo 2 — Analisar apenas as solicitações ARP**
```
arp.opcode == 1
```
> `opcode == 1` são as *requests* — pacotes enviados em broadcast perguntando quem tem determinado IP. Um host enviando um volume anormal de requests para múltiplos IPs pode estar fazendo reconhecimento da rede.

<img width="1897" height="873" alt="image" src="https://github.com/user-attachments/assets/bafa2252-30bc-41fb-9b5c-f1af482c3327" />

---

**Passo 3 — Analisar apenas as respostas ARP**
```
arp.opcode == 2
```
> `opcode == 2` são as *replies* (`is-at`). ARP Spoofing se baseia em respostas — o atacante envia `is-at` não solicitados para envenenar os caches. Respostas sem requests anteriores visíveis são forte indicador de ataque.
<img width="1917" height="609" alt="image" src="https://github.com/user-attachments/assets/9cf57117-80ef-4441-a0dc-e7538718a12b" />

---

**Passo 4 — Filtrar Gratuitous ARPs**
```
arp.isgratuitous
```
> ARPs gratuitos são respostas que ninguém pediu — um host anunciando proativamente seu próprio mapeamento IP→MAC. Legítimos existem (ex: ao inicializar), mas um host enviando repetidamente ARPs gratuitos para múltiplos destinos está quase certamente realizando envenenamento de cache.
<img width="1247" height="494" alt="image" src="https://github.com/user-attachments/assets/1a3ca381-16f3-42cc-90bf-f2199799fd60" />

---

**Passo 5 — Examinar tráfego ARP associado ao gateway legítimo**
```
arp && arp.src.proto_ipv4 == 192.168.10.1 && eth.src == 02:aa:bb:cc:00:01
```
> Filtra apenas tráfego ARP onde a origem é o IP **e** o MAC legítimo do gateway. Serve como baseline — o que o gateway real anuncia.
<img width="1152" height="342" alt="image" src="https://github.com/user-attachments/assets/1cb0c916-3ed6-4baf-a9b5-57cc6e716ed3" />

---

**Passo 6 — Identificar respostas para o IP do gateway de qualquer MAC**
```
arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.10.1
```
> Este é o filtro crítico: mostra **todos** os pacotes que dizem `"192.168.10.1 está em [MAC X]"`. Se aparecer mais de um MAC diferente reivindicando o mesmo IP do gateway, o envenenamento está confirmado.
<img width="1073" height="576" alt="image" src="https://github.com/user-attachments/assets/b2a9510a-d006-42e8-9554-77359fb83ec9" />

---

**Passo 7 — Confirmar o MAC do atacante**
```
arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.10.1 && eth.src == 02:fe:fe:fe:55:55
```
> Após identificar o MAC suspeito no passo anterior, este filtro confirma a identidade do atacante — todos os pacotes onde `02:fe:fe:fe:55:55` está afirmando ser o gateway.
<img width="1110" height="561" alt="image" src="https://github.com/user-attachments/assets/1424aeb3-8382-4db4-a501-f103030d3a90" />


---

**Passo 8 — Verificar mapeamentos duplicados (confirmação final)**
```
arp.duplicate-address-detected || arp.duplicate-address-frame
```
> O próprio Wireshark sinaliza automaticamente quando detecta dois MACs diferentes reivindicando o mesmo IP. Este filtro exibe esses pacotes diretamente — é a confirmação técnica definitiva do ARP Spoofing.
<img width="1052" height="582" alt="image" src="https://github.com/user-attachments/assets/3a2b7d96-b9fc-409f-b8de-fe35de41f61a" />

---

### Findings — ARP Spoofing

| Indicador | Valor |
|---|---|
| Gateway legítimo | `192.168.10.1` → `02:aa:bb:cc:00:01` |
| MAC do atacante | `02:fe:fe:fe:55:55` |
| Pacotes ARP do gateway legítimo | 10 |
| Respostas ARP gratuitas para `192.168.10.1` | 2 |
| MACs únicos reivindicando `192.168.10.1` | 2 |
| Total de pacotes de ARP spoofing do atacante | 14 |
| Técnica confirmada | Gratuitous ARP + Duplicate Address Detected |

---

## Fase 2 — DNS Spoofing

### Conceito

O **DNS** funciona como a lista de contatos da internet: traduz nomes amigáveis (`corp-login.acme-corp.local`) em endereços IP. O **DNS Spoofing** (ou envenenamento de cache DNS) ocorre quando um atacante já posicionado na rede intercepta a consulta DNS da vítima e responde com um IP falso — o seu próprio — antes que o servidor legítimo responda.

### Como o ataque se encadeia

```
[1] Vítima consulta: "Qual é o IP de corp-login.acme-corp.local?"
[2] Atacante (já na posição MITM via ARP) intercepta a consulta DNS
[3] Atacante responde PRIMEIRO com IP falso: "É 192.168.10.55"
[4] Vítima confia na resposta e salva em cache
[5] Vítima se conecta ao servidor do atacante pensando ser o legítimo
```

O atacante usa **TTL baixo** (1–30 segundos) para manter o envenenamento ativo e reafirmar o controle continuamente.

### Indicadores de Ataque (IoAs)

- Múltiplas respostas DNS para a mesma consulta (legítima + falsificada)
- Resposta DNS originada de IP diferente do servidor DNS configurado (`8.8.8.8`)
- TTL suspeito (muito baixo: 1–30 segundos)
- Resposta DNS não solicitada — aparece sem request correspondente da vítima
- IP retornado aponta para endereço interno desconhecido

---

### Wireshark — Análise do `network-traffic.pcap`

**Passo 1 — Isolar todo tráfego DNS**
```
dns
```
> Exibe todas as consultas e respostas DNS. Permite observar o volume total, os domínios consultados e as origens das respostas.

---

**Passo 2 — Examinar respostas do servidor DNS legítimo (baseline)**
```
dns.flags.response == 1 && ip.src == 8.8.8.8
```
> Isola apenas as respostas vindas do servidor DNS legítimo (`8.8.8.8`). Serve como baseline para entender como respostas normais se parecem — IPs externos conhecidos, TTLs razoáveis, um único respondente por consulta.
<img width="1450" height="477" alt="image" src="https://github.com/user-attachments/assets/f022eeb1-afcc-4039-b80a-8f5dcd341653" />

---

**Passo 3 — Ver todas as respostas DNS (identificar anomalias)**
```
dns.flags.response == 1
```
> Com o baseline em mente, este filtro mais amplo permite identificar respostas vindas de IPs **diferentes** de `8.8.8.8` — um host interno respondendo DNS é imediatamente suspeito.
<img width="1421" height="492" alt="image" src="https://github.com/user-attachments/assets/a1d82ee6-265d-4fec-99ae-9e9b7a478265" />

---

**Passo 4 — Focar no domínio alvo**
```
dns && dns.qry.name == "corp-login.acme-corp.local"
```
> Isola todo tráfego DNS relacionado ao domínio corporativo de interesse. Permite ver quem está consultando, com que frequência, e quem está respondendo.

---

**Passo 5 — Confirmar respostas legítimas para o domínio**
```
dns.flags.response == 1 && ip.src == 8.8.8.8 && dns.qry.name == "corp-login.acme-corp.local"
```
> Mostra apenas respostas legítimas do servidor DNS para o domínio alvo. Confirma o IP real do servidor (`93.184.216.34` ou similar) que serve como referência para comparação.
<img width="1428" height="492" alt="image" src="https://github.com/user-attachments/assets/d77cd95d-f386-48f5-8a1d-905a403d2588" />

---

**Passo 6 — Detectar respostas falsificadas (confirmação do ataque)**
```
dns.flags.response == 1 && ip.src != 8.8.8.8 && dns.qry.name == "corp-login.acme-corp.local"
```
> Este é o filtro definitivo. O operador `!=` exclui o servidor DNS legítimo e expõe qualquer host **dentro da rede** respondendo DNS para o domínio alvo. Um host interno respondendo DNS é um servidor DNS não autorizado — confirmação direta do DNS Spoofing.
<img width="1503" height="260" alt="image" src="https://github.com/user-attachments/assets/c77f4d79-ce7b-43a8-b7c9-95aa5980cd97" />

---

### Findings — DNS Spoofing

| Indicador | Valor |
|---|---|
| Domínio alvo | `corp-login.acme-corp.local` |
| Total de respostas DNS para o domínio | 211 |
| Respostas de IPs diferentes de `8.8.8.8` | 2 |
| IP retornado pela resposta falsificada | `192.168.10.55` (IP do atacante) |
| IP real do servidor legítimo | `93.184.216.34` |
| Técnica confirmada | DNS Spoofing via servidor DNS não autorizado interno |

---

##  Fase 3 — SSL Stripping

### Conceito

O **SSL Stripping** é a fase final do ataque. Após o atacante ter:
1. Se posicionado via ARP Spoofing
2. Redirecionado a vítima via DNS Spoofing

...a vítima tenta se conectar ao servidor corporativo via **HTTPS**. O atacante intercepta essa conexão e a **rebaixa para HTTP**, mantendo ele mesmo uma sessão HTTPS com o servidor real — enquanto a vítima se comunica sem criptografia.

### Como funciona

```
O que a vítima pensa que acontece:
  Vítima ──[HTTPS]──► Servidor legítimo

O que realmente acontece:
  Vítima ──[HTTP]──► Atacante ──[HTTPS]──► Servidor legítimo
           ↑ sem criptografia     ↑ criptografado
           credenciais visíveis   atacante lê tudo
```

### Indicadores de Ataque (IoAs)

- Cliente inicia com HTTPS (porta 443) mas tráfego subsequente muda para HTTP (porta 80) para o mesmo domínio
- Ausência de handshake TLS entre a vítima e o servidor após redirecionamento DNS
- Requisição HTTP POST para `/login` de um domínio que normalmente usa HTTPS
- Credenciais visíveis em texto puro no tráfego HTTP
- Redirecionamentos 301/302 empurrando HTTPS para HTTP

---

### Wireshark — Análise do `network-traffic.pcap`

**Passo 1 — Isolar todo tráfego TLS/SSL**
```
tls || ssl
```
> Exibe todos os handshakes TLS e sessões criptografadas. Permite identificar quais hosts estão se comunicando de forma segura com o servidor corporativo.

---

**Passo 2 — Confirmar que o domínio normalmente usa TLS**
```
tls.handshake.type == 1 && tls.handshake.extensions_server_name == "corp-login.acme-corp.local"
```
> `handshake.type == 1` são os *Client Hello* — a primeira mensagem de um handshake TLS. Este filtro confirma que o domínio `corp-login.acme-corp.local` **normalmente opera com TLS**, estabelecendo o baseline para comparação. Se a vítima não aparece mais fazendo Client Hello após o DNS Spoofing, o stripping foi efetivo.
<img width="1496" height="576" alt="image" src="https://github.com/user-attachments/assets/62f20fb2-4cb1-42db-bb43-c00d3ba71301" />

---

**Passo 3 — Confirmar o redirecionamento DNS que precede o stripping**
```
dns.flags.response == 1 && ip.src == 192.168.10.55 && dns.qry.name == "corp-login.acme-corp.local"
```
> Isola as respostas DNS falsificadas do atacante para o domínio alvo. Confirma que a vítima foi direcionada para `192.168.10.55` (atacante) em vez do servidor real — este é o pré-requisito do SSL Stripping.
<img width="1462" height="232" alt="image" src="https://github.com/user-attachments/assets/1123f37c-d59a-4937-8f50-d6c746ca099a" />

---

**Passo 4 — Confirmar a conexão HTTP após o stripping (evidência do ataque)**
```
http && ip.src == 192.168.10.10 && ip.dst == 192.168.10.55
```
> Este é o filtro mais impactante da investigação. Mostra a vítima (`192.168.10.10`) se comunicando com o atacante (`192.168.10.55`) via **HTTP puro** — sem criptografia. Se o domínio normalmente usa HTTPS e agora a vítima está enviando HTTP para um IP interno, o SSL Stripping foi bem-sucedido.
<img width="1652" height="775" alt="image" src="https://github.com/user-attachments/assets/3930f4ef-c857-48ef-898f-405de64a9446" />

> **Follow → HTTP Stream** no pacote POST para visualizar as credenciais capturadas em texto puro.

---

### Findings — SSL Stripping

| Indicador | Valor |
|---|---|
| Vítima | `192.168.10.10` |
| Atacante | `192.168.10.55` |
| Protocolo esperado | HTTPS (porta 443) |
| Protocolo observado | HTTP (porta 80) |
| URI alvo | `/login` |
| Credenciais capturadas | `username=alice` / `password=Secret123!` (texto puro) |
| Técnica confirmada | SSL Stripping — HTTPS rebaixado para HTTP via posição MITM |

---

## Cronologia do Ataque

```
DIA 1-2 — FASE 1: ARP Spoofing
  └── Atacante (02:fe:fe:fe:55:55) começa a enviar Gratuitous ARPs
  └── Cache ARP da vítima envenenado: gateway → MAC do atacante
  └── Todo tráfego da vítima passa pelo atacante (posição MITM estabelecida)

DIA 3+ — FASE 2: DNS Spoofing
  └── Atacante intercepta consultas DNS da vítima para corp-login.acme-corp.local
  └── Responde com IP falso: 192.168.10.55 (próprio IP)
  └── Vítima salva em cache: corp-login.acme-corp.local → 192.168.10.55

FASE 3: SSL Stripping + Captura de Credenciais
  └── Vítima tenta acessar o portal via HTTPS
  └── Atacante intercepta e retransmite via HTTP para a vítima
  └── Vítima faz login sem saber via HTTP
  └── Atacante captura: username=alice / password=Secret123!
```

---

## Resumo — IoAs por Técnica

| Técnica | Principal IoA | Filtro Wireshark Chave |
|---|---|---|
| **ARP Spoofing** | Duplicate address detected — dois MACs para o mesmo IP | `arp.duplicate-address-detected \|\| arp.duplicate-address-frame` |
| **DNS Spoofing** | Resposta DNS de IP diferente do servidor configurado | `dns.flags.response == 1 && ip.src != 8.8.8.8` |
| **SSL Stripping** | HTTP POST para domínio que normalmente usa HTTPS | `http && ip.src == [vítima] && ip.dst == [atacante]` |

---

## Referências MITRE ATT&CK

| Técnica | ID | Descrição |
|---|---|---|
| ARP Cache Poisoning | [T1557.002](https://attack.mitre.org/techniques/T1557/002/) | Envenenamento de cache ARP para posicionamento MITM |
| DNS Spoofing | [T1557.003](https://attack.mitre.org/techniques/T1557/003/) | Falsificação de respostas DNS para redirecionamento |
| Adversary-in-the-Middle | [T1557](https://attack.mitre.org/techniques/T1557/) | Posicionamento entre comunicações legítimas |
| Network Sniffing | [T1040](https://attack.mitre.org/techniques/T1040/) | Captura de tráfego de rede para obter credenciais |
| Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | Captura de credenciais via SSL Stripping |

---

## Stack Utilizada

| Ferramenta | Uso |
|---|---|
| **Wireshark** | Análise do PCAP `network-traffic.pcap` (ARP, DNS, TLS, HTTP) |
| **Splunk (SPL)** | Correlação de logs — `index=network_logs` |
| **TryHackMe** | Ambiente de laboratório controlado (Acme Corp scenario) |

---

*Documentado por Nicolas Farias — SOC Analyst | Cybersecurity Research & SOC Labs*
