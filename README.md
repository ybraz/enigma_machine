# Máquina Enigma v2.0 - Criptografia Moderna

Sistema de criptografia educacional baseado na histórica Máquina Enigma, modernizado com criptografia forte usando **AES-GCM (AEAD)**, **Argon2id** para derivação de chaves, e recursos avançados de segurança.

## Melhorias de Segurança Implementadas

### 1. AES-GCM (AEAD) com IV Aleatório
- **Substituído**: AES-CBC com IV derivado (inseguro)
- **Implementado**: AES-GCM com IV aleatório de 12 bytes por mensagem
- **Benefícios**:
  - Confidencialidade + Integridade em uma única operação
  - Autenticação da mensagem (detecta adulterações)
  - IV único e aleatório para cada operação

### 2. Argon2id para Derivação de Chaves
- **Substituído**: SHA-256 direto (vulnerável a força bruta)
- **Implementado**: Argon2id com parâmetros fortes:
  - Time cost: 3 iterações
  - Memory cost: 64 MB
  - Parallelism: 4 threads
  - Salt único de 32 bytes por mensagem
- **Benefícios**: Resistente a ataques GPU/ASIC

### 3. MD5 Completamente Removido
- **Removido**: Uso de MD5 para derivar IVs
- **Implementado**: `os.urandom()` para geração criptograficamente segura

### 4. Versionamento e Cabeçalho Autenticado
- **Cabeçalho estruturado** contendo:
  - Versão do formato
  - KDF utilizada (argon2id)
  - Parâmetros da KDF
  - Salt (32 bytes)
  - Config salt (16 bytes)
  - IV (12 bytes)
- **Autenticação**: Cabeçalho usado como AAD no AES-GCM
- **Compatibilidade**: Verificação de versão na descriptografia

### 5. Derivação de Configuração Não-Determinística
- **Salt de configuração** único por mensagem
- Mesma senha pode gerar configurações Enigma diferentes
- Evita ataques baseados em configurações conhecidas

### 6. Password Strength Meter
- Cálculo de entropia da senha
- Feedback visual sobre força da senha
- Avisos sobre senhas fracas
- Recomendações de melhoria

### 7. Esquema Híbrido (X25519 + AES-GCM)
- Geração de pares de chaves X25519
- ECDH para troca de chaves
- Permite criptografia sem senha compartilhada
- Chaves efêmeras para forward secrecy

### 8. Criptografia de Arquivos com Streaming
- Suporte a arquivos grandes
- Chunks de 64 KB
- Progress bar
- Cada chunk com IV único

### 9. CLI Robusta
- Subcomandos: `encrypt`, `decrypt`, `encrypt-file`, `decrypt-file`, `keygen`
- Modo interativo
- Modo linha de comando

### 10. Features Extras
- **Copy to clipboard**: Copia resultado automaticamente
- **Fingerprints**: Hash curto da configuração para verificação manual
- **Feedback de progresso**: Durante operações longas

## Instalação

```bash
# Clone o repositório
git clone <repo-url>
cd enigma_machine

# Crie um ambiente virtual
python3 -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate

# Instale as dependências
pip install -r requirements.txt
```

## Uso

### Modo Interativo

```bash
python enigma_machine_aesv2.py
```

Menu interativo com opções:
1. Criptografar mensagem
2. Descriptografar mensagem
3. Criptografar arquivo
4. Descriptografar arquivo

### Modo CLI

#### Criptografar Mensagem

```bash
# Com prompt interativo
python enigma_machine_aesv2.py encrypt

# Com mensagem inline
python enigma_machine_aesv2.py encrypt -m "Mensagem secreta"

# Salvar em arquivo
python enigma_machine_aesv2.py encrypt -m "Mensagem secreta" -o encrypted.txt
```

#### Descriptografar Mensagem

```bash
# De arquivo
python enigma_machine_aesv2.py decrypt -f encrypted.txt

# Inline
python enigma_machine_aesv2.py decrypt -m "AgIJYXJnb24yaWQfeyJ0..."
```

#### Criptografar Arquivo

```bash
python enigma_machine_aesv2.py encrypt-file -i document.pdf -o document.pdf.enc
```

#### Descriptografar Arquivo

```bash
python enigma_machine_aesv2.py decrypt-file -i document.pdf.enc -o document_decrypted.pdf
```

## Formato de Criptografia

### Cabeçalho

```
[version: 1 byte]
[kdf_name_len: 1 byte]
[kdf_name: variable]
[kdf_params_len: 2 bytes]
[kdf_params_json: variable]
[salt: 32 bytes]
[config_salt: 16 bytes]
[iv: 12 bytes]
```

### Corpo

```
[AES-GCM ciphertext + tag]
```

### AAD (Additional Authenticated Data)

O cabeçalho completo é usado como AAD, garantindo que qualquer adulteração seja detectada.

## Exemplos de Uso

### Exemplo 1: Mensagem Simples

```bash
$ python enigma_machine_aesv2.py encrypt -m "Hello, World!"
Digite a senha:
Força da senha: FORTE (entropia: 87.3 bits)
✓ Boa senha!
🔐 Iniciando criptografia...
🔑 Derivando chave criptográfica com Argon2id...
⚙️  Configurando Máquina Enigma...
🔍 Fingerprint da configuração: A3F2B8C1
🎰 Processando com Enigma...
🔒 Aplicando AES-GCM...

AgIJYXJnb24yaWQfeyJ0aW1lX2Nvc3QiOjMsIm1lbW9yeV9jb3N0Ijo2NTUzNi...

✅ Copiado para clipboard!
```

### Exemplo 2: Arquivo Grande

```bash
$ python enigma_machine_aesv2.py encrypt-file -i large_video.mp4 -o encrypted.bin
Digite a senha:
Força da senha: MUITO FORTE (entropia: 142.1 bits)
✓ Excelente senha!
📁 Criptografando arquivo: large_video.mp4
🔑 Derivando chave...
🔒 Criptografando...
Progresso: 100.0%
✅ Arquivo criptografado salvo em: encrypted.bin
```

## Segurança

### Threat Model

Este sistema é **educacional** e **experimental**. Para uso em produção:

- Use bibliotecas estabelecidas: **NaCl/libsodium**, **Age**, **GPG/PGP**
- Este código não foi auditado por especialistas em segurança
- Pode conter bugs de implementação

### Proteções Implementadas

- ✅ Confidencialidade (AES-GCM)
- ✅ Integridade (AES-GCM tag)
- ✅ Autenticação (AAD)
- ✅ Resistência a força bruta (Argon2id)
- ✅ IVs únicos (os.urandom)
- ✅ Salts únicos por mensagem
- ✅ Versionamento para compatibilidade futura
- ✅ Detecção de adulteração

### Limitações

- ⚠️ Código educacional, não auditado
- ⚠️ Enigma histórica é fraca; segurança vem do AES-GCM
- ⚠️ Sem proteção contra side-channel attacks
- ⚠️ Sem proteção contra keyloggers/malware
- ⚠️ Senhas fracas ainda são vulneráveis

## Parâmetros de Segurança

```python
ARGON2_TIME_COST = 3         # Iterações
ARGON2_MEMORY_COST = 65536   # 64 MB
ARGON2_PARALLELISM = 4       # Threads
ARGON2_HASH_LEN = 32         # 256 bits
SALT_LENGTH = 32             # 256 bits
IV_LENGTH = 12               # 96 bits (recomendado GCM)
CONFIG_SALT_LENGTH = 16      # 128 bits
```

Para aumentar segurança (mas mais lento):
- Aumente `ARGON2_TIME_COST` para 4-5
- Aumente `ARGON2_MEMORY_COST` para 131072 (128 MB)

## Desenvolvimento Futuro

Possíveis melhorias (PRs bem-vindos):

- [ ] TUI com curses (interface visual)
- [ ] Desktop notifications
- [ ] Suporte a YubiKey/hardware tokens
- [ ] Comando `hybrid-encrypt` usando X25519
- [ ] Testes unitários completos
- [ ] Benchmark de performance
- [ ] Auditoria de segurança

## Licença

MIT License - Use por sua conta e risco!

## Referências

- [NIST SP 800-38D (GCM)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [RFC 9106 (Argon2)](https://www.rfc-editor.org/rfc/rfc9106.html)
- [RFC 7748 (X25519)](https://www.rfc-editor.org/rfc/rfc7748)
- [Cryptography Library Docs](https://cryptography.io/)

## Histórico de Versões

### v2.0 (2025)
- ✅ AES-GCM com IV aleatório
- ✅ Argon2id para KDF
- ✅ MD5 removido
- ✅ Versionamento e cabeçalhos
- ✅ Password strength meter
- ✅ Esquema híbrido X25519
- ✅ Criptografia de arquivos
- ✅ CLI robusta
- ✅ Clipboard e fingerprints

### v1.0 (anterior)
- ⚠️ AES-CBC (inseguro)
- ⚠️ SHA-256 direto (fraco)
- ⚠️ MD5 para IV (quebrado)
- ⚠️ Sem versionamento

---

**AVISO**: Este projeto é para fins educacionais. Para aplicações críticas de segurança, use soluções estabelecidas e auditadas.
