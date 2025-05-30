# Máquina Enigma usando AES para Criptografia

## História

A Máquina Enigma foi uma ferramenta de criptografia utilizada principalmente durante a Segunda Guerra Mundial. 
Ela foi inventada pelo engenheiro alemão Arthur Scherbius no final da década de 1910 e usada extensivamente pelas forças militares alemãs. 
A Enigma permitia a substituição de letras em mensagens de forma complexa, usando uma combinação de rotores, um refletor e uma configuração de plugboard, tornando suas mensagens extremamente difíceis de decifrar. 
As mensagens cifradas pela Enigma eram consideradas quase impossíveis de serem quebradas, até que os esforços dos criptógrafos aliados, como Alan Turing e sua equipe em Bletchley Park, conseguiram decifrá-las, mudando o rumo da guerra.

Este código implementa uma versão simplificada da Máquina Enigma, complementada com criptografia AES moderna e outras melhorias de segurança para uma camada adicional de proteção e autenticidade da mensagem.

## Implementação e Configuração da Enigma

Nesta implementação:
- A parte da "Máquina Enigma" do código simula o comportamento de uma Enigma de 3 rotores.
- **Importante:** As configurações da Enigma (seleção de rotores, suas posições iniciais, a escolha do refletor e as conexões do plugboard) são todas **determinísticamente derivadas da senha fornecida pelo usuário**. Isso significa que a mesma senha sempre resultará na mesma configuração da Enigma, o que é crucial para a reprodutibilidade da criptografia e decriptografia. A derivação usa um hash SHA-256 da senha como semente para um gerador de números pseudoaleatórios, que então escolhe as configurações.

## How to Run

1.  **Instale a dependência de criptografia:**
    Este script requer a biblioteca `cryptography`. Você pode instalá-la usando pip:
    ```bash
    pip install cryptography
    ```

2.  **Execute o script:**
    Para rodar a máquina Enigma, use o seguinte comando:
    ```bash
    python enigma_machine_aesv2.py
    ```
    O script apresentará um menu para criptografar ou descriptografar mensagens.

## Security Enhancements

Esta versão da Máquina Enigma incorpora várias melhorias de segurança modernas sobre a Enigma original e implementações básicas de AES:

1.  **AES com Vetor de Inicialização (IV) Aleatório:**
    *   Para a criptografia AES, um Vetor de Inicialização (IV) de 16 bytes completamente aleatório é gerado para cada mensagem usando `os.urandom(16)`.
    *   Este IV é então **prependido** aos dados criptografados por AES (ciphertext). A estrutura parcial é `iv + aes_ciphertext`.
    *   O uso de um IV aleatório para cada criptografia garante que mensagens idênticas criptografadas com a mesma senha resultarão em ciphertexts diferentes, uma propriedade crucial para a segurança do AES em modos como o CFB (Cipher Feedback).

2.  **Derivação de Chave Baseada em Senha com PBKDF2:**
    *   A chave de criptografia AES e a chave HMAC não são usadas diretamente da senha. Em vez disso, elas são derivadas usando PBKDF2 (Password-Based Key Derivation Function 2) com o algoritmo HMAC-SHA256.
    *   Um `salt` criptográfico aleatório de 16 bytes (`os.urandom(16)`) é gerado para cada operação de criptografia. Este salt é **prependido** ao IV e ao ciphertext (antes do IV). A estrutura parcial é `salt + iv + aes_ciphertext`.
    *   PBKDF2 aumenta significativamente a resistência contra ataques de força bruta e de dicionário na senha, esticando a chave através de muitas iterações (100.000 neste caso). O salt garante que chaves derivadas sejam únicas mesmo para senhas idênticas e protege contra ataques de tabelas pré-calculadas (rainbow tables). São derivados 64 bytes de material chave: os primeiros 32 bytes para a chave AES-256 e os próximos 32 bytes para a chave HMAC-SHA256.

3.  **Autenticação de Mensagem com HMAC (Encrypt-then-MAC):**
    *   Para garantir a integridade (a mensagem não foi alterada) e a autenticidade (a mensagem origina-se de alguém com a senha correta), um Código de Autenticação de Mensagem baseado em Hash (HMAC) é utilizado.
    *   Especificamente, HMAC-SHA256 é calculado sobre o `salt + iv + aes_ciphertext`.
    *   Este HMAC é então **anexado** ao final da mensagem. A estrutura final da mensagem antes da codificação Base64 é: `salt + iv + aes_ciphertext + hmac`.
    *   Durante a descriptografia, o HMAC é verificado primeiro. Se a verificação falhar, a mensagem é considerada adulterada ou a senha está incorreta, e o processo é interrompido. Isso segue o paradigma "Encrypt-then-MAC", que é geralmente recomendado para segurança. A comparação de HMACs é feita usando `hmac.compare_digest` para prevenir ataques de temporização.

Estas melhorias tornam a comunicação significativamente mais segura do que a Enigma original sozinha.
