"""
Máquina Enigma usando AES para Criptografia

História:
A Máquina Enigma foi uma ferramenta de criptografia utilizada principalmente durante a Segunda Guerra Mundial. 
Ela foi inventada pelo engenheiro alemão Arthur Scherbius no final da década de 1910 e usada extensivamente pelas forças militares alemãs. 
A Enigma permitia a substituição de letras em mensagens de forma complexa, usando uma combinação de rotores, um refletor e uma configuração de plugboard, tornando suas mensagens extremamente difíceis de decifrar. 
As mensagens cifradas pela Enigma eram consideradas quase impossíveis de serem quebradas, até que os esforços dos criptógrafos aliados, como Alan Turing e sua equipe em Bletchley Park, conseguiram decifrá-las, mudando o rumo da guerra.

Este código implementa uma versão simplificada da Máquina Enigma, complementada com criptografia AES para uma camada adicional de segurança.
"""

import getpass
import hashlib
import base64
import random
import string
import time
import os
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Tentativa de importar winsound para feedback sonoro opcional no Windows
try:
    import winsound
    CAN_BEEP = True
except ImportError:
    CAN_BEEP = False

class EnigmaMachine:
    def __init__(self, rotors, reflector, plugboard):
        """
        Inicializa a Máquina Enigma com os rotores, refletor e plugboard fornecidos.

        Args:
            rotors (list): Lista de strings representando os mapeamentos dos rotores.
            reflector (str): String representando o mapeamento do refletor.
            plugboard (dict): Dicionário representando as conexões do plugboard.
        """
        self.rotors = rotors
        self.reflector = reflector
        self.plugboard = plugboard
        self.rotor_positions = [0] * len(rotors)

    def set_rotor_positions(self, positions):
        """
        Define as posições iniciais dos rotores.

        Args:
            positions (list): Lista de inteiros representando as posições iniciais dos rotores.
        """
        self.rotor_positions = positions

    def encrypt_character(self, char):
        """
        Criptografa um único caractere usando a lógica da Máquina Enigma.

        Args:
            char (str): Caractere a ser criptografado.

        Returns:
            str: Caractere criptografado.
        """
        if char in self.plugboard:
            char = self.plugboard[char]
        
        for i, rotor in enumerate(self.rotors):
            char = rotor[(ord(char) - 65 + self.rotor_positions[i]) % 26]
        
        char = self.reflector[(ord(char) - 65) % 26]
        
        for i, rotor in reversed(list(enumerate(self.rotors))):
            char = chr((rotor.index(char) - self.rotor_positions[i] + 26) % 26 + 65)
        
        if char in self.plugboard:
            char = self.plugboard[char]
        
        self.step_rotors()
        
        return char

    def step_rotors(self):
        """
        Avança a posição dos rotores, simulando o mecanismo de rotação da Máquina Enigma.
        """
        for i in range(len(self.rotors)):
            self.rotor_positions[i] = (self.rotor_positions[i] + 1) % 26
            if self.rotor_positions[i] != 0:
                break

    def encrypt_message(self, message):
        """
        Criptografa uma mensagem completa.

        Args:
            message (str): Mensagem a ser criptografada.

        Returns:
            str: Mensagem criptografada.
        """
        encrypted_message = ''
        for char in message:
            if char.isalpha():
                encrypted_message += self.encrypt_character(char.upper())
            else:
                encrypted_message += char
        return encrypted_message

def derive_configuration_from_password(password):
    """
    Deriva a configuração da Máquina Enigma a partir de uma senha.

    Args:
        password (str): Senha fornecida pelo usuário.

    Returns:
        tuple: Contém os rotores, refletor, plugboard, posições iniciais, ordem dos rotores e escolha do refletor.
    """
    hash_object = hashlib.sha256(password.encode())
    hex_dig = hash_object.hexdigest()
    
    rotor_wiring = {
        'I': 'EKMFLGDQVZNTOWYHXUSPAIBRCJ',
        'II': 'AJDKSIRUXBLHWTMCQGZNPYFVOE',
        'III': 'BDFHJLCPRTXVZNYEIWGAKMUSQO',
        'IV': 'ESOVPZJAYQUIRHXLNFTGKDCMWB',
        'V': 'VZBRGITYUPSDNHLXAWMJQOFECK'
    }

    reflectors = {
        'B': 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
        'C': 'FVPJIAOYEDRZXWGCTKUQSBNMHL'
    }

    all_rotors = list(rotor_wiring.keys())
    all_reflectors = list(reflectors.keys())

    # Usa a senha para derivar a seleção de rotores e posições iniciais
    random.seed(int(hex_dig, 16))
    rotor_order = random.sample(all_rotors, 3)
    initial_positions = [random.randint(0, 25) for _ in range(3)]
    reflector_choice = random.choice(all_reflectors)

    # Deriva pares do plugboard a partir da senha
    alphabet = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    random.shuffle(alphabet)
    plugboard_pairs = [(alphabet[i], alphabet[i + 1]) for i in range(0, 12, 2)]

    rotors = [rotor_wiring[rotor] for rotor in rotor_order]
    reflector = reflectors[reflector_choice]

    plugboard = {}
    for pair in plugboard_pairs:
        plugboard[pair[0]] = pair[1]
        plugboard[pair[1]] = pair[0]

    return rotors, reflector, plugboard, initial_positions, rotor_order, reflector_choice

def aes_encrypt_decrypt(text, key, iv, operation):
    """
    Realiza criptografia ou descriptografia AES em modo CFB.

    Args:
        text (bytes): Texto a ser criptografado ou descriptografado.
        key (bytes): Chave de criptografia.
        iv (bytes): Vetor de inicialização.
        operation (str): Operação a ser realizada ('encrypt' ou 'decrypt').

    Returns:
        bytes: Texto criptografado ou descriptografado.
    """
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor_decryptor = cipher.encryptor() if operation == 'encrypt' else cipher.decryptor()
    return encryptor_decryptor.update(text) + encryptor_decryptor.finalize()

def print_with_delay(message, delay=0.1):
    """
    Imprime uma mensagem caractere por caractere com um atraso entre eles.

    Args:
        message (str): Mensagem a ser impressa.
        delay (float): Atraso entre a impressão de cada caractere.
    """
    for char in message:
        print(char, end='', flush=True)
        time.sleep(delay)
        if CAN_BEEP:
            winsound.Beep(500, 100)  # Frequência de 500Hz, duração de 100ms
    print()

def clear_screen():
    """
    Limpa a tela do terminal.
    """
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    """
    Função principal que gerencia a interação do usuário com a Máquina Enigma.
    """
    clear_screen()
    print("""
    *******************************************************
    *                                                     *
    *               BEM-VINDO À MÁQUINA ENIGMA            *
    *                                                     *
    *******************************************************
    """)
    
    print("Escolha uma opção:")
    print("1. Criptografar")
    print("2. Descriptografar")
    option = input("Opção: ")

    if option == '1':
        message = input("Digite a mensagem (letras A-Z serão convertidas para maiúsculas; outros caracteres serão preservados): ").upper()
        password = getpass.getpass("Digite a senha: ")

        rotors, reflector, plugboard, initial_positions, rotor_order, reflector_choice = derive_configuration_from_password(password)

        enigma = EnigmaMachine(rotors, reflector, plugboard)
        enigma.set_rotor_positions(initial_positions)

        encrypted_message = enigma.encrypt_message(message)
        
        # --- Criptografia AES e HMAC ---
        # 1. Gerar um salt aleatório para PBKDF2
        salt = os.urandom(16) 
        
        # 2. Derivar chaves AES e HMAC da senha usando PBKDF2
        # Isso gera 64 bytes: 32 para a chave AES-256 e 32 para a chave HMAC-SHA256.
        # PBKDF2 ajuda a proteger contra ataques de força bruta na senha.
        derived_key = hashlib.pbkdf2_hmac(
            'sha256',             # Algoritmo hash
            password.encode(),    # Senha (bytes)
            salt,                 # Salt (bytes)
            100000,               # Iterações (quanto mais, mais seguro, porém mais lento)
            dklen=64              # Comprimento da chave derivada em bytes
        )
        aes_key = derived_key[:32]   # Primeiros 32 bytes para AES
        hmac_key = derived_key[32:]  # Próximos 32 bytes para HMAC

        # 3. Gerar um Vetor de Inicialização (IV) aleatório de 16 bytes para AES
        # O IV garante que a mesma mensagem criptografada várias vezes com a mesma chave
        # produza ciphertexts diferentes. Essencial para a segurança do AES.
        iv = os.urandom(16)
        
        # 4. Criptografar a mensagem (saída da Enigma) usando AES
        aes_encrypted_data = aes_encrypt_decrypt(encrypted_message.encode(), aes_key, iv, 'encrypt')
        
        # 5. Construir os dados para autenticação HMAC: salt + iv + aes_ciphertext
        # O HMAC protegerá a integridade e autenticidade desses três componentes.
        data_to_auth = salt + iv + aes_encrypted_data
        
        # 6. Calcular o HMAC tag sobre data_to_auth
        hmac_tag = hmac.new(hmac_key, data_to_auth, hashlib.sha256).digest()
        
        # 7. Concatenar tudo para a mensagem final: salt (16B) + iv (16B) + aes_ciphertext + hmac_tag (32B)
        final_encrypted_message = data_to_auth + hmac_tag
        
        clear_screen()
        print("""
        *******************************************************
        *                                                     *
        *                  MENSAGEM CRIPTOGRAFADA             *
        *                                                     *
        *******************************************************
        """)
        print_with_delay(base64.b64encode(final_encrypted_message).decode(), 0.2)
    elif option == '2':
        encrypted_message = input("Digite a mensagem criptografada: ")
        password = getpass.getpass("Digite a senha: ")

        encrypted_message_blob = base64.b64decode(encrypted_message) # Dados completos: salt + IV + ciphertext + HMAC
        
        # --- Descriptografia AES e Verificação HMAC ---
        # A estrutura esperada é: salt (16B) + iv (16B) + aes_ciphertext (?) + hmac_tag (32B)

        # 1. Extrair o HMAC recebido (últimos 32 bytes, assumindo HMAC-SHA256)
        received_hmac = encrypted_message_blob[-32:]
        # O restante é o que precisa ser verificado (salt + iv + ciphertext)
        data_to_verify = encrypted_message_blob[:-32]

        # 2. Extrair o salt (primeiros 16 bytes de data_to_verify)
        salt = data_to_verify[:16]
        # 3. Extrair o IV (próximos 16 bytes de data_to_verify)
        iv = data_to_verify[16:32]
        # O restante de data_to_verify é o ciphertext AES puro
        encrypted_data_for_aes = data_to_verify[32:]

        # 4. Re-derivar as chaves AES e HMAC usando PBKDF2 com o salt extraído
        # É crucial usar os mesmos parâmetros de PBKDF2 (hash, iterações, dklen) da criptografia.
        derived_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000,
            dklen=64
        )
        aes_key = derived_key[:32]
        hmac_key = derived_key[32:]

        # 5. Calcular o HMAC esperado sobre os dados extraídos (data_to_verify)
        # Isso recalcula o HMAC como se estivéssemos criptografando, para comparar com o recebido.
        calculated_hmac = hmac.new(hmac_key, data_to_verify, hashlib.sha256).digest()
        
        # 6. Verificar o HMAC
        # hmac.compare_digest é usado para prevenir ataques de temporização.
        if not hmac.compare_digest(calculated_hmac, received_hmac):
            print("\nErro: A mensagem está corrompida, foi adulterada ou a senha está incorreta. Verificação HMAC falhou.")
            # A configuração da Enigma é mostrada abaixo, mas pode ser incorreta se a senha estiver errada.
            print("\nConfiguração da Enigma (pode não ser relevante se a mensagem estiver corrompida ou a senha incorreta):")
            temp_rotors, temp_reflector, temp_plugboard, temp_initial_positions, temp_rotor_order, temp_reflector_choice = derive_configuration_from_password(password)
            print(f"Rotores: {temp_rotors}")
            print(f"Ordem dos Rotores: {temp_rotor_order}")
            print(f"Posições Iniciais: {temp_initial_positions}")
            print(f"Refletor: {temp_reflector_choice}")
            print(f"Plugboard: {temp_plugboard}")
            return # Interrompe o processamento se o HMAC for inválido

        # Se o HMAC for válido, prosseguir com a descriptografia e o processamento da Enigma
        rotors, reflector, plugboard, initial_positions, rotor_order, reflector_choice = derive_configuration_from_password(password)
        
        try:
            # 7. Descriptografar os dados AES
            decrypted_bytes = aes_encrypt_decrypt(encrypted_data_for_aes, aes_key, iv, 'decrypt')
            decrypted_message = decrypted_bytes.decode('utf-8')
            
            enigma = EnigmaMachine(rotors, reflector, plugboard)
            enigma.set_rotor_positions(initial_positions)
            final_decrypted_message = enigma.encrypt_message(decrypted_message)
            
            clear_screen()
            print("""
            *******************************************************
            *                                                     *
            *                MENSAGEM DESCRIPTOGRAFADA            *
            *                                                     *
            *******************************************************
            """)
            print_with_delay(final_decrypted_message, 0.2)
        except UnicodeDecodeError:
            print("\nErro: A senha fornecida está incorreta ou a mensagem está corrompida. Não foi possível decodificar os dados da Enigma.")
    else:
        print("Opção inválida!")

    # Exibe a configuração da Enigma derivada da senha.
    # Nota: Se a descriptografia falhou devido à senha incorreta, esta configuração também será baseada nessa senha incorreta.
    # Em caso de falha de HMAC, esta seção é alcançada após a mensagem de erro HMAC e o 'return'.
    # Se a descriptografia for bem-sucedida, 'rotors', etc., são definidos corretamente.
    # Se a opção for inválida, 'rotors' etc. não serão definidos, causando um erro se tentarmos imprimi-los aqui sem um 'else' que os defina ou saia.
    # Para simplificar, vamos garantir que só imprimimos se 'rotors' foi definido, o que acontece nos caminhos '1' e '2' (após o HMAC check no '2').
    if option in ['1', '2']: # Apenas imprime se a configuração foi derivada.
        # No caso de falha de HMAC, 'rotors' etc. não são redefinidos no escopo de main() antes do return,
        # então esta impressão não ocorreria nesse caso específico, o que é bom.
        # No entanto, se a falha for UnicodeDecodeError, 'rotors' etc. *foram* definidos.
        # E se a opção for '1', também são definidos.
        # O 'return' na falha de HMAC impede que esta seção seja impressa para esse erro específico.
        # Se o HMAC passar, mas UnicodeDecodeError ocorrer, esta seção será impressa.
        # Se a criptografia (opção '1') for bem-sucedida, esta seção será impressa.

        # A mensagem de erro HMAC já exibe uma configuração "temporária".
        # Se o HMAC falhar, a função retorna, então esta seção não é executada.
        # Se o HMAC passar, mas a decodificação UTF-8 falhar, esta seção é executada.
        # Se a criptografia (opção 1) for executada, esta seção é executada.
        # Basicamente, esta seção será impressa se option '1' ou se option '2' e HMAC passar.
    # E também se HMAC passar mas a decodificação UTF-8 falhar.
    if 'rotors' in locals() or 'rotors' in globals(): # Verifica se 'rotors' foi definido
        print("\nConfiguração da Enigma utilizada/derivada:")
        print(f"Rotores: {rotors}")
        print(f"Ordem dos Rotores: {rotor_order}")
        print(f"Posições Iniciais: {initial_positions}")
        print(f"Refletor: {reflector_choice}")
        print(f"Plugboard: {plugboard}")

if __name__ == "__main__":
    main()
