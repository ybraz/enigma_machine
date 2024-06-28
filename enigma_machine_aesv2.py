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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Se você estiver no Windows, descomente a linha abaixo.
import winsound

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
        # Se você estiver no Windows, descomente a linha abaixo.
        winsound.Beep(500, 100)
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
        message = input("Digite a mensagem (apenas letras A-Z): ").upper()
        password = getpass.getpass("Digite a senha: ")

        rotors, reflector, plugboard, initial_positions, rotor_order, reflector_choice = derive_configuration_from_password(password)

        enigma = EnigmaMachine(rotors, reflector, plugboard)
        enigma.set_rotor_positions(initial_positions)

        encrypted_message = enigma.encrypt_message(message)
        key = hashlib.sha256(password.encode()).digest()
        iv = hashlib.md5(reflector.encode()).digest()  # Usando um hash MD5 para derivar um IV fixo e variável
        final_encrypted_message = aes_encrypt_decrypt(encrypted_message.encode(), key, iv, 'encrypt')
        
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

        encrypted_message_bytes = base64.b64decode(encrypted_message)
        key = hashlib.sha256(password.encode()).digest()
        rotors, reflector, plugboard, initial_positions, rotor_order, reflector_choice = derive_configuration_from_password(password)
        iv = hashlib.md5(reflector.encode()).digest()  # Usando um hash MD5 para derivar um IV fixo e variável

        try:
            decrypted_bytes = aes_encrypt_decrypt(encrypted_message_bytes, key, iv, 'decrypt')
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
            print("\nErro: A senha fornecida está incorreta ou a mensagem está corrompida.")
    else:
        print("Opção inválida!")

    print("\nConfiguração da Enigma:")
    print(f"Rotores: {rotors}")
    print(f"Ordem dos Rotores: {rotor_order}")
    print(f"Posições Iniciais: {initial_positions}")
    print(f"Refletor: {reflector_choice}")
    print(f"Plugboard: {plugboard}")

if __name__ == "__main__":
    main()
