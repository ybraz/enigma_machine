import getpass
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random
import string

class EnigmaMachine:
    def __init__(self, rotors, reflector, plugboard):
        self.rotors = rotors
        self.reflector = reflector
        self.plugboard = plugboard
        self.rotor_positions = [0] * len(rotors)

    def set_rotor_positions(self, positions):
        self.rotor_positions = positions

    def encrypt_character(self, char):
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
        for i in range(len(self.rotors)):
            self.rotor_positions[i] = (self.rotor_positions[i] + 1) % 26
            if self.rotor_positions[i] != 0:
                break

    def encrypt_message(self, message):
        encrypted_message = ''
        for char in message:
            if char.isalpha():
                encrypted_message += self.encrypt_character(char.upper())
            else:
                encrypted_message += char
        return encrypted_message

def derive_configuration_from_password(password):
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

    # Use the password to derive rotor selection and initial positions
    random.seed(int(hex_dig, 16))
    rotor_order = random.sample(all_rotors, 3)
    initial_positions = [random.randint(0, 25) for _ in range(3)]
    reflector_choice = random.choice(all_reflectors)

    # Derive plugboard pairs from the password
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
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor_decryptor = cipher.encryptor() if operation == 'encrypt' else cipher.decryptor()
    return encryptor_decryptor.update(text) + encryptor_decryptor.finalize()

def main():
    print("Bem-vindo à Máquina Enigma!")
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
        iv = base64.b64encode(reflector.encode())[:16]
        final_encrypted_message = aes_encrypt_decrypt(encrypted_message.encode(), key, iv, 'encrypt')
        print("Mensagem criptografada:", base64.b64encode(final_encrypted_message).decode())
    elif option == '2':
        encrypted_message = input("Digite a mensagem criptografada: ")
        password = getpass.getpass("Digite a senha: ")

        encrypted_message_bytes = base64.b64decode(encrypted_message)
        key = hashlib.sha256(password.encode()).digest()
        rotors, reflector, plugboard, initial_positions, rotor_order, reflector_choice = derive_configuration_from_password(password)
        iv = base64.b64encode(reflector.encode())[:16]

        decrypted_bytes = aes_encrypt_decrypt(encrypted_message_bytes, key, iv, 'decrypt')
        decrypted_message = decrypted_bytes.decode('utf-8')
        
        enigma = EnigmaMachine(rotors, reflector, plugboard)
        enigma.set_rotor_positions(initial_positions)
        final_decrypted_message = enigma.encrypt_message(decrypted_message)
        print("Mensagem descriptografada:", final_decrypted_message)
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
