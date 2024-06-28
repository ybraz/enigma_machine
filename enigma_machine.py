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

def configure_enigma(rotor_order, initial_positions, reflector_choice, plugboard_pairs):
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

    rotors = [rotor_wiring[rotor] for rotor in rotor_order]
    reflector = reflectors[reflector_choice]
    
    plugboard = {pair[0]: pair[1] for pair in plugboard_pairs}
    plugboard.update({pair[1]: pair[0] for pair in plugboard_pairs})

    enigma = EnigmaMachine(rotors, reflector, plugboard)
    enigma.set_rotor_positions([ord(pos) - 65 for pos in initial_positions])
    
    return enigma

## Regras do plugboard
'''
Pares Exclusivos: Cada letra pode ser conectada a no máximo uma outra letra. 
Uma vez conectada, não pode ser usada novamente para outra conexão.

Conexões Bidirecionais: Se a letra A está conectada à letra B, então a letra B deve estar conectada à letra A.

Número de Conexões: Historicamente, o número de pares conectados variava, mas normalmente entre 6 a 10 pares eram utilizados. 
No entanto, qualquer número de pares até 13 pode ser configurado.
'''

# Setup Criptográfico
rotor_order = ['III', 'II', 'I']
initial_positions = ['M', 'C', 'K']
reflector_choice = 'B'
plugboard_pairs = [('A', 'Z'), ('B', 'F'), ('E', 'K'), ('L', 'H'), ('I', 'W'), ('M', 'C')]

enigma = configure_enigma(rotor_order, initial_positions, reflector_choice, plugboard_pairs)
message = "HELLO WORLD"
encrypted_message = enigma.encrypt_message(message)
print(f"Encrypted message: {encrypted_message}")

# Para descriptografar, reinicie as posições dos rotores e passe a mensagem criptografada
enigma.set_rotor_positions([ord(pos) - 65 for pos in initial_positions])
decrypted_message = enigma.encrypt_message(encrypted_message)
print(f"Decrypted message: {decrypted_message}")
