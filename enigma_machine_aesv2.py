"""
Enigma Machine using AES-GCM for Cryptography

History:
The Enigma Machine was a cryptography tool used primarily during World War II.
It was invented by German engineer Arthur Scherbius in the late 1910s and used extensively by German military forces.
The Enigma Machine allowed complex letter substitution in messages using a combination of rotors, a reflector, and a plugboard configuration, making its messages extremely difficult to decipher.
Messages encrypted by Enigma were considered nearly impossible to break, until the efforts of Allied cryptographers, such as Alan Turing and his team at Bletchley Park, managed to decipher them, changing the course of the war.

This code implements a modern and secure version of the Enigma Machine, complemented with AES-GCM (AEAD) cryptography, strong key derivation with Argon2id, and advanced security features.

WARNING: This is a cryptography system for educational and experimental purposes.
For production use, utilize established cryptography libraries such as NaCl/libsodium, Age, or PGP.
"""

import getpass
import hashlib
import base64
import random
import string
import time
import os
import sys
import argparse
import struct
import json
from pathlib import Path
from typing import Tuple, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type
import pyperclip

# Cryptography format version
CRYPTO_VERSION = 2

# Security parameters
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
SALT_LENGTH = 32
IV_LENGTH = 12  # GCM recommends 12 bytes
TAG_LENGTH = 16  # GCM tag
CONFIG_SALT_LENGTH = 16

class PasswordStrength:
    """Evaluates password strength."""

    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Calculates password entropy in bits."""
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(not c.isalnum() for c in password):
            charset_size += 32

        import math
        if charset_size == 0:
            return 0
        return len(password) * math.log2(charset_size)

    @staticmethod
    def assess_strength(password: str) -> Tuple[str, str]:
        """
        Assesses password strength.

        Returns:
            Tuple of (level, message)
        """
        entropy = PasswordStrength.calculate_entropy(password)

        if entropy < 28:
            return ("MUITO FRACA", "⚠️  ATENÇÃO: Senha muito fraca! Use pelo menos 12 caracteres com números, maiúsculas e símbolos.")
        elif entropy < 36:
            return ("FRACA", "⚠️  Senha fraca. Considere usar uma passphrase mais longa.")
        elif entropy < 60:
            return ("MÉDIA", "✓ Senha razoável, mas poderia ser mais forte.")
        elif entropy < 128:
            return ("FORTE", "✓ Boa senha!")
        else:
            return ("MUITO FORTE", "✓ Excelente senha!")


class EnigmaMachine:
    """Enigma Machine implementation."""

    def __init__(self, rotors: List[str], reflector: str, plugboard: Dict[str, str]):
        """
        Initializes the Enigma Machine with the provided rotors, reflector, and plugboard.

        Args:
            rotors: List of strings representing rotor mappings.
            reflector: String representing reflector mapping.
            plugboard: Dictionary representing plugboard connections.
        """
        self.rotors = rotors
        self.reflector = reflector
        self.plugboard = plugboard
        self.rotor_positions = [0] * len(rotors)

    def set_rotor_positions(self, positions: List[int]):
        """
        Sets the initial rotor positions.

        Args:
            positions: List of integers representing initial rotor positions.
        """
        self.rotor_positions = positions

    def step_rotors(self):
        """
        Advances rotor positions, simulating the Enigma Machine rotation mechanism.
        """
        for i in range(len(self.rotors)):
            self.rotor_positions[i] = (self.rotor_positions[i] + 1) % 26
            if self.rotor_positions[i] != 0:
                break

    def encrypt_character(self, char: str) -> str:
        """
        Encrypts a single character using Enigma Machine logic.

        Args:
            char: Character to be encrypted.

        Returns:
            Encrypted character.
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

    def encrypt_message(self, message: str) -> str:
        """
        Encrypts a complete message.

        Args:
            message: Message to be encrypted.

        Returns:
            Encrypted message.
        """
        encrypted_message = ''
        for char in message:
            if char.isascii() and char.isalpha():
                encrypted_message += self.encrypt_character(char.upper())
            else:
                encrypted_message += char
        return encrypted_message


class CryptoConfig:
    """Manages cryptography configuration."""

    ROTOR_WIRING = {
        'I': 'EKMFLGDQVZNTOWYHXUSPAIBRCJ',
        'II': 'AJDKSIRUXBLHWTMCQGZNPYFVOE',
        'III': 'BDFHJLCPRTXVZNYEIWGAKMUSQO',
        'IV': 'ESOVPZJAYQUIRHXLNFTGKDCMWB',
        'V': 'VZBRGITYUPSDNHLXAWMJQOFECK'
    }

    REFLECTORS = {
        'B': 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
        'C': 'FVPJIAOYEDRZXWGCTKUQSBNMHL'
    }

    @staticmethod
    def derive_configuration_from_password(password: str, config_salt: bytes) -> Tuple:
        """
        Derives Enigma Machine configuration from password and salt.

        Args:
            password: User-provided password.
            config_salt: Salt for configuration derivation (allows different configs with same password).

        Returns:
            Tuple containing: rotors, reflector, plugboard, initial_positions, rotor_order, reflector_choice
        """
        # Deriva seed da configuração usando a senha + salt
        seed_bytes = hash_secret_raw(
            secret=password.encode(),
            salt=config_salt,
            time_cost=2,
            memory_cost=8192,
            parallelism=1,
            hash_len=32,
            type=Type.ID
        )
        seed = int.from_bytes(seed_bytes, 'big')

        all_rotors = list(CryptoConfig.ROTOR_WIRING.keys())
        all_reflectors = list(CryptoConfig.REFLECTORS.keys())

        # Usa o seed para derivar a seleção de rotores e posições iniciais
        random.seed(seed)
        rotor_order = random.sample(all_rotors, 3)
        initial_positions = [random.randint(0, 25) for _ in range(3)]
        reflector_choice = random.choice(all_reflectors)

        # Deriva pares do plugboard
        alphabet = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        random.shuffle(alphabet)
        plugboard_pairs = [(alphabet[i], alphabet[i + 1]) for i in range(0, 12, 2)]

        rotors = [CryptoConfig.ROTOR_WIRING[rotor] for rotor in rotor_order]
        reflector = CryptoConfig.REFLECTORS[reflector_choice]

        plugboard = {}
        for pair in plugboard_pairs:
            plugboard[pair[0]] = pair[1]
            plugboard[pair[1]] = pair[0]

        return rotors, reflector, plugboard, initial_positions, rotor_order, reflector_choice

    @staticmethod
    def get_config_fingerprint(rotor_order: List[str], reflector_choice: str,
                                initial_positions: List[int]) -> str:
        """
        Gera um fingerprint curto da configuração para verificação manual.

        Returns:
            String hexadecimal de 8 caracteres
        """
        config_str = f"{'-'.join(rotor_order)}-{reflector_choice}-{'-'.join(map(str, initial_positions))}"
        hash_obj = hashlib.sha256(config_str.encode())
        return hash_obj.hexdigest()[:8].upper()


class SecureEnigmaCrypto:
    """Secure cryptography system using Enigma + AES-GCM."""

    @staticmethod
    def derive_key_argon2(password: str, salt: bytes) -> bytes:
        """
        Deriva uma chave criptográfica forte usando Argon2id.

        Args:
            password: Senha do usuário.
            salt: Salt único para esta mensagem.

        Returns:
            Chave de 32 bytes.
        """
        key = hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            type=Type.ID
        )
        return key

    @staticmethod
    def create_header(version: int, kdf: str, kdf_params: dict,
                     salt: bytes, config_salt: bytes, iv: bytes) -> bytes:
        """
        Cria cabeçalho com metadados de criptografia.

        Formato:
        - version (1 byte)
        - kdf_name_len (1 byte)
        - kdf_name (variable)
        - kdf_params_len (2 bytes)
        - kdf_params_json (variable)
        - salt (32 bytes)
        - config_salt (16 bytes)
        - iv (12 bytes)
        """
        kdf_bytes = kdf.encode()
        kdf_params_bytes = json.dumps(kdf_params).encode()

        header = struct.pack('B', version)  # version
        header += struct.pack('B', len(kdf_bytes))  # kdf name length
        header += kdf_bytes
        header += struct.pack('H', len(kdf_params_bytes))  # kdf params length
        header += kdf_params_bytes
        header += salt
        header += config_salt
        header += iv

        return header

    @staticmethod
    def parse_header(data: bytes) -> Tuple[int, str, dict, bytes, bytes, bytes, int]:
        """
        Faz parse do cabeçalho.

        Returns:
            Tupla: (version, kdf, kdf_params, salt, config_salt, iv, header_length)
        """
        offset = 0

        version = struct.unpack('B', data[offset:offset+1])[0]
        offset += 1

        kdf_len = struct.unpack('B', data[offset:offset+1])[0]
        offset += 1

        kdf = data[offset:offset+kdf_len].decode()
        offset += kdf_len

        kdf_params_len = struct.unpack('H', data[offset:offset+2])[0]
        offset += 2

        kdf_params = json.loads(data[offset:offset+kdf_params_len].decode())
        offset += kdf_params_len

        salt = data[offset:offset+SALT_LENGTH]
        offset += SALT_LENGTH

        config_salt = data[offset:offset+CONFIG_SALT_LENGTH]
        offset += CONFIG_SALT_LENGTH

        iv = data[offset:offset+IV_LENGTH]
        offset += IV_LENGTH

        return version, kdf, kdf_params, salt, config_salt, iv, offset

    @staticmethod
    def encrypt(message: str, password: str, show_progress: bool = True) -> bytes:
        """
        Criptografa uma mensagem usando Enigma + AES-GCM com Argon2id.

        Args:
            message: Mensagem em texto claro.
            password: Senha.
            show_progress: Se deve mostrar progresso.

        Returns:
            Dados criptografados com cabeçalho.
        """
        if show_progress:
            print("🔐 Iniciando criptografia...")

        # Gera salts e IV aleatórios
        salt = os.urandom(SALT_LENGTH)
        config_salt = os.urandom(CONFIG_SALT_LENGTH)
        iv = os.urandom(IV_LENGTH)

        if show_progress:
            print("🔑 Derivando chave criptográfica com Argon2id...")

        # Deriva chave com Argon2id
        key = SecureEnigmaCrypto.derive_key_argon2(password, salt)

        if show_progress:
            print("⚙️  Configurando Máquina Enigma...")

        # Deriva configuração da Enigma
        rotors, reflector, plugboard, initial_positions, rotor_order, reflector_choice = \
            CryptoConfig.derive_configuration_from_password(password, config_salt)

        # Cria fingerprint da configuração
        fingerprint = CryptoConfig.get_config_fingerprint(rotor_order, reflector_choice, initial_positions)

        if show_progress:
            print(f"🔍 Fingerprint da configuração: {fingerprint}")
            print("🎰 Processando com Enigma...")

        # Passa pela Enigma
        enigma = EnigmaMachine(rotors, reflector, plugboard)
        enigma.set_rotor_positions(initial_positions)
        enigma_encrypted = enigma.encrypt_message(message)

        if show_progress:
            print("🔒 Aplicando AES-GCM...")

        # Cria cabeçalho
        kdf_params = {
            'time_cost': ARGON2_TIME_COST,
            'memory_cost': ARGON2_MEMORY_COST,
            'parallelism': ARGON2_PARALLELISM,
            'hash_len': ARGON2_HASH_LEN
        }
        header = SecureEnigmaCrypto.create_header(
            CRYPTO_VERSION, 'argon2id', kdf_params, salt, config_salt, iv
        )

        # Criptografa com AES-GCM (AEAD)
        aesgcm = AESGCM(key)
        # Usa o cabeçalho como AAD (Additional Authenticated Data)
        ciphertext = aesgcm.encrypt(iv, enigma_encrypted.encode(), header)

        # Retorna header + ciphertext
        return header + ciphertext

    @staticmethod
    def decrypt(encrypted_data: bytes, password: str, show_progress: bool = True) -> str:
        """
        Descriptografa dados.

        Args:
            encrypted_data: Dados criptografados com cabeçalho.
            password: Senha.
            show_progress: Se deve mostrar progresso.

        Returns:
            Mensagem em texto claro.

        Raises:
            ValueError: Se a descriptografia falhar.
        """
        if show_progress:
            print("🔓 Iniciando descriptografia...")

        # Parse do cabeçalho
        version, kdf, kdf_params, salt, config_salt, iv, header_length = \
            SecureEnigmaCrypto.parse_header(encrypted_data)

        if version != CRYPTO_VERSION:
            raise ValueError(f"Versão de formato não suportada: {version}")

        if kdf != 'argon2id':
            raise ValueError(f"KDF não suportada: {kdf}")

        header = encrypted_data[:header_length]
        ciphertext = encrypted_data[header_length:]

        if show_progress:
            print(f"📋 Versão do formato: {version}")
            print(f"🔑 Derivando chave criptográfica com {kdf}...")

        # Deriva chave
        key = SecureEnigmaCrypto.derive_key_argon2(password, salt)

        if show_progress:
            print("🔓 Descriptografando com AES-GCM...")

        # Descriptografa com AES-GCM
        aesgcm = AESGCM(key)
        try:
            enigma_encrypted = aesgcm.decrypt(iv, ciphertext, header).decode('utf-8')
        except Exception as e:
            raise ValueError("Senha incorreta ou dados corrompidos/adulterados") from e

        if show_progress:
            print("⚙️  Configurando Máquina Enigma...")

        # Deriva configuração da Enigma
        rotors, reflector, plugboard, initial_positions, rotor_order, reflector_choice = \
            CryptoConfig.derive_configuration_from_password(password, config_salt)

        fingerprint = CryptoConfig.get_config_fingerprint(rotor_order, reflector_choice, initial_positions)

        if show_progress:
            print(f"🔍 Fingerprint da configuração: {fingerprint}")
            print("🎰 Processando com Enigma...")

        # Passa pela Enigma (Enigma é simétrica)
        enigma = EnigmaMachine(rotors, reflector, plugboard)
        enigma.set_rotor_positions(initial_positions)
        decrypted_message = enigma.encrypt_message(enigma_encrypted)

        return decrypted_message


class HybridCrypto:
    """Hybrid system using X25519 + AES-GCM."""

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """
        Gera um par de chaves X25519.

        Returns:
            Tupla (private_key_bytes, public_key_bytes)
        """
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        return private_bytes, public_bytes

    @staticmethod
    def encrypt_hybrid(message: str, recipient_public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Criptografa mensagem usando esquema híbrido.

        Args:
            message: Mensagem em texto claro.
            recipient_public_key: Chave pública do destinatário (32 bytes).

        Returns:
            Tupla (ephemeral_public_key, encrypted_data)
        """
        # Gera chave efêmera
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()

        # Carrega chave pública do destinatário
        recipient_public = X25519PublicKey.from_public_bytes(recipient_public_key)

        # Faz ECDH
        shared_secret = ephemeral_private.exchange(recipient_public)

        # Deriva chave simétrica do shared secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'enigma-hybrid-v1'
        )
        symmetric_key = hkdf.derive(shared_secret)

        # Criptografa com AES-GCM
        iv = os.urandom(IV_LENGTH)
        aesgcm = AESGCM(symmetric_key)
        ciphertext = aesgcm.encrypt(iv, message.encode(), None)

        # Empacota IV + ciphertext
        encrypted_data = iv + ciphertext

        ephemeral_public_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        return ephemeral_public_bytes, encrypted_data

    @staticmethod
    def decrypt_hybrid(ephemeral_public_key: bytes, encrypted_data: bytes,
                      private_key: bytes) -> str:
        """
        Descriptografa mensagem usando esquema híbrido.

        Args:
            ephemeral_public_key: Chave pública efêmera (32 bytes).
            encrypted_data: Dados criptografados.
            private_key: Chave privada do destinatário (32 bytes).

        Returns:
            Mensagem em texto claro.
        """
        # Carrega chaves
        ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_public_key)
        recipient_private = X25519PrivateKey.from_private_bytes(private_key)

        # Faz ECDH
        shared_secret = recipient_private.exchange(ephemeral_public)

        # Deriva chave simétrica
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'enigma-hybrid-v1'
        )
        symmetric_key = hkdf.derive(shared_secret)

        # Extrai IV e ciphertext
        iv = encrypted_data[:IV_LENGTH]
        ciphertext = encrypted_data[IV_LENGTH:]

        # Descriptografa
        aesgcm = AESGCM(symmetric_key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)

        return plaintext.decode('utf-8')


class FileEncryption:
    """File encryption with streaming."""

    CHUNK_SIZE = 64 * 1024  # 64 KB chunks

    @staticmethod
    def encrypt_file(input_path: str, output_path: str, password: str):
        """
        Criptografa um arquivo usando streaming.

        Args:
            input_path: Caminho do arquivo de entrada.
            output_path: Caminho do arquivo de saída.
            password: Senha.
        """
        print(f"📁 Criptografando arquivo: {input_path}")

        # Gera parâmetros
        salt = os.urandom(SALT_LENGTH)
        config_salt = os.urandom(CONFIG_SALT_LENGTH)
        iv = os.urandom(IV_LENGTH)

        print("🔑 Derivando chave...")
        key = SecureEnigmaCrypto.derive_key_argon2(password, salt)

        # Cria cabeçalho
        kdf_params = {
            'time_cost': ARGON2_TIME_COST,
            'memory_cost': ARGON2_MEMORY_COST,
            'parallelism': ARGON2_PARALLELISM,
            'hash_len': ARGON2_HASH_LEN
        }
        header = SecureEnigmaCrypto.create_header(
            CRYPTO_VERSION, 'argon2id', kdf_params, salt, config_salt, iv
        )

        # Obtém tamanho do arquivo
        file_size = os.path.getsize(input_path)

        print("🔒 Criptografando...")

        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Escreve cabeçalho
            f_out.write(header)

            # Criptografa em chunks
            aesgcm = AESGCM(key)
            chunk_num = 0
            bytes_processed = 0

            while True:
                chunk = f_in.read(FileEncryption.CHUNK_SIZE)
                if not chunk:
                    break

                # Usa IV + chunk_num para cada chunk
                chunk_iv = iv + struct.pack('>Q', chunk_num)[:4]
                encrypted_chunk = aesgcm.encrypt(chunk_iv, chunk, header)

                # Escreve tamanho do chunk + chunk criptografado
                f_out.write(struct.pack('>I', len(encrypted_chunk)))
                f_out.write(encrypted_chunk)

                chunk_num += 1
                bytes_processed += len(chunk)

                # Progress bar
                progress = (bytes_processed / file_size) * 100
                print(f"\rProgresso: {progress:.1f}%", end='', flush=True)

        print(f"\n✅ Arquivo criptografado salvo em: {output_path}")

    @staticmethod
    def decrypt_file(input_path: str, output_path: str, password: str):
        """
        Descriptografa um arquivo.

        Args:
            input_path: Caminho do arquivo criptografado.
            output_path: Caminho do arquivo de saída.
            password: Senha.
        """
        print(f"📁 Descriptografando arquivo: {input_path}")

        with open(input_path, 'rb') as f_in:
            # Lê suficiente para o cabeçalho
            header_data = f_in.read(1024)

            # Parse do cabeçalho
            version, kdf, kdf_params, salt, config_salt, iv, header_length = \
                SecureEnigmaCrypto.parse_header(header_data)

            if version != CRYPTO_VERSION:
                raise ValueError(f"Versão não suportada: {version}")

            # Volta ao início e lê o cabeçalho completo
            f_in.seek(0)
            header = f_in.read(header_length)

            print("🔑 Derivando chave...")
            key = SecureEnigmaCrypto.derive_key_argon2(password, salt)

            print("🔓 Descriptografando...")

            with open(output_path, 'wb') as f_out:
                aesgcm = AESGCM(key)
                chunk_num = 0

                while True:
                    # Lê tamanho do chunk
                    size_data = f_in.read(4)
                    if not size_data:
                        break

                    chunk_size = struct.unpack('>I', size_data)[0]
                    encrypted_chunk = f_in.read(chunk_size)

                    if not encrypted_chunk:
                        break

                    # Descriptografa
                    chunk_iv = iv + struct.pack('>Q', chunk_num)[:4]
                    try:
                        decrypted_chunk = aesgcm.decrypt(chunk_iv, encrypted_chunk, header)
                        f_out.write(decrypted_chunk)
                    except Exception as e:
                        raise ValueError("Senha incorreta ou arquivo corrompido") from e

                    chunk_num += 1
                    print(f"\rChunks processados: {chunk_num}", end='', flush=True)

        print(f"\n✅ Arquivo descriptografado salvo em: {output_path}")


def print_with_delay(message: str, delay: float = 0.05):
    """Imprime mensagem com delay."""
    for char in message:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()


def clear_screen():
    """Limpa a tela."""
    os.system('cls' if os.name == 'nt' else 'clear')


def get_password_with_strength_check(prompt: str = "Digite a senha: ") -> str:
    """
    Solicita senha com verificação de força.

    Returns:
        Senha validada.
    """
    while True:
        password = getpass.getpass(prompt)

        if len(password) < 8:
            print("⚠️  Senha muito curta! Use pelo menos 8 caracteres.")
            continue

        strength, message = PasswordStrength.assess_strength(password)
        entropy = PasswordStrength.calculate_entropy(password)

        print(f"Força da senha: {strength} (entropia: {entropy:.1f} bits)")
        print(message)

        if strength in ["MUITO FRACA", "FRACA"]:
            choice = input("Deseja continuar mesmo assim? (s/N): ")
            if choice.lower() != 's':
                continue

        return password


def interactive_mode():
    """Modo interativo original."""
    clear_screen()
    print("""
    *******************************************************
    *                                                     *
    *          BEM-VINDO À MÁQUINA ENIGMA v2.0            *
    *         Criptografia Moderna com AES-GCM            *
    *                                                     *
    *******************************************************
    """)

    print("Escolha uma opção:")
    print("1. Criptografar mensagem")
    print("2. Descriptografar mensagem")
    print("3. Criptografar arquivo")
    print("4. Descriptografar arquivo")
    option = input("Opção: ")

    if option == '1':
        message = input("Digite a mensagem: ")
        password = get_password_with_strength_check()

        print("\n⏳ Pressione ENTER para continuar...")
        input()

        encrypted_data = SecureEnigmaCrypto.encrypt(message, password)
        encrypted_b64 = base64.b64encode(encrypted_data).decode()

        clear_screen()
        print("""
        *******************************************************
        *                                                     *
        *              MENSAGEM CRIPTOGRAFADA                 *
        *                                                     *
        *******************************************************
        """)
        print_with_delay(encrypted_b64, 0.01)

        # Oferecer copiar para clipboard
        try:
            choice = input("\nCopiar para clipboard? (s/N): ")
            if choice.lower() == 's':
                pyperclip.copy(encrypted_b64)
                print("✅ Copiado para clipboard!")
        except Exception as e:
            print(f"⚠️  Não foi possível copiar: {e}")

    elif option == '2':
        encrypted_message = input("Digite a mensagem criptografada: ")
        password = getpass.getpass("Digite a senha: ")

        try:
            encrypted_data = base64.b64decode(encrypted_message)
            decrypted_message = SecureEnigmaCrypto.decrypt(encrypted_data, password)

            print("\n⏳ Pressione ENTER para ver a mensagem descriptografada...")
            input()

            clear_screen()
            print("""
            *******************************************************
            *                                                     *
            *            MENSAGEM DESCRIPTOGRAFADA                *
            *                                                     *
            *******************************************************
            """)
            print_with_delay(decrypted_message, 0.05)
        except ValueError as e:
            print(f"\n❌ Erro: {e}")

    elif option == '3':
        input_file = input("Arquivo de entrada: ")
        output_file = input("Arquivo de saída (criptografado): ")
        password = get_password_with_strength_check()

        print("\n⏳ Pressione ENTER para continuar...")
        input()

        try:
            FileEncryption.encrypt_file(input_file, output_file, password)
        except Exception as e:
            print(f"❌ Erro: {e}")

    elif option == '4':
        input_file = input("Arquivo criptografado: ")
        output_file = input("Arquivo de saída: ")
        password = getpass.getpass("Digite a senha: ")

        print("\n⏳ Pressione ENTER para continuar...")
        input()

        try:
            FileEncryption.decrypt_file(input_file, output_file, password)
        except Exception as e:
            print(f"❌ Erro: {e}")

    else:
        print("❌ Opção inválida!")


def cli_mode():
    """Modo CLI com argparse."""
    parser = argparse.ArgumentParser(
        description='Máquina Enigma v2.0 - Criptografia moderna com AES-GCM',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  %(prog)s encrypt -m "Hello World" -o encrypted.txt
  %(prog)s decrypt -f encrypted.txt
  %(prog)s encrypt-file -i document.pdf -o document.pdf.enc
  %(prog)s decrypt-file -i document.pdf.enc -o document.pdf
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Comandos disponíveis')

    # Encrypt
    encrypt_parser = subparsers.add_parser('encrypt', help='Criptografar mensagem')
    encrypt_parser.add_argument('-m', '--message', help='Mensagem a criptografar')
    encrypt_parser.add_argument('-o', '--output', help='Arquivo de saída')
    encrypt_parser.add_argument('--armor', action='store_true', help='Saída em base64')

    # Decrypt
    decrypt_parser = subparsers.add_parser('decrypt', help='Descriptografar mensagem')
    decrypt_parser.add_argument('-m', '--message', help='Mensagem criptografada')
    decrypt_parser.add_argument('-f', '--file', help='Arquivo com mensagem criptografada')

    # Encrypt file
    encfile_parser = subparsers.add_parser('encrypt-file', help='Criptografar arquivo')
    encfile_parser.add_argument('-i', '--input', required=True, help='Arquivo de entrada')
    encfile_parser.add_argument('-o', '--output', required=True, help='Arquivo de saída')

    # Decrypt file
    decfile_parser = subparsers.add_parser('decrypt-file', help='Descriptografar arquivo')
    decfile_parser.add_argument('-i', '--input', required=True, help='Arquivo criptografado')
    decfile_parser.add_argument('-o', '--output', required=True, help='Arquivo de saída')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Executar comando
    if args.command == 'encrypt':
        message = args.message or input("Mensagem: ")
        password = get_password_with_strength_check()

        print("\n⏳ Pressione ENTER para continuar...")
        input()

        encrypted_data = SecureEnigmaCrypto.encrypt(message, password)
        encrypted_b64 = base64.b64encode(encrypted_data).decode()

        if args.output:
            Path(args.output).write_text(encrypted_b64)
            print(f"✅ Salvo em {args.output}")
        else:
            print("\n" + encrypted_b64)
            try:
                pyperclip.copy(encrypted_b64)
                print("✅ Copiado para clipboard!")
            except:
                pass

    elif args.command == 'decrypt':
        if args.file:
            encrypted_b64 = Path(args.file).read_text().strip()
        else:
            encrypted_b64 = args.message or input("Mensagem criptografada: ")

        password = getpass.getpass("Senha: ")

        try:
            encrypted_data = base64.b64decode(encrypted_b64)
            decrypted = SecureEnigmaCrypto.decrypt(encrypted_data, password)

            print("\n⏳ Pressione ENTER para ver a mensagem descriptografada...")
            input()

            print("\n" + decrypted)
        except Exception as e:
            print(f"❌ Erro: {e}")
            sys.exit(1)

    elif args.command == 'encrypt-file':
        password = get_password_with_strength_check()

        print("\n⏳ Pressione ENTER para continuar...")
        input()

        FileEncryption.encrypt_file(args.input, args.output, password)

    elif args.command == 'decrypt-file':
        password = getpass.getpass("Senha: ")

        print("\n⏳ Pressione ENTER para continuar...")
        input()

        FileEncryption.decrypt_file(args.input, args.output, password)


def main():
    """Função principal."""
    if len(sys.argv) > 1:
        cli_mode()
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
