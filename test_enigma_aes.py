import unittest
import os
import base64
import hashlib
import hmac

# Assuming enigma_machine_aesv2.py is in the same directory or accessible in PYTHONPATH
from enigma_machine_aesv2 import (
    derive_configuration_from_password,
    EnigmaMachine,
    aes_encrypt_decrypt
)

class TestEnigmaAES(unittest.TestCase):

    def test_enigma_settings_derivation_consistency(self):
        """
        Test that derive_configuration_from_password produces consistent
        Enigma settings for the same password.
        """
        password = "testpassword123"
        
        rotors1, reflector1, plugboard1, positions1, order1, ref_choice1 = derive_configuration_from_password(password)
        rotors2, reflector2, plugboard2, positions2, order2, ref_choice2 = derive_configuration_from_password(password)

        self.assertEqual(rotors1, rotors2, "Rotor configurations should be identical")
        self.assertEqual(reflector1, reflector2, "Reflector choice should be identical")
        self.assertEqual(plugboard1, plugboard2, "Plugboard settings should be identical")
        self.assertEqual(positions1, positions2, "Initial rotor positions should be identical")
        self.assertEqual(order1, order2, "Rotor order should be identical")
        self.assertEqual(ref_choice1, ref_choice2, "Reflector choice string should be identical")

    def test_enigma_encrypt_message_simple_reciprocity(self):
        """
        Test the Enigma machine's reciprocity: encrypting an encrypted message
        with the same settings should yield the original.
        Tests with uppercase only.
        """
        password = "enigma_reciprocity_test"
        original_message = "TESTINGENIGMARECIPROCITY"

        rotors, reflector, plugboard, initial_positions, _, _ = derive_configuration_from_password(password)
        
        enigma_machine = EnigmaMachine(rotors, reflector, plugboard)
        enigma_machine.set_rotor_positions(initial_positions[:]) # Use a copy for first encryption

        encrypted_once = enigma_machine.encrypt_message(original_message)
        
        # Reset positions for the second encryption pass (as if it's a new operation for decryption)
        enigma_machine_for_decryption = EnigmaMachine(rotors, reflector, plugboard)
        enigma_machine_for_decryption.set_rotor_positions(initial_positions[:]) # Use a copy

        decrypted_message = enigma_machine_for_decryption.encrypt_message(encrypted_once)

        self.assertEqual(decrypted_message, original_message, "Enigma decryption (encryption of ciphertext) failed")

    def _encrypt_data(self, message_str, password_str):
        """Helper function to perform the full encryption process."""
        # 1. Derive Enigma config
        rotors, reflector, plugboard, initial_positions, _, _ = derive_configuration_from_password(password_str)
        
        # 2. Enigma encrypt
        enigma = EnigmaMachine(rotors, reflector, plugboard)
        enigma.set_rotor_positions(initial_positions[:])
        enigma_encrypted_str = enigma.encrypt_message(message_str) # Handles .upper() internally if needed by Enigma part
        enigma_encrypted_bytes = enigma_encrypted_str.encode('utf-8')

        # 3. Generate salt for PBKDF2
        salt = os.urandom(16)
        
        # 4. Derive AES and HMAC keys using PBKDF2
        derived_key = hashlib.pbkdf2_hmac('sha256', password_str.encode(), salt, 100000, dklen=64)
        aes_key = derived_key[:32]
        hmac_key = derived_key[32:]

        # 5. Generate random IV for AES
        iv = os.urandom(16)
        
        # 6. AES encrypt
        aes_encrypted_data = aes_encrypt_decrypt(enigma_encrypted_bytes, aes_key, iv, 'encrypt')
        
        # 7. Prepare data for HMAC: salt + iv + aes_ciphertext
        data_to_auth = salt + iv + aes_encrypted_data
        
        # 8. Calculate HMAC tag
        hmac_tag = hmac.new(hmac_key, data_to_auth, hashlib.sha256).digest()
        
        # 9. Final package: Base64 encode (salt + iv + aes_ciphertext + hmac_tag)
        final_package_bytes = data_to_auth + hmac_tag
        return base64.b64encode(final_package_bytes).decode('utf-8')

    def _decrypt_data(self, final_package_str, password_str):
        """Helper function to perform the full decryption process. Returns decrypted message or error string."""
        try:
            encrypted_message_blob = base64.b64decode(final_package_str)
            
            received_hmac = encrypted_message_blob[-32:]
            data_to_verify = encrypted_message_blob[:-32]

            salt = data_to_verify[:16]
            iv = data_to_verify[16:32]
            encrypted_data_for_aes = data_to_verify[32:]

            derived_key = hashlib.pbkdf2_hmac('sha256', password_str.encode(), salt, 100000, dklen=64)
            aes_key = derived_key[:32]
            hmac_key = derived_key[32:]

            calculated_hmac = hmac.new(hmac_key, data_to_verify, hashlib.sha256).digest()
            
            if not hmac.compare_digest(calculated_hmac, received_hmac):
                return "HMAC_VERIFICATION_FAILED"

            decrypted_aes_bytes = aes_encrypt_decrypt(encrypted_data_for_aes, aes_key, iv, 'decrypt')
            decrypted_enigma_str = decrypted_aes_bytes.decode('utf-8')
            
            rotors_dec, reflector_dec, plugboard_dec, initial_positions_dec, _, _ = derive_configuration_from_password(password_str)
            enigma_dec = EnigmaMachine(rotors_dec, reflector_dec, plugboard_dec)
            enigma_dec.set_rotor_positions(initial_positions_dec[:])
            
            original_message_str = enigma_dec.encrypt_message(decrypted_enigma_str)
            return original_message_str
        except Exception as e:
            return f"DECRYPTION_ERROR: {str(e)}"


    def test_full_encryption_decryption_roundtrip_simple(self):
        """Test full encryption and decryption with a simple uppercase message."""
        original_message = "HELLOWORLD"
        password = "mysecretpassword"

        encrypted_package = self._encrypt_data(original_message, password)
        decrypted_message = self._decrypt_data(encrypted_package, password)
        
        self.assertEqual(decrypted_message, original_message.upper(), "Full roundtrip failed for simple message")

    def test_full_encryption_decryption_roundtrip_complex(self):
        """Test full encryption/decryption with mixed case, spaces, and punctuation."""
        original_message = "Hello, World! This is a test message 123."
        # Expected after enigma processing (letters to upper, others preserved)
        expected_processed_message = "HELLO, WORLD! THIS IS A TEST MESSAGE 123."
        password = "complex_password_!@#"

        encrypted_package = self._encrypt_data(original_message, password)
        decrypted_message = self._decrypt_data(encrypted_package, password)
        
        self.assertEqual(decrypted_message, expected_processed_message, "Full roundtrip failed for complex message")


    def test_decryption_tampered_data(self):
        """Test that decryption fails or returns incorrect data if the payload is tampered."""
        original_message = "Don't tamper with this!"
        password = "integrity_check_password"

        encrypted_package_str = self._encrypt_data(original_message, password)
        encrypted_package_bytes = base64.b64decode(encrypted_package_str)

        # Tamper the data (e.g., flip a bit in the AES ciphertext part)
        # Salt (16) + IV (16) = 32. Let's tamper a byte after that.
        if len(encrypted_package_bytes) > 33: # Ensure there's a byte to tamper
            tampered_byte_index = 32 
            tampered_package_list = list(encrypted_package_bytes)
            tampered_package_list[tampered_byte_index] = tampered_package_list[tampered_byte_index] ^ 0xFF # Flip all bits
            tampered_package_bytes = bytes(tampered_package_list)
        else:
            # If package is too short (shouldn't happen with valid encryption), make it clearly invalid
            tampered_package_bytes = encrypted_package_bytes + b"tamper" 
            
        tampered_package_str = base64.b64encode(tampered_package_bytes).decode('utf-8')

        decrypted_result = self._decrypt_data(tampered_package_str, password)
        
        self.assertIn("HMAC_VERIFICATION_FAILED", decrypted_result, 
                      "Decryption should fail HMAC check for tampered data, or result in different message.")
        # If HMAC somehow passed (extremely unlikely for this tampering), the message should not match
        if "HMAC_VERIFICATION_FAILED" not in decrypted_result:
             self.assertNotEqual(decrypted_result, original_message.upper(), 
                                "Decrypted message should not match original if data was tampered and HMAC passed by fluke.")


    def test_decryption_wrong_password(self):
        """Test that decryption fails if the wrong password is used."""
        original_message = "Secret Squirrel"
        correct_password = "correct_password_here"
        wrong_password = "wrong_password_guess"

        encrypted_package = self._encrypt_data(original_message, correct_password)
        
        # Attempt decryption with the wrong password
        decrypted_result = self._decrypt_data(encrypted_package, wrong_password)
        
        self.assertEqual(decrypted_result, "HMAC_VERIFICATION_FAILED", 
                         "Decryption with wrong password should fail HMAC verification.")

if __name__ == '__main__':
    unittest.main()
