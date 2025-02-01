
# Password Recovery

This project demonstrates a password cracker that supports multiple cryptographic hash algorithms. The program attempts to crack hashes using a wordlist (e.g., `rockyou.txt`). It is designed to work with various hashing algorithms.

## Supported Algorithms

- MD4
- MD5
- SHA-224
- SHA-256
- SHA-384
- SHA-512
- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512
- Tiger
- Whirlpool
- Streebog-256
- Streebog-512

## How to Use

#### 1. Clone the project to your local machine:

```bash
git clone https://github.com/yourusername/password-cracker.git
cd password-cracker
```

#### 2. Run the project using [Cargo](https://www.rust-lang.org/tools/install):

```bash
cargo run <algo> <file_path> <wordlist_path>
```

#### 3. Demo Script (Optional)

You can also use the provided `crackdemo.sh` script to run the program for all supported algorithms with one command. This will iterate through all hash files in the `hashes/` directory and attempt to crack them using the provided wordlist.

## Example Output:

```
cracked::8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92 --- 123456 
cracked::5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 --- password 
cracked::65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5 --- qwerty 
cracked::27cc6994fc1c01ce6659c6bddca9b69c4c6a9418065e612c69d110b3f7b11f8a --- hello123
```

```
====================
Starting process for: sha256
====================
cracked::9b74c9897bac770ffc029102a200c5de7d57c0d7ec2fa278502c920de0b6d99c --- password123
...

Process completed in: 2 minutes, 35 seconds.
```
