from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

def generate_key_pair():
    if not os.path.exists('private_key.pem'):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        # Save the private key
        with open('private_key.pem', 'wb') as private_key_file:
            private_key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save the public key
        with open('public_key.pem', 'wb') as public_key_file:
            public_key_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        return True  # Keys were generated
    return False  # Keys already exist

if __name__ == "__main__":
    if generate_key_pair():
        print("Keys generated")
    else:
        print("Keys already present")

# Load public key to encrypt message

def load_public_key():
    with open('public_key.pem', 'rb') as public_key_file:
        public_key = serialization.load_pem_public_key(public_key_file.read())
    return public_key

def encrypt_message(message):
    public_key = load_public_key()
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open('encrypted_message.bin', 'wb') as file:
        file.write(encrypted_message)
    print(f'Encrypted message: {encrypted_message}')

# Remove hashtags in front of message, encrypt_message(message), and decrypt_message() in order to test functionality without user input

# message = "This is a secret message"
# encrypt_message(message)

def load_private_key():
    with open('private_key.pem', 'rb') as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None
        )
    return private_key

def decrypt_message():
    private_key = load_private_key()
    with open('encrypted_message.bin', 'rb') as file:
        encrypted_message = file.read()
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f'Decrypted message: {decrypted_message.decode()}')

# Remove hashtag below to test functionality without user input
# decrypt_message()

def main():
    choice = input("Please type E to encrypt a message, or D to decrypt the previous message: ").upper()
    if choice == "E":
        message = input("Please enter a message to encrypt: ")
        encrypt_message(message)
    elif choice == "D":
        decrypt_message()
    else:
        print("Invalid choice, please RTFM and get back to me")

if __name__ == '__main__':
    main()