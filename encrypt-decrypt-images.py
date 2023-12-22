# before running code setup python environment and install these libraries using below given commands. 
#pip install cryptography
#pip nstall pillow
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from PIL import Image
import io
import os
import base64


def encrypt(key, original_image):
    f = Fernet(key)
    encrypted_image = f.encrypt(original_image)
    return encrypted_image


def decrypt(key, encrypted_image):
    f = Fernet(key)
    decrypted_image = f.decrypt(encrypted_image)
    return decrypted_image


def process_image(image_path):
    with Image.open(image_path) as img:
        byte_arr = io.BytesIO()
        img.save(byte_arr, format='PNG')
        img_byte = byte_arr.getvalue()
    return img_byte


def generate_key(password):
    password = password.encode() 
    salt = b'salt_'  
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password)) 
    return key


def main():
    print("This is an image encryption tool. Where you can encrypt and decrypt those encrypted images. Only you have "
          "to do is to remember that password you used to encrypt your data.")
    x = input("Enter 1 for encryption and 2 for decryption: ")
    
    if x == "1":
        password = input("Enter a password: ")
        image_path = input("Input image path (Relative path): ")
        key = generate_key(password)
        original_image = process_image(image_path)
        encrypted_image = encrypt(key, original_image)
        with open('encrypted_image.png', 'wb') as encrypted_file:
            encrypted_file.write(encrypted_image)
        print("Image encrypted and saved as 'encrypted_image.png'.")
        
    elif x == "2":
        password = input("Enter the password used for encryption: ")
        image_path = input("Input the path of the encrypted image (Relative path): ")
        key = generate_key(password)
        with open(image_path, 'rb') as encrypted_file:
            encrypted_image = encrypted_file.read()
        decrypted_image = decrypt(key, encrypted_image)
        with Image.open(io.BytesIO(decrypted_image)) as img:
            img.show()
        print("Image decrypted and displayed.")
        
    else:
        print("Invalid input. Please enter either '1' for encryption or '2' for decryption.")


if __name__ == "__main__":
    main()
