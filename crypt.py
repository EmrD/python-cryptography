import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def encrypt_json(data, key, output_path):
    iv = os.urandom(16)  # IV oluştur
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # JSON verisini stringe çevirin ve bytes'a dönüştürün
    json_data = json.dumps(data).encode('utf-8')

    # Padding uygulayın
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(json_data) + padder.finalize()

    # Şifreleme işlemi
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Şifrelenmiş veriyi ve IV'yi dosyaya yazın
    with open(output_path, 'wb') as f:
        f.write(iv + ciphertext)

# Kullanım örneği
key = os.urandom(32)  # 256-bit anahtar
data = open("settings.json" , "r").read()
encrypt_json(data, key, 'settings.json')

print("Encryption key (save this securely):", key.hex())
