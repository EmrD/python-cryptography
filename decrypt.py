import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def decrypt_json(file_path, key):
    with open(file_path, 'rb') as f:
        iv = f.read(16)  # İlk 16 byte IV'yi oku
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Veri dolgusunu kaldırın
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # JSON verisini çözün
    return json.loads(plaintext.decode('utf-8'))

# Kullanım örneği
key = bytes.fromhex('b9d4af7d2c0e8bdf35d9d8946c305b0d25c4f469d6891ccbf05ccb2faf0faec0')  # Anahtarı burada girin
decrypted_data = decrypt_json('settings.json', key)
print(decrypted_data)
open("settings.json" , "w").write(json.dumps(decrypted_data))