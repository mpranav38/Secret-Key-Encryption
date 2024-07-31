
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

import os

def substitution_cipher(plaintext, key, decrypt=False):
    key = -key if decrypt else key
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            shift = ord('a') if char.islower() else ord('A')
            ciphertext += chr((ord(char) - shift + key) % 26 + shift)
        else:
            ciphertext += char
    return ciphertext

def shift_cipher(plaintext, key):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            shift = ord('a') if char.islower() else ord('A')
            ciphertext += chr((ord(char) - shift + key) % 26 + shift)
        else:
            ciphertext += char
    return ciphertext

def permutation_cipher(plaintext, permutation_key):
    if len(plaintext) != len(permutation_key):
        raise ValueError("Permutation key length must match plaintext length")

    ciphertext = [0] * len(plaintext)
    for i, index in enumerate(permutation_key):
        ciphertext[index - 1] = plaintext[i]

    return ''.join(ciphertext)

def simple_transposition(plaintext, key):
    num_columns = key
    num_rows = (len(plaintext) + num_columns - 1) // num_columns
    table = [''] * num_rows

    for i in range(len(plaintext)):
        table[i % num_rows] += plaintext[i]

    return ''.join(table)

def double_transposition(plaintext, key1, key2):
    intermediate = simple_transposition(plaintext, key1)
    ciphertext = simple_transposition(intermediate, key2)

    return ciphertext

def vigenere_cipher(plaintext, keyword):
    ciphertext = ""
    keyword = keyword * (len(plaintext) // len(keyword)) + keyword[:len(plaintext) % len(keyword)]

    for i in range(len(plaintext)):
        char = plaintext[i]
        if char.isalpha():
            shift = ord('a') if char.islower() else ord('A')
            key_shift = ord(keyword[i]) - ord('a') if keyword[i].islower() else ord(keyword[i]) - ord('A')
            ciphertext += chr((ord(char) - shift + key_shift) % 26 + shift)
        else:
            ciphertext += char

    return ciphertext

def aes_encrypt(plaintext, key, mode):
    if isinstance(mode, modes.CBC):
        iv = os.urandom(16)  # Generate a random IV for CBC mode
        encryptor = Cipher(algorithms.AES(key), mode(iv), backend=default_backend()).encryptor()
    else:
        encryptor = Cipher(algorithms.AES(key), mode, backend=default_backend()).encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext

def aes_decrypt(ciphertext, key, mode):
    if isinstance(mode, modes.CBC):
        decryptor = Cipher(algorithms.AES(key), mode(ciphertext[:16]), backend=default_backend()).decryptor()
    else:
        decryptor = Cipher(algorithms.AES(key), mode, backend=default_backend()).decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext
    
def des_encrypt(plaintext, key, mode):
    padder = padding.PKCS7(algorithms.DES3.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.DES3(key), mode, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext

def des_decrypt(ciphertext, key, mode):
    cipher = Cipher(algorithms.DES3(key), mode, backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.DES3.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

def des3_encrypt(plaintext, key, mode):
    padder = padding.PKCS7(algorithms.DES3.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.TripleDES(key), mode, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext

def des3_decrypt(ciphertext, key, mode):
    cipher = Cipher(algorithms.TripleDES(key), mode, backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.DES3.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

def main():
    while True:
        print("Select an encryption technique:")
        print("1. Substitution cipher")
        print("2. Shift Cipher")
        print("3. Permutation Cipher")
        print("4. Simple Transposition")
        print("5. Double Transposition")
        print("6. Vigenere Cipher")
        print("7. AES Encryption")
        print("8. DES Encryption")
        print("9. Triple DES (DES3) Encryption")
        print("0. Exit")

        choice = input("Enter your choice (0-9): ")

        if choice == "0":
            break

        plaintext = input("Enter the message (plaintext): ")

        if len(plaintext) <= 0:
            print("Message should not be empty.")
            continue

        key_option = input("Do you want to enter a custom key? (yes/no): ").lower()

        if key_option == "yes":
            key = input("Enter the encryption key: ")
        else:
            key = None

        mode_option = input("Enter the encryption mode (ECB, CBC, CFB, OFB): ").upper()

        if choice == "1":
            key = int(key) if key is not None else 4
            ciphertext = substitution_cipher(plaintext, key)
        elif choice == "2":
            key = int(key) if key is not None else 3
            ciphertext = shift_cipher(plaintext, key)
        elif choice == "3":
            key = [int(i) for i in key] if key is not None else [4, 3, 2, 1]
            ciphertext = permutation_cipher(plaintext, key)
        elif choice == "4":
            key = int(key) if key is not None else 4
            ciphertext = simple_transposition(plaintext, key)
        elif choice == "5":
            key1 = int(input("Enter the first transposition key: "))
            key2 = int(input("Enter the second transposition key: "))
            ciphertext = double_transposition(plaintext, key1, key2)
        elif choice == "6":
            keyword = input("Enter the Vigenere keyword: ")
            ciphertext = vigenere_cipher(plaintext, keyword)
        elif choice == "7":
            key_size = int(input("Enter the AES key size (16, 24, or 32 bytes): "))
            key = input(f"Enter the AES encryption key ({key_size} bytes in hexadecimal format): ")
            key = bytes.fromhex(key)
            mode = getattr(modes, mode_option, modes.ECB)()
            ciphertext = aes_encrypt(plaintext.encode('utf-8'), key, mode)
        elif choice == "8":
            key = input("Enter the DES encryption key (8 bytes in hexadecimal format): ")
            key = bytes.fromhex(key)
            mode = getattr(modes, mode_option, modes.ECB)()
            ciphertext = des_encrypt(plaintext.encode('utf-8'), key, mode)
        elif choice == "9":
            key_size = int(input("Enter the Triple DES (DES3) key size (16 or 24 bytes): "))
            key = input(f"Enter the Triple DES (DES3) encryption key ({key_size} bytes in hexadecimal format): ")
            key = bytes.fromhex(key)
            mode = getattr(modes, mode_option, modes.ECB)()
            ciphertext = des3_encrypt(plaintext.encode('utf-8'), key, mode)

        print("Encrypted message (ciphertext):", ciphertext.hex() if isinstance(ciphertext, bytes) else ciphertext)

        decrypt_choice = input("Do you want to decrypt the message? (yes/no): ").lower()

        if decrypt_choice == "yes":
            if choice == "1":
                decrypted_text = substitution_cipher(ciphertext, key, decrypt=True)
            elif choice == "2":
                decrypted_text = shift_cipher(ciphertext, key)
            elif choice == "3":
                decrypted_text = permutation_cipher(ciphertext, key)
            elif choice == "4":
                decrypted_text = simple_transposition(ciphertext, key)
            elif choice == "5":
                decrypted_text = double_transposition(ciphertext, key1, key2)
            elif choice == "6":
                decrypted_text = vigenere_cipher(ciphertext, keyword)
            elif choice == "7":
                mode = getattr(modes, mode_option, modes.ECB)()
                decrypted_text = aes_decrypt(bytes.fromhex(ciphertext), key, mode)
            elif choice == "8":
                mode = getattr(modes, mode_option, modes.ECB)()
                decrypted_text = des_decrypt(bytes.fromhex(ciphertext), key, mode)
            elif choice == "9":
                mode = getattr(modes, mode_option, modes.ECB)()
                decrypted_text = des3_decrypt(bytes.fromhex(ciphertext), key, mode)

            print("Decrypted message (plaintext):", decrypted_text.decode('utf-8'))

if __name__ == "__main__":
    main()
