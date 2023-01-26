import hashlib
from Crypto.Cipher import AES

# Key of AES, can be arbitrary long due to hashing
key = b"MyKeyValue"

input_file = "plaintext.txt"
output_file = "ciphertext.txt"

# Hash the key to get a fixed-length key
hasher = hashlib.sha256()
hasher.update(key)
hashed_key = hasher.digest()

print(f"Key: {key}")
print(f"Hashed key: {hashed_key}")


def encrypt_file_with_key(hashed_key, input_file, output_file):
    # Initialize the cipher
    cipher = AES.new(hashed_key, AES.MODE_EAX)

    # Open the input and output files
    with open(input_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
        # Encrypt the data
        data = in_file.read()
        print(f"  Content of {input_file}:\n{data}")
        ciphertext, tag = cipher.encrypt_and_digest(data)
        print(f"  Encrypted content:\n{ciphertext}")
        [out_file.write(x) for x in (cipher.nonce, tag, ciphertext)]


def decrypt_file_with_key(hashed_key, input_file, output_file):
    # Open the input and output files
    with open(input_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
        # Read nonce, tag and ciphertext from file
        nonce, tag, ciphertext = [in_file.read(x) for x in (16, 16, -1)]
        print(f"  Ciphertext:\n{ciphertext}")
        # Initialize the cipher
        cipher = AES.new(hashed_key, AES.MODE_EAX, nonce)
        # Decrypt the data
        data = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"  Decrypted content:\n{data}")
        out_file.write(data)


encrypt_file_with_key(hashed_key, input_file, output_file)
decrypt_file_with_key(hashed_key, output_file, "deciphered.txt")
