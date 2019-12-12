from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import base64
import os

BLOCK_SIZE = 16
KEY_SIZE = 32
key = os.urandom(KEY_SIZE)

def AESencrypt(message, key):
    IV = Random.new().read(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CFB, IV)
    return base64.b64encode(IV + cipher.encrypt(message))

def AESdecrypt(encrypted, key):
    temp = base64.b64decode(encrypted)
    IV = temp[:BLOCK_SIZE]
    encryptedMSG = temp[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CFB, IV)
    return cipher.decrypt(encryptedMSG)

def AES_main():
    print('#' * 3 + ' AES ' + '#' * 3)
    print("key :", key)
    print('*' * 10 + 'Input Message' + '*' * 10)
    message = input('> Message : ')

    encrypted = AESencrypt(message, key)
    print("Encrypted :", encrypted)

    decrypted = AESdecrypt(encrypted, key)
    print("Decrypted :", decrypted.decode(), end='\n\n')

if __name__ == '__main__':
    AES_main()
