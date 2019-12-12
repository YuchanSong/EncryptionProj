from Crypto.PublicKey import RSA

key = RSA.generate(1024)  # key_size(1024 bit)

def createKey():
    print('#' * 3 + ' RSA ' + '#' * 3)
    print('*' * 10 + 'Create Key' + '*' * 10)
    print(key)
    public_key = key.publickey()
    print(public_key)
    return public_key

def inputMessage():
    print('*' * 10 + 'Input Message' + '*' * 10)
    plaintext = input('> Message : ')
    return plaintext

def encrypt(plaintext, public_key):
    cipher = public_key.encrypt(plaintext.encode(), 32)  # 뒤는 블럭사이즈
    return cipher

def decrypt(cipher):
    plaintext = key.decrypt(cipher)
    return plaintext

def RSA_main():
    public_key = createKey()
    plaintext = inputMessage()

    encrypted = encrypt(plaintext, public_key)
    print('Encrypted : ', encrypted)

    decrypted = decrypt(encrypted)
    print('Decrypted : ', decrypted.decode())

if __name__ == '__main__':
    RSA_main()
