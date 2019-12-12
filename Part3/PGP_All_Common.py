from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import socket                   # Import socket module
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import base64
from Crypto.Cipher import AES
from Crypto import Random


def PGP_Generate_Key_File(priKey_filename, pubKey_filename, keySize=2048):
    privatekey = RSA.generate(keySize)
    f = open(priKey_filename,'wb')
    f.write(bytes(privatekey.exportKey('PEM'))); f.close()
    publickey = privatekey.publickey()
    f = open(pubKey_filename,'wb')
    f.write(bytes(publickey.exportKey('PEM'))); f.close()
    return


def PGP_Server_Send_File(host_name, port_Num, send_filename):
    port = port_Num  # Reserve a port for your service.
    host = host_name  # ex : 'localhost' Get local machine name
    server_socket = socket.socket()  # Create a socket object
    server_socket.bind((host, port))  # Bind to the port
    server_socket.listen(15)  # Now wait for client connection.
    print('Server listening....')

    while True:
        client_socket, addr = server_socket.accept()  # Establish connection with client.
        print('Got connection from', addr)
        data = client_socket.recv(1024)
        print('Server received', repr(data))

        filename = send_filename  # './HybridAlice/alicepublickey.txt'
        f = open(filename, 'rb')
        l = f.read(1024)
        while (l):
            client_socket.send(l)
            print('Sent ', repr(l))
            l = f.read(1024)
        f.close()
        print('Done sending')
        client_socket.send(b'')
        break
    print("Sent %s file from Server to Client!!" % send_filename)
    client_socket.close()
    server_socket.close()


def PGP_Client_Receive_File(host_name, port_Num, receive_filename):
    port = port_Num  # Reserve a port for your service.
    host = host_name  # ex : 'localhost' Get local machine name
    client_socket = socket.socket()  # Create a socket object
    client_socket.connect((host, port))
    client_socket.send(b"Client OK")

    f = open(receive_filename, 'wb') # './HybridAlice/received_bobpublickey.txt'
    print('file opened')

    while True:
        print('Receiving data...')
        data = client_socket.recv(1024)
        print('Received ', repr(data))
        if not data:
            break
        f.write(data)

    print("Receive %s file from Server to Client!!" % receive_filename)
    f.close()
    client_socket.close()


def Generate_DigSig_On_Hashed_File(input_filename, sender_prikey_filename, output_filename):
    f = open(input_filename, 'rb')  #'./HybridAlice/plaintext.txt'
    plaintext = f.read()
    f.close()
    privatekey = RSA.importKey(open(sender_prikey_filename, 'rb').read())  #'./HybridAlice/aliceprivatekey.txt'
    myhash = SHA.new(plaintext)  # Generate Hash
    signature = PKCS1_v1_5.new(privatekey)  # Signature algo
    sigVal = signature.sign(myhash)  # signature value
    print("Length of Signature: ", len(sigVal))
    print("Signature: ", sigVal)
    output = sigVal + plaintext  ## concatnate message
    f = open(output_filename, 'wb') #'./HybridAlice/sig_MSG_Alice.txt'
    f.write(bytes(output))
    f.close()


def Verify_DigSig_On_Hashed_File(input_filename, receiver_pubkey_filename, output_filename):
    f = open(input_filename, 'rb')
    sig_MSG = f.read()
    f.close()

    publickey = RSA.importKey(open(receiver_pubkey_filename, 'rb').read())
    cipherrsa = PKCS1_v1_5.new(publickey)

    print("Signature: ", sig_MSG[:256])
    print("PlainText: ", sig_MSG[256:])
    f = open(output_filename, 'wb')
    f.write(sig_MSG[256:])
    f.close()
    myhash = SHA.new(sig_MSG[256:])

    result = cipherrsa.verify(myhash, sig_MSG[:256])
    print("Signature Verification Result : ", result)

    return str(result), sig_MSG[256:]


def Generate_AES_Enc_On_DigSig_Plus_Key(sig_MSG_filename, receiver_pubkey_filename, output_filename):
    sessionkey = Random.new().read(32)  # 256 bit
    print("Session Key: ", sessionkey)
    # encryption AES of the message
    f = open(sig_MSG_filename, 'rb')  ### signature.txt || plaintext
    plaintext = f.read()
    f.close()
    iv = Random.new().read(16)  # 128 bit
    print("IV: ", iv)
    obj = AES.new(sessionkey, AES.MODE_CFB, iv)
    ciphertext = iv + obj.encrypt(plaintext)
    print("Cipher: ", ciphertext)

    # encryption RSA of the session key
    publickey = RSA.importKey(open(receiver_pubkey_filename, 'rb').read())
    cipherrsa = PKCS1_OAEP.new(publickey)
    enc_sessionkey = cipherrsa.encrypt(sessionkey)
    print("Length of encrypted session key: ", len(enc_sessionkey))  #### Length of session key: 256 byte
    print("Encrypted Session Key:", enc_sessionkey)
    f = open(output_filename, 'wb')
    f.write(bytes(enc_sessionkey))
    f.write(bytes(ciphertext))
    f.close()



def Generate_AES_Dec_For_DigSig_Plus_Key(sig_MSG_filename, receiver_prikey_filename, output_filename):
    ENC_SESSION_KEY_SIZE = 256  # 256 * 8 = 2048 bit

    f = open(sig_MSG_filename, 'rb')  ### signature.txt || plaintext
    outputAlice = f.read()
    f.close()

    # decryption session key
    privatekey = RSA.importKey(open(receiver_prikey_filename, 'rb').read())
    cipherrsa = PKCS1_OAEP.new(privatekey)

    # 세션키 뽑아내기
    sessionkey = cipherrsa.decrypt(outputAlice[:ENC_SESSION_KEY_SIZE])
    print("Decrypted Session Key: ", sessionkey)
    
    # 암호문 뽑아내기
    ciphertext = outputAlice[ENC_SESSION_KEY_SIZE:]

    # IV 뽑아내기(119Line)
    iv = ciphertext[:16]
    print("Extracted IV: ", iv)

    # 복호화
    obj = AES.new(sessionkey, AES.MODE_CFB, iv)
    plaintext = obj.decrypt(ciphertext[16:])
    f = open(output_filename, 'wb')
    f.write(bytes(plaintext))
    f.close()


def B64Encoding(fromFile, toFile):
    ff = open(fromFile, 'rb')
    l = ff.read(768)   # 3byte * 256 = 768
    tf = open(toFile, 'wb')
    while(l):
        l = base64.b64encode(l)
        tf.write(l)
        l = ff.read(768)
    tf.close()
    ff.close()


def B64Decoding(fromFile, toFile):
    ff = open(fromFile, 'rb')
    l = ff.read(1024)   # 4byte * 256 = 1024
    tf = open(toFile, 'wb')
    while(l):
        l = base64.b64decode(l)
        tf.write(l)
        l = ff.read(1024)
    tf.close()
    ff.close()
