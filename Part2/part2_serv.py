import socket
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

# init
HOST = 'localhost'
PORT = 12345
ADDR = (HOST, PORT)
BUF_SIZE = 1024

# socket create & bind & accept
server_sock = socket.socket()
server_sock.bind(ADDR)
server_sock.listen(10)
print('Server waiting for connection')
server_sock, addr = server_sock.accept()
print('Connection Client From :', addr)

# 1. 개인 및 공개 키 생성
print("*"*10 + "1. RSA Key Create" + "*"*10)
key = RSA.generate(1024)
public_key = key.publickey()
print(key)

# 2. 암호화를 위한 공개키 송신
print("*"*10 + "2. Send Public Key" + "*"*10)
server_sock.send(public_key.exportKey())
print(public_key.exportKey())

# 3. 암호화 된 message 수신
print("#"*3 + " Waiting for client response... " + "#"*3)
encrypted = server_sock.recv(BUF_SIZE)
print("*"*10 + "3. Receive Encrypted Message" + "*"*10)
print(encrypted)
t = (encrypted,) # 표준화
decrypted = key.decrypt(t) # 복호화

# 4. Data Signature
print("*"*10 + "4. RSA with Signature and Verification" + "*"*10)
client_hash = server_sock.recv(BUF_SIZE) # 클라이언트에게 메시지(원문) hash 값 수신
server_hash = SHA256.new(decrypted).digest() # 서버가 수신한 메시지(원문) hash 값 생성
signature = key.sign(server_hash, '') # 서버 hash 값에 대한 signature 생성
result = public_key.verify(client_hash, signature) # 클라이언트 hash 값과 서버의 hash 값을 비교
print(result)

# 5. 결과 확인
print("*"*10 + "5. Result" + "*"*10)
if result: # hash 값이 일치하면 실행
    print('Client :', decrypted.decode())
    server_sock.send(b'I received well :)')
server_sock.send(b'I received not well :(')

# close
server_sock.close()