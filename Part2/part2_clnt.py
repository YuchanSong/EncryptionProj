import socket
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# init
ServerHOST = 'localhost'
ServerPORT = 12345
ServerADDR = (ServerHOST, ServerPORT)
BUF_SIZE = 1024

# socket create & connect
client_sock = socket.socket()
client_sock.connect(ServerADDR)
print('Connection Complete')

# 1. 서버에서 공개 키(문자열) 수신 및 문자열을 키로 변환
print("*"*10 + "1. Receive Public Key" + "*"*10)
server_string = client_sock.recv(BUF_SIZE)
server_public_key = RSA.importKey(server_string)
print(server_public_key.exportKey())

# 2. 암호화 한 메시지 + 해시 값 서버로 전송
print("*"*10 + "2. Send Encrypted Message & hash" + "*"*10)
message = input('> Enter message : ')
encrypted = server_public_key.encrypt(message.encode(), 32) # 공개키로 암호화
client_sock.send(encrypted[0])  # 서버로 암호화 된 메시지 전송
hash = SHA256.new(message.encode()).digest() # 메시지에 대한 hash 값 생성
client_sock.send(hash) # 서버로 hash 값 전송

# 3. 결과 확인
print("*"*10 + "3. Result" + "*"*10)
recv_data = client_sock.recv(BUF_SIZE)
print('Server :', recv_data.decode())

# close
client_sock.close()