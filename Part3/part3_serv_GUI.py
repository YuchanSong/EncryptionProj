import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from datetime import datetime
from final_termp.Part3.PGP_All_Common import *
from threading import Thread
from select import *
from tkinter import messagebox

# init
server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 투표자 리스트와 투표참여 리스트
idList = ['uchan']
votedList = []

# 투표 결과 생성을 위한 글로벌 변수 선언 및 초기화
# global candidate1, candidate2, candidate3
candidate1, candidate2, candidate3 = 0, 0, 0

def recv_file():
    bob_privatekey = './HybridBob/bobprivatekey.txt'
    bob_publickey = './HybridBob/bobpublickey.txt'
    alice_publickey = './HybridBob/received_alicepublickey.txt'

    PGP_Generate_Key_File(bob_privatekey, bob_publickey)
    PGP_Client_Receive_File('localhost', 6000, alice_publickey)
    PGP_Server_Send_File('localhost', 7000, bob_publickey)

    bob_received_output_b64 = './HybridBob/received_outputAlice_b64.txt'  # Alice에게 B64로 인코딩한 파일 수신
    PGP_Client_Receive_File('localhost', 8000, bob_received_output_b64)

    bob_received_output = './HybridBob/received_outputAlice.txt'
    B64Decoding(bob_received_output_b64, bob_received_output)  # B64로 디코딩

    bob_received_sig_MSG_alice = './HybridBob/sig_MSG_Alice.txt'
    Generate_AES_Dec_For_DigSig_Plus_Key(bob_received_output, bob_privatekey, bob_received_sig_MSG_alice)
    bob_received_plaintext = './HybridBob/received_plaintext.txt'
    return Verify_DigSig_On_Hashed_File(bob_received_sig_MSG_alice, alice_publickey, bob_received_plaintext)

def serv_start():
    state.configure(text='Server : Running!', foreground='red')
    time = datetime.today().strftime("%Y-%m-%d %H:%M:%S\n")
    scr.insert(tk.INSERT, '서버가 실행되었습니다. ' + time)
    # _thread.start_new_thread(connect_handle, ())
    t1 = Thread(target=connect_handle, args=())
    t1.daemon = True
    t1.start()

def connect_handle():
    HOST = 'localhost'
    PORT = 12345
    ADDR = (HOST, PORT)

    server_sock.bind(ADDR)
    server_sock.listen(10)
    connection_list = [server_sock]
    print('Server started')

    while connection_list:
        try:
            print('Waiting for client')

            # select 로 요청을 받고, 10초마다 블럭킹을 해제하도록 함
            read_socket, write_socket, error_socket = select(connection_list, [], [], 10)

            for sock in read_socket:
                # 새로운 접속
                if sock == server_sock:
                    client_sock, addr = server_sock.accept()
                    connection_list.append(client_sock)
                    t2 = Thread(target=client_handle, args=(client_sock,))
                    t2.daemon = True
                    t2.start()
        except:
            break

def client_handle(client_sock):
    BUF_SIZE = 1024

    data = client_sock.recv(BUF_SIZE) # 이름 수신

    if data.decode() in idList: # 아이디가 있으면
        print('OK')
        client_sock.send('OK'.encode())
        result, plaintext = recv_file()
        if result == 'True':
            client_sock.send('투표 성공'.encode())
            votedList.append(data.decode())
            idList.remove(data.decode())

            global candidate1, candidate2, candidate3

            if plaintext.decode()[-1] == '1': candidate1 += 1
            elif plaintext.decode()[-1] == '2': candidate2 += 1
            else: candidate3 += 1

            scr.insert(tk.INSERT, "Signature Verification Result :" + result + '\n')
            scr.insert(tk.INSERT, 'Decrypted message => ' + plaintext.decode() + '\n')
        else:
            client_sock.send('투표 실패'.encode())

    elif data.decode() in votedList: # 이미 투표했으면
        client_sock.send('이미 투표하셨습니다.'.encode())
    else: # 아이디가 없으면
        client_sock.send('존재하지 않는 아이디입니다.'.encode())

def serv_end():
    server_sock.close()
    state.configure(text='Server : Stopped')
    time = datetime.today().strftime("%Y-%m-%d %H:%M:%S\n")
    scr.insert(tk.INSERT, '서버가 종료 되었습니다. ' + time)
    print('Server Close')
    messagebox.showinfo('투표 결과', '총 투표 인원 : ' + str(len(votedList)) + '명\n' +
                        '      1번 : ' + str(candidate1) + '표      \n' +
                        '      2번 : ' + str(candidate2) + '표      \n' + '      3번 : ' + str(candidate3) + '표      \n')
    exit(0)

def voterCheck():
    messagebox.showinfo('명단', '총 인원 : ' + str(len(idList)) + '\n' + ', '.join(idList))

def voterAddGUI():
    window = tk.Toplevel(win)

    window.title('ADD')

    # Disable x-dimension, disable y-dimension
    window.resizable(False, False)

    # Adding a Label
    ttk.Label(window, text='          ').grid(column=0, row=0)
    ttk.Label(window, text='아이디').grid(column=1, row=1)
    ttk.Label(window, text='          ').grid(column=5, row=3)

    # Adding a Text box - Name
    id_enterd = ttk.Entry(window, width=15, textvariable=id)
    id_enterd.grid(columnspan=2, column=2, row=1)
    ttk.Label(window, text='').grid(column=0, row=3)

    # Adding a Button
    send = ttk.Button(window, text='추가하기', width=10, command=voterAdd)
    send.grid(column=4, row=1)

    # Place cursor into ID Entry
    id_enterd.focus()

def voterAdd():
    userID = id.get()
    if userID not in idList:
        if userID:
            idList.append(id.get())
            messagebox.showinfo('추가', '추가 완료되었습니다.')
        else:
            messagebox.showerror('오류', '아이디를 입력해주세요!')
    else:
        messagebox.showerror('오류', '이미 추가된 ID 입니다.')

def voterRemoveGUI():
    window = tk.Toplevel(win)

    window.title('Remove')

    # Disable x-dimension, disable y-dimension
    window.resizable(False, False)

    # Adding a Label
    ttk.Label(window, text='          ').grid(column=0, row=0)
    ttk.Label(window, text='아이디').grid(column=1, row=1)
    ttk.Label(window, text='          ').grid(column=5, row=3)

    # Adding a Text box - Name
    id_enterd = ttk.Entry(window, width=15, textvariable=id)
    id_enterd.grid(columnspan=2, column=2, row=1)
    ttk.Label(window, text='').grid(column=0, row=3)

    # Adding a Button
    send = ttk.Button(window, text='제거하기', width=10, command=voterRemove)
    send.grid(column=4, row=1)

    # Place cursor into ID Entry
    id_enterd.focus()

def voterRemove():
    userID = id.get()
    if userID in idList:
        idList.remove(id.get())
        messagebox.showinfo('제거', '제거 완료되었습니다.')
    else:
        if userID:
            messagebox.showerror('오류', '존재하지 않는 ID 입니다.')
        else:
            messagebox.showerror('오류', '아이디를 입력해주세요!')

def develop_info():
    window = tk.Toplevel(win)

    window.title('info')

    window.geometry('190x120')
    # Disable x-dimension, disable y-dimension
    window.resizable(False, False)

    # Adding a Label
    ttk.Label(window, text='          ').grid(column=0, row=0)
    ttk.Label(window, text='Hanshin University').grid(columnspan=3, column=1, row=1)
    ttk.Label(window, text='과목명').grid(column=1, row=2)
    ttk.Label(window, text='보안프로래밍').grid(column=2, row=2)
    ttk.Label(window, text='제작자').grid(column=1, row=4)
    ttk.Label(window, text='송유찬').grid(column=2, row=4)
    ttk.Label(window, text='제작일').grid(column=1, row=5)
    ttk.Label(window, text='2018.12.15').grid(column=2, row=5)
    ttk.Label(window, text='          ').grid(column=5, row=6)

# Create instance
win = tk.Tk()
state = ttk.Label(win) # state 문구
scr = scrolledtext.ScrolledText(win) # 스크롤바
id = tk.StringVar() # ID 변수

# Add a title
win.title('Server')

# Disable x-dimension, disable y-dimension
win.resizable(False, False)

# create menu bar
menubar=tk.Menu(win)
menu_1=tk.Menu(menubar, tearoff=0)
menubar.add_cascade(label="투표관리", menu=menu_1)
menu_1.add_command(label="투표 인원 확인하기", command=voterCheck)
menu_1.add_separator()
menu_1.add_command(label="투표 인원 추가하기", command=voterAddGUI)
menu_1.add_command(label="투표 인원 제거하기", command=voterRemoveGUI)

menu_2=tk.Menu(menubar, tearoff=0)
menubar.add_cascade(label="개발정보", menu=menu_2)
menu_2.add_command(label="확인", command=develop_info)

win.config(menu=menubar)

# Adding a Label
style = ttk.Style()
style.configure('BW.TLabel', foreground='black')
space1 = ttk.Label(win, text='').grid(column=0,row=0)
state.configure(text='Server : Stopped', style='BW.TLabel')
state.grid(columnspan=3, row=1)
space2 = ttk.Label(win, text='').grid(column=0,row=2)

# action = ttk.Button(win, text='Do with Key0', command=run)
start = ttk.Button(win, text='선거 시작', width=20, command=serv_start)
start.grid(columnspan=2, row=1)

# Adding Election End Button
end = ttk.Button(win, text='선거 종료', width=20, command=serv_end)
end.grid(column=2, row=1)

# Using a scrolled Text control
scroll_w = 80
scroll_h = 18
scr.config(width=scroll_w, height=scroll_h, wrap=tk.WORD)
scr.grid(column=0, columnspan=3)

# Start GUI
win.mainloop()
