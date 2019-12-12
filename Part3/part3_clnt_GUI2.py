import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from final_termp.Part3.PGP_All_Common import *

# Create instance
win = tk.Tk()

# Add a title
win.title('Client')

# Disable x-dimension, disable y-dimension
win.resizable(0, 0)

def send_file():
    alice_privatekey = './HybridAlice/aliceprivatekey.txt'
    alice_publickey = './HybridAlice/alicepublickey.txt'
    bob_publickey = './HybridAlice/received_bobpublickey.txt'

    PGP_Generate_Key_File(alice_privatekey, alice_publickey)
    PGP_Server_Send_File('localhost', 6000, alice_publickey)
    PGP_Client_Receive_File('localhost', 7000, bob_publickey)

    alice_plaintext = './HybridAlice/plaintext.txt'
    sig_MSG_alice = './HybridAlice/sig_MSG_Alice.txt'
    Generate_DigSig_On_Hashed_File(alice_plaintext, alice_privatekey, sig_MSG_alice)

    alice_output = './HybridAlice/outputAlice.txt'
    Generate_AES_Enc_On_DigSig_Plus_Key(sig_MSG_alice, bob_publickey, alice_output)

    alice_output_b64 = './HybridAlice/outputAlice_b64.txt'
    B64Encoding(alice_output, alice_output_b64)
    PGP_Server_Send_File('localhost', 8000, alice_output_b64)


def send():
    BUF_SIZE = 1024

    # 아이디가 빈칸일때 메시지
    if id.get() == '':
        messagebox.showerror('오류', '아이디를 입력해주세요!')
    else:
        MsgBox = messagebox.askquestion("투표 확인", "투표 하시겠습니까?")
        if MsgBox == 'yes':
            # init
            ServerHOST = 'localhost'
            ServerPORT = 12345
            ServerADDR = (ServerHOST, ServerPORT)

            # socket create & connect
            client_sock = socket.socket()
            client_sock.connect(ServerADDR)
            print('Connection Complete')

            client_sock.send(id.get().encode()) # 이름 송신
            data = client_sock.recv(BUF_SIZE) # 이름 있는지 결과

            if (data.decode() == 'OK'):
                # id + radio send
                msg = id_enterd.get() + ':' + str(RadioVar.get())

                # 투표결과를 plaintext로 저장
                alice_plaintext = './HybridAlice/plaintext.txt'
                f1 = open(alice_plaintext, 'w')
                f1.write(msg)
                f1.close()

                send_file()

                data = client_sock.recv(BUF_SIZE) # 투표 결과 송신
                messagebox.showinfo("투표 결과", data.decode())
                client_sock.close()
            else:
                messagebox.showerror("오류", data.decode())
                client_sock.close()
        else:
            messagebox.showinfo("투표", "잘 생각하고 투표해주세요!")

# Adding a Label
ttk.Label(win, text='          ').grid(column=0, row=0)
ttk.Label(win, text='아이디').grid(column=1, row=1)
ttk.Label(win, text='          ').grid(column=4, row=3)

# Adding a Text box - Name
id = tk.StringVar()
id_enterd = ttk.Entry(win, width=15, textvariable=id)
id_enterd.grid(columnspan=2, column=2, row=1)
ttk.Label(win, text='').grid(column=0, row=3)

# Creating radioButton
RadioVar = tk.IntVar()
r_enc = tk.Radiobutton(win, text='후보1', value=1, variable=RadioVar)
r_enc.grid(column=1, row=4, sticky=tk.W)
r_enc.select()

r_dec = tk.Radiobutton(win, text='후보2', value=2, variable=RadioVar)
r_dec.grid(column=2, row=4, sticky=tk.W)

r_no = tk.Radiobutton(win, text='무효표', value=3, variable=RadioVar)
r_no.grid(column=3, row=4, sticky=tk.W)

ttk.Label(win, text='').grid(column=0, row=5)

# Adding a Button
send = ttk.Button(win, text='투표하기', width=10, command=send)
send.grid(column=2, row=6)
ttk.Label(win, text='').grid(column=0, row=7)

# Place cursor into ID Entry
id_enterd.focus()

# Start GUI
win.mainloop()