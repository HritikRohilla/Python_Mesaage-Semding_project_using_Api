import time
import requests
import json
from tkinter import *
from tkinter.messagebox import showinfo, showerror


def send_sms(number, message):
    url = 'https://www.fast2sms.com/dev/bulkV2?'
    params = {
        'authorization': 'uMz5HFpjokWEJ6D0U2Pn4KGl7Rdxy8VYTvXAmbfe39thqcZBr1WwZDzgaj6NTU7SJ9VfqAvtuhsGdxYk',
        'sender_id': 'TXTIND',
        'message': message,
        'language': 'english',
        'route': 'v3',
        'numbers': number
    }
    response = requests.get(url, params=params)
    dic = response.json()
    print(dic)
    return dic.get('return')


def btn_click():
    num = textNumber.get()
    msg = textMsg.get("1.0", END)
    r = send_sms(num, msg)
    if r:
        showinfo("Send Success", "Successfully sent")
    else:
        showerror("Error", "Something went wrong..")



root = Tk()
root.title("Message Encryption and Decryption")

root.geometry("1800x800")
root.config(bg='BLACK')

Tops = Frame(root, width=600, relief=SUNKEN, bg='black')
Tops.pack(side=TOP)

f1 = Frame(root, width=600, height=600, relief=SUNKEN, bg='black')
f1.pack(side=LEFT)

localtime = time.asctime(time.localtime(time.time()))

lblInfo = Label(Tops, font=('Times new roman', 35, 'bold'),
                text="MESSAGE ENCRYPTING, DECRYPTING AND SENDING ", fg="red", bd=10, anchor='w', bg='black')

lblInfo.grid(row=0, column=0)

# message code

font = ("Helvetica", 22, "bold")
textNumber = Entry(root, font=font,bg="powder blue")
textNumber.pack(fill=X, pady=20)
textMsg = Text(root,bg="powder blue")
textMsg.pack(fill=X)
sendBtn = Button(root, text="SEND SMS", command=btn_click)
sendBtn.pack()

###------------####

lblInfo = Label(Tops, font=('Times new roman', 20, 'bold'),
                text=localtime, fg="yellow",
                bd=20, anchor='w', bg='black')

lblInfo.grid(row=1, column=0)

rand = StringVar()
Msg = StringVar()
key = StringVar()
mode = StringVar()
Result = StringVar()



def qExit():
    root.destroy()


def Reset():
    rand.set("")
    Msg.set("")
    key.set("")
    mode.set("")
    Result.set("")



lblReference = Label(f1, font=('arial', 16, 'bold'),
                     text="Name:", bd=16, anchor="w", fg='purple', bg='black')

lblReference.grid(row=0, column=0)

txtReference = Entry(f1, font=('times new roman', 16, 'bold'),
                     textvariable=rand, bd=10, insertwidth=4,
                     bg="powder blue", justify='right')

txtReference.grid(row=0, column=1)


lblMsg = Label(f1, font=('arial', 16, 'bold'),
               text="MESSAGE", bd=16, anchor="w", bg='black', fg='purple')

lblMsg.grid(row=1, column=0)

txtMsg = Entry(f1, font=('arial', 16, 'bold'),
               textvariable=Msg, bd=10, insertwidth=4,
               bg="powder blue", justify='right')

txtMsg.grid(row=1, column=1)

lblkey = Label(f1, font=('arial', 16, 'bold'),
               text="KEY", bd=16, anchor="w", bg='black', fg='purple')

lblkey.grid(row=2, column=0)

txtkey = Entry(f1, font=('arial', 16, 'bold'),
               textvariable=key, bd=10, insertwidth=4,
               bg="powder blue", justify='right')

txtkey.grid(row=2, column=1)

lblmode = Label(f1, font=('arial', 16, 'bold'),
                text="MODE(e for encrypt, d for decrypt)",
                bd=16, anchor="w", bg='black', fg='purple')

lblmode.grid(row=3, column=0)

txtmode = Entry(f1, font=('arial', 16, 'bold'),
                textvariable=mode, bd=10, insertwidth=4,
                bg="powder blue", justify='right')

txtmode.grid(row=3, column=1)

lblService = Label(f1, font=('arial', 16, 'bold'),
                   text="The Result-", bd=16, anchor="w", bg='black', fg='purple')

lblService.grid(row=2, column=2)

txtService = Entry(f1, font=('arial', 16, 'bold'),
                   textvariable=Result, bd=10, insertwidth=4,
                   bg="powder blue", justify='right')

txtService.grid(row=2, column=3)


import base64


def encode(key, clear):
    enc = []

    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) +
                     ord(key_c)) % 256)

        enc.append(enc_c)

    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []

    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) -
                     ord(key_c)) % 256)

        dec.append(dec_c)
    return "".join(dec)



def Ref():
    print("Message= ", (Msg.get()))

    clear = Msg.get()
    k = key.get()
    m = mode.get()

    if (m == 'e'):
        Result.set(encode(k, clear))
    else:
        Result.set(decode(k, clear))




btnTotal = Button(f1, padx=16, pady=8, bd=16, fg="black",
                  font=('arial', 16, 'bold'), width=10,
                  text="Show Message", bg="powder blue",
                  command=Ref).grid(row=7, column=1)


btnReset = Button(f1, padx=16, pady=8, bd=16,
                  fg="black", font=('arial', 16, 'bold'),
                  width=10, text="Reset", bg="green",
                  command=Reset).grid(row=7, column=2)


btnExit = Button(f1, padx=16, pady=8, bd=16,
                 fg="black", font=('arial', 16, 'bold'),
                 width=10, text="Exit", bg="red",
                 command=qExit).grid(row=7, column=3)



root.mainloop()
