from Tkinter import *
from socket import *
import thread
import sys, re, os, nDDB, qcrypt, keyfile
import authenticator as auth
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

END_MARK = 'STOP'
END_LEN = 4

class output:
    def __init__(self, name='Tim'):
        self.name = name+':\t'

    def setGui(self, gui):
        self.gui = gui

    def setNetwork(self, network):
        self.network = network
        
    def printInfo(self, data):
        self.gui.printText.insert(END, data+'\n')

    def sendInfo(self, data):
        self.network.send(data)

class Gui:
    def __init__(self, root, printer):
        printer.setGui(self)
        self.printer = printer
        self.root = root
        self.root.title('chatter')

        self.printText = Text(self.root)
        self.enterText = Entry(self.root)
        self.exit = Button(self.root, {'text':'Exit', 'command':self.exit})

        self.printText.pack()
        self.enterText.pack()
        self.exit.pack(side=RIGHT)

        self.enterText.bind('<Return>', self.inputText)

    def inputText(self, event):
        printer.sendInfo(self.enterText.get())
        self.enterText.delete(0, END)

    def exit(self):
        network.deactivateClient()
        gui.root.destroy()
        self.root.quit()

class tcpClient:

    def __init__(self, printer, host, port=21567, bufsize=1024):
        printer.setNetwork(self)
        self.HOST = host
        self.PORT = port
        self.BUFSIZE = bufsize
        self.ADDR = (self.HOST, self.PORT)
        self.stop = False
        self.printer = printer
        
        self.keyfile = keyfile.load_client_keyfile(raw_input('key file path: '))
        
        sha256 = SHA256.new()
        sha256.update(os.urandom(64))
        for x in xrange(5000): sha256.update(sha256.digest())
        self.aeskey = sha256.digest()
        
        self.server_secret_hash = self.keyfile['server_secret_hash']
        self.user = self.keyfile['user']
        
        self.password = raw_input('password: ')
        
        #----------------DEBUG----------------#
        # self.pass_hash = self.user['pass_hash']
        # if self.pass_hash != auth.saltedhash_hex(self.password, self.user['salt']): 
            # print "passwords don't match error"
            # sys.exit()
        # else: print 'passwords match'
        #----------------DEBUG----------------#
        
        self.server_key = None

    def connect(self):
        self.tcpCliSock = socket(AF_INET, SOCK_STREAM)
        self.tcpCliSock.connect(self.ADDR)

    def send(self, data):
        if not data: return
        msg = qcrypt.aes_encrypt(data, self.aeskey)
        #signature = auth.sign_msg(self.server_secret_hash, msg)
        signature = 0
        self.send_dict(self.tcpCliSock, {'type':'message', 'value':msg, 'signature':signature})
        #printer.printInfo(data)

    def stopListening(self):
        self.stop = True
        self.send_dict(self.tcpCliSock, {'type':'stop', 'value':None})
        
    def disconnect(self):
        self.tcpCliSock.close()

    def deactivateClient(self):
        self.stopListening()
        self.disconnect()
    
    def read_data(self, sock):
        data = ''
        while data == '':
            try:
                while data[(-3-END_LEN):] != '>~>STOP': data += sock.recv(1024)
            except:
                data = ''
                continue
        data = data[:-1*END_LEN]
        return data
    
    def send_dict(self, sock, msg_dict):
        sock.sendall(nDDB.encode(msg_dict)+END_MARK)
    
    def listen(self, lock=False, stuff=False):
        print 'listening'
        while 1:
            data = self.read_data(self.tcpCliSock)
            print '\n--------'
            print data
            
            if not data: break
            if self.stop: break
            
            d = nDDB.decode(data)
            
            print d
            try:
                if d and d.has_key('type') and d.has_key('value') and d.has_key('signature'):
                    if d['type'] == 'message':
                        signature = d['signature']
                        msg_e = d['value']
                        print msg_e
                        #vr = auth.verify_signature(self.password, self.user['salt'], msg_e, signature)
                        msg = qcrypt.aes_decrypt(msg_e, self.aeskey)
                        print msg
                        self.printer.printInfo(msg)
                    elif d['type'] == 'stop':
                        break
            except:
                continue
            print '--------\n'
        self.disconnect()
        if lock: lock.release()

    def activateClient(self):
        self.connect()
        
        a = None
        self.send_dict(self.tcpCliSock, {'type':'request_auth', 'value':self.user['login_name']})
        while not a:
            data = self.read_data(self.tcpCliSock)
            
            d = nDDB.decode(data)
            
            if d and d.has_key('type') and d.has_key('value') and d['type'] == 'sign_auth':
                a = d['value']
                signed_a = auth.sign_auth(self.password, self.user['salt'], self.server_secret_hash, a)
                d = {'type':'verify_auth', 'value':{'signed_a':signed_a, 'login_name':self.user['login_name']}}
                self.send_dict(self.tcpCliSock, d)
            else:
                self.send_dict(self.tcpCliSock, {'type':'request_auth', 'value':None})
        
        data = self.read_data(self.tcpCliSock)
        
        d = nDDB.decode(data)
        
        if d and d.has_key('type') and d.has_key('value') and d['type'] == 'verification_result':
            print 'asdfaef weawef awef '
            try:
                vr = bool(int(d['value']))
                if not vr: 
                    print 'verification failed'
                    sys.exit()
                print 'server verified client'
            except:
                print 'verification failed'
                sys.exit()
        else:
            print 'wtf'
            sys.exit()
        
        ran_str = os.urandom(64)
        a = auth.create_auth(self.server_secret_hash, ran_str)
        self.send_dict(self.tcpCliSock, {'type':'sign_auth', 'value':a})
        
        data = self.read_data(self.tcpCliSock)
        
        d = nDDB.decode(data)
        
        if d and d.has_key('type') and d.has_key('value') and d['type'] == 'verify_auth':
            print 'about to verify'
            signed_a = d['value']
            vr = auth.verify_auth(self.password, self.user['salt'], ran_str, signed_a)
            self.send_dict(self.tcpCliSock, {'type':'verification_result', 'value':str(int(vr))})
            if not vr: 
                print 'verification failed'
                sys.exit()
            print 'server verified'
        
        # data = ''
        # while data != 'pubkeyset':
            # k = self.pubkey.publickey().__getstate__()
            # k = qcrypt.normalize(nDDB.encode(k))
            # signature = auth.sign_msg(self.server_secret_hash, k)
            # self.send_dict(self.tcpCliSock, {'type':'setpubkey', 'value':k, 'signature':signature})
            # data = self.tcpCliSock.recv(4096)
        
        k = None
        while k is None:
            self.send_dict(self.tcpCliSock, {'type':'getkey', 'value':0})
            data = self.read_data(self.tcpCliSock)
            d = nDDB.decode(data)
            print d
            if d and d.has_key('type') and d.has_key('value') and d['type'] == 'key':
                try:
                    print 'trying to verify message'
                    signature = d['signature']
                    k_dict = d['value']
                    vr = auth.verify_signature(self.password, self.user['salt'], k_dict, signature)
                    print 'verified: ', vr
                    if vr:
                        k_dict = nDDB.decode(qcrypt.denormalize(d['value']))
                        k = RSA.generate(1, os.urandom)
                        k.__setstate__(keyfile.proc_key_dict(k_dict))
                    else:
                        print 'incorrect message signature'
                        k = None
                except:
                    k = None
        
        self.server_key = k
        print k.__getstate__()
        
        data = ''
        while data != 'aeskeyset':
            k = qcrypt.pub_encrypt(self.aeskey, self.server_key)
            signature = auth.sign_msg(self.server_secret_hash, k)
            self.send_dict(self.tcpCliSock, {'type':'setaeskey', 'value':k, 'signature':signature})
            data = self.tcpCliSock.recv(4096)
        
        lock = thread.allocate_lock()
        lock.acquire()
        thread.start_new_thread(self.listen, (lock, True))

printer = output()
network = tcpClient(printer, 'localhost')
network.activateClient()
master = Tk()
gui = Gui(master, printer)

master.mainloop()


