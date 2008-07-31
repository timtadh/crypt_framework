from Tkinter import *
from socket import *
import thread
import sys, re, os, nDDB, qcrypt, keyfile
import authenticator as auth
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from CommGenerics import SocketGeneric
from network import CommunicationLink

END_MARK = 'STOP'
END_LEN = 4

class output:
    def __init__(self, name='Tim'):
        self.name = name+':\t'

    def setGui(self, gui):
        self.gui = gui

    def setTcpClient(self, tcp_client):
        self.tcp_client = tcp_client
        
    def printInfo(self, data):
        self.gui.printText.insert(END, data+'\n')

    def sendInfo(self, data):
        self.tcp_client.send(data)

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
        try:
            gui.root.destroy()
            self.root.quit()
        except:
            pass

class tcpClient:

    def __init__(self, printer, host, port=21567, bufsize=1024):
        printer.setTcpClient(self)
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
        
        
        self.sockg = SocketGeneric(host, port, bufsize)
        self.link = CommunicationLink(self.sockg, self.password, self.user['salt'], self.server_secret_hash)
        
        def syscommands(data):
            try: d = nDDB.decode(data)
            except: return
            
            if (not (d.has_key('type') or d.has_key('value'))): return 
            
            command = d['type']
            msg = d['value']
            
            if command == 'stop': self.sockg.close()
        
        self.sockg.set_proc_syscommand(syscommands)
        
        #----------------DEBUG----------------#
        # self.pass_hash = self.user['pass_hash']
        # if self.pass_hash != auth.saltedhash_hex(self.password, self.user['salt']): 
            # print "passwords don't match error"
            # sys.exit()
        # else: print 'passwords match'
        #----------------DEBUG----------------#
        
        self.server_key = None

    def connect(self):
        self.sockg.connect()

    def send(self, data):
        if not data: return
        self.link.send_message(data)

    def stopListening(self):
        self.stop = True
        self.sockg.send_dict({'type':'stop', 'value':None})
        
    def disconnect(self):
        self.sockg.close()

    def deactivateClient(self):
        self.stopListening()
        self.disconnect()
    
    def listen(self, lock=False, stuff=False):
        print 'listening'
        while not self.sockg.closed and self.link.authenticated and self.link.key_agreement:
            cmd, msg, sig = self.unpack_data(self.sockg.recieve())
            
            try:
                if cmd == 'message':
                    msg = self.link.recieved_message(msg)
                    self.printer.printInfo(msg)
            except Exception, e:
                print e
                continue
        #self.disconnect()
        if lock: lock.release()
        try:
            gui.root.destroy()
            gui.root.quit()
            sys.exit()
        except: pass
    
    def unpack_data(self, data):
        d = nDDB.decode(data)
        if (not (d.has_key('type') or d.has_key('value'))): return None, None, None
        if d.has_key('signature'): return d['type'], d['value'], d['signature']
        return d['type'], d['value'], None
    
    def activateClient(self):
        self.connect()
        
        while not (self.sockg.closed or self.link.authenticated):
            self.link.begin_auth(self.user['login_name'])
            cmd, msg, sig = self.unpack_data(self.sockg.recieve())
            if cmd != 'sign_auth': continue
            self.link.sign_auth(msg)
            cmd, msg, sig = self.unpack_data(self.sockg.recieve())
            if cmd != 'verification_result': continue
            msg = qcrypt.denormalize(msg)
            msg_vr = auth.verify_signature(self.link.secret, self.link.salt, msg, sig)
            vr = bool(int(msg[0]))
            if not msg_vr: continue
            if vr: print 'server verified client'
            else: 
                cli_sockg.close()
                sys.exit()
            
            self.link.request_auth()
            cmd, msg, sig = self.unpack_data(self.sockg.recieve())
            if cmd != 'verify_auth': continue
            vr = self.link.verify_auth(msg)
            if not vr:
                cli_sockg.close()
                sys.exit()
            print 'client verified server'
        
        while not self.sockg.closed and self.link.authenticated and not self.link.pub_key:
            self.sockg.send_dict({'type':'request_pub_key', 'value':None})
            cmd, msg, sig = self.unpack_data(self.sockg.recieve())
            if cmd != 'set_pub_key': continue
            self.link.set_pub_key(msg, sig)
        
        if not self.link.authenticated and not self.link.pub_key: return
            
        while not self.sockg.closed and self.link.key_agreement == False:
            self.link.send_new_aes_key()
            cmd, msg, sig = self.unpack_data(self.sockg.recieve())
            if cmd != 'confirm_aeskey': continue
            self.link.confirm_aes_key_set(msg, sig)
        
        lock = thread.allocate_lock()
        lock.acquire()
        thread.start_new_thread(self.listen, (lock, True))

printer = output()
network = tcpClient(printer, 'localhost')
network.activateClient()
master = Tk()
gui = Gui(master, printer)

master.mainloop()


