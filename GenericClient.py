from Tkinter import *
from socket import *
import thread
import sys, re, os, nDDB, qcrypt, keyfile
import authenticator as auth
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from CommGenerics import SocketGeneric
from network import CommunicationLink

class GenericClient:

    def __init__(self, commGeneric, password, keyfile, externalPrint=None):
        self.stop = False
        
        self.keyfile = keyfile
        self.password = password
        
        self.server_secret_hash = self.keyfile['server_secret_hash']
        self.user = self.keyfile['user']
        
        self.commGeneric = commGeneric
        self.link = CommunicationLink(self.commGeneric, self.password, self.user['salt'], self.server_secret_hash)
        
        def syscommands(data):
            try: d = nDDB.decode(data)
            except: return
            
            if (not (d.has_key('type') or d.has_key('value'))): return 
            
            command = d['type']
            msg = d['value']
            
            if command == 'stop': self.commGeneric.close()
        
        self.commGeneric.set_proc_syscommand(syscommands)
        
        def defualtPrint(data): print data
        if externalPrint == None: self.ext_print = defualtPrint
        else: self.ext_print = externalPrint
        
        self.exit = sys.exit

    def connect(self):
        self.commGeneric.connect()

    def send(self, data):
        if not data: return
        self.link.send_message(data)

    def stopListening(self):
        self.stop = True
        self.commGeneric.send_dict({'type':'stop', 'value':None})
        
    def disconnect(self):
        self.commGeneric.close()

    def deactivateClient(self):
        self.stopListening()
        self.disconnect()
    
    def listen(self, lock=False, stuff=False):
        print 'listening'
        while not self.commGeneric.closed and self.link.authenticated and self.link.key_agreement:
            cmd, msg, sig = self.unpack_data(self.commGeneric.recieve())
            
            try:
                if cmd == 'message':
                    msg = self.link.recieved_message(msg)
                    self.ext_print(msg)
            except Exception, e:
                print e
                continue
        #self.disconnect()
        if lock: lock.release()
        self.exit()
    
    def unpack_data(self, data):
        d = nDDB.decode(data)
        if (not (d.has_key('type') or d.has_key('value'))): return None, None, None
        if d.has_key('signature'): return d['type'], d['value'], d['signature']
        return d['type'], d['value'], None
    
    def activateClient(self):
        self.connect()
        
        while not (self.commGeneric.closed or self.link.authenticated):
            self.link.begin_auth(self.user['login_name'])
            cmd, msg, sig = self.unpack_data(self.commGeneric.recieve())
            if cmd != 'sign_auth': continue
            self.link.sign_auth(msg)
            cmd, msg, sig = self.unpack_data(self.commGeneric.recieve())
            if cmd != 'verification_result': continue
            msg = qcrypt.denormalize(msg)
            msg_vr = auth.verify_signature(self.link.secret, self.link.salt, msg, sig)
            vr = bool(int(msg[0]))
            if not msg_vr: continue
            if vr: print 'server verified client'
            else: 
                cli_commGeneric.close()
                sys.exit()
            
            self.link.request_auth()
            cmd, msg, sig = self.unpack_data(self.commGeneric.recieve())
            if cmd != 'verify_auth': continue
            vr = self.link.verify_auth(msg)
            if not vr:
                cli_commGeneric.close()
                sys.exit()
            print 'client verified server'
        
        while not self.commGeneric.closed and self.link.authenticated and not self.link.pub_key:
            self.commGeneric.send_dict({'type':'request_pub_key', 'value':None})
            cmd, msg, sig = self.unpack_data(self.commGeneric.recieve())
            if cmd != 'set_pub_key': continue
            self.link.set_pub_key(msg, sig)
        
        if not self.link.authenticated and not self.link.pub_key: return
            
        while not self.commGeneric.closed and self.link.key_agreement == False:
            self.link.send_new_aes_key()
            cmd, msg, sig = self.unpack_data(self.commGeneric.recieve())
            if cmd != 'confirm_aeskey': continue
            self.link.confirm_aes_key_set(msg, sig)
        
        lock = thread.allocate_lock()
        lock.acquire()
        thread.start_new_thread(self.listen, (lock, True))
