from Tkinter import *
from socket import *
import thread
import sys, re, os, nDDB, qcrypt, keyfile
import authenticator as auth
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from CommGenerics import SocketGeneric

class ClientGeneric(object):

    def __init__(self, commGeneric, keyfile, comm_link_class, activationScript, recieveFunc=None):
        self.stop = False
        self.activate = activationScript
        self.keyfile = keyfile
        
        self.commGeneric = commGeneric
        self.link = comm_link_class(self.commGeneric, self.keyfile)
        
        def syscommands(data):
            try: d = nDDB.decode(data)
            except: return
            
            if (not (d.has_key('type') or d.has_key('value'))): return 
            
            command = d['type']
            msg = d['value']
            
            if command == 'stop': self.commGeneric.close()
        
        self.commGeneric.set_proc_syscommand(syscommands)
        
        def defualtPrint(data): print data
        if recieveFunc == None: self.recieve = defualtPrint
        else: self.recieve = recieveFunc
        
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
            cmd, msg, sig = self.link.recieve()
            
            try:
                if cmd == 'message':
                    msg = self.link.recieved_message(msg)
                    self.recieve(msg)
            except Exception, e:
                print e
                continue
        #self.disconnect()
        if lock: lock.release()
        self.exit()
    
    def activateClient(self):
        self.connect()
        
        self.activate(self)
        
        lock = thread.allocate_lock()
        lock.acquire()
        thread.start_new_thread(self.listen, (lock, True))
