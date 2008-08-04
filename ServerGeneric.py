from socket import *
import thread
import sys, re, os, nDDB, qcrypt, keyfile
import authenticator as auth
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from CommGenerics import SocketGeneric

class GenericServer_Listener(object):
    
    def __init__(self, commGeneric, keyfile, comm_link_class, client_handler_class, cmd_processor_class):
        self.commGeneric = commGeneric
        self.keyfile = keyfile
        self.client_handler_class = client_handler_class
        self.cmd_processor_class = cmd_processor_class
        self.comm_link_class = comm_link_class
        self.clients = {}
    
    def start_listening(self):
        self.commGeneric.listen()
        
        handler = self.client_handler_class(self, self.cmd_processor_class)
        
        print 'waiting for connections...'
        while 1:
            socket_generic = self.commGeneric.accept()
            comm_link = self.comm_link_class(socket_generic, self.keyfile)
            
            uid = self.get_uid()
            self.clients.update({uid:comm_link})
            
            lock = thread.allocate_lock()
            lock.acquire()
            thread.start_new_thread(handler.handle, (uid, comm_link, lock))
    
    def get_uid(self):
        uid = None
        while uid == None or self.clients.has_key(uid): uid = qcrypt.normalize(os.urandom(8))
        return uid
    
    def get_client(self, uid):
        if self.clients.has_key(uid): return self.clients[uid]
        else: return None

class GenericServer_ClientHandler(object):
    
    def __init__(self, server_listener, cmd_processor_class):
        self.server_listener = server_listener
        self.active_clients = []
        self.cmd_processor_class = cmd_processor_class
        print cmd_processor_class
    
    def handle(self, uid, comm_link, lock):
        print uid
        self.active_clients.append(uid)
        comm_generic = comm_link.comm
        cmd_proc = self.cmd_processor_class(uid, comm_link, self.server_listener, self)
        
        def syscommands(data):
            try: d = nDDB.decode(data)
            except: return
            if (not (d.has_key('type') or d.has_key('value'))): return 
            
            command = d['type']
            msg = d['value']
            if d.has_key('signature'): sig = d['signature']
            else: sig = None
            
            if command == 'stop':  
                comm_generic.close()
                return
            
            cmd_proc.exec_command(command, msg, sig)
        
        comm_generic.set_proc_syscommand(syscommands)
        
        print 'about to listen'
        while not comm_generic.closed:
            try:
                cmd, msg, sig = comm_link.recieve()
            except Exception, e:
                print e
        
        for i, item in enumerate(self.active_clients):
            if item == uid:
                del self.active_clients[i]
                break
        
        print 'disconnected from: ', comm_generic.ADDR
        lock.release()

class ServerGeneric(object):
    
    def __init__(self, commGeneric, keyfile, comm_link_class, listener_class, client_handler_class, cmd_processor_class):
        self.listener = listener_class(commGeneric, keyfile, comm_link_class, client_handler_class, cmd_processor_class)
        self.keyfile = keyfile
        
    def startServer(self): self.listener.start_listening()

