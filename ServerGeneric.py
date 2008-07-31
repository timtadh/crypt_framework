from socket import *
import thread
import sys, re, os, nDDB, qcrypt, keyfile
import authenticator as auth
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from CommGenerics import SocketGeneric
from network import CommunicationLink

class GenericServer_Listener(object):
    
    def __init__(self, commGeneric, keyfile, client_handler):
        self.commGeneric = commGeneric
        self.keyfile = keyfile
        self.secret = qcrypt.denormalize(self.keyfile['secret'])
        self.salt = self.keyfile['salt']
        self.pri_key = RSA.generate(1, os.urandom)
        self.pri_key.__setstate__(self.keyfile['key'])
        self.users = self.keyfile['users']
        self.client_handler = client_handler
        self.clients = {}
    
    def start_listening(self):
        self.commGeneric.listen()
        
        handler = self.client_handler(self)
        
        print 'waiting for connections...'
        while 1:
            socket_generic = self.commGeneric.accept()
            comm_link = CommunicationLink(socket_generic, self.secret, self.salt, None)
            comm_link.pri_key = self.pri_key
            
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
    
    def __init__(self, server_listener):
        self.server_listener = server_listener
        self.active_clients = []
    
    def handle(self, uid, comm_link, lock):
        print uid
        self.active_clients.append(uid)
        comm_generic = comm_link.comm
        
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
            
            self.exec_command(uid, command, msg, sig)
        
        comm_generic.set_proc_syscommand(syscommands)
        
        while not comm_generic.closed:
            try:
                data = comm_generic.recieve()
            except Exception, e:
                print e
        
        for i, item in enumerate(self.active_clients):
            if item == uid:
                del self.active_clients[i]
                break
        
        print 'disconnected from: ', comm_generic.ADDR
        lock.release()
    
    def _send(self, mesg, fromCli):
        name = self.server_listener.get_client(fromCli).name
        u = self.server_listener.users[name]
        n = u['l_name'] + ', ' + u['f_name']
        msg = n+': '+mesg
        for x in self.active_clients:
            try:
                link = self.server_listener.get_client(x)
                link.send_message(msg)
            except:
                pass
            
    def exec_command(self, uid, cmd, msg, sig=None):
        link = self.server_listener.get_client(uid)
        comm_generic = link.comm
        
        def message(msg):
            m = link.recieved_message(msg)
            self._send(m, uid)
            
        def request_auth(msg): 
            link.name = msg
            link.partner_secret_hash = self.server_listener.users[link.name]['pass_hash']
            link.request_auth()
            
        def sign_auth(msg): link.sign_auth(msg)
        def verify_auth(msg): 
            if link.verify_auth(msg): print 'server verified client'
        
        def verification_result(msg, sig):
            msg = qcrypt.denormalize(msg)
            msg_vr = auth.verify_signature(link.secret, link.salt, msg, sig)
            vr = bool(int(msg[0]))
            if not msg_vr: return
            if vr: print 'client verified server'
            else: comm_generic.close()
            
        def request_pub_key(): link.request_pub_key()
        def set_pub_key(msg, sig): link.set_pub_key(msg, sig)
        def set_aes_key(msg, sig): link.set_aes_key(msg, sig)
        
        if not locals().has_key(cmd): return
        cmd = locals()[cmd]
        
        try:
            if 'sig' in cmd.func_code.co_varnames and 'msg' in cmd.func_code.co_varnames: cmd(msg, sig)
            elif 'msg' in cmd.func_code.co_varnames: cmd(msg)
            else: cmd()
        except Exception, e:
            print '-----------ERROR-----------\n'
            print 'error: ', e
            print 'Error proccessing: ', cmd
            print 'Message: ', msg
            print 'Sig: ', sig
            print '\n-----------ERROR-----------'

class ServerGeneric(object):
    
    def __init__(self, commGeneric, keyfile, listener, client_handler):
        self.listener = listener(commGeneric, keyfile, client_handler)
        self.keyfile = keyfile
        
    def startServer(self): self.listener.start_listening()

