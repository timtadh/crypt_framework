from socket import *
import thread
import sys, re, os, nDDB, qcrypt, keyfile
import authenticator as auth
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from CommGenerics import SocketGeneric
from CommunicationLink import PillowTalkLink

class ServerCommandProcessor(object):
    
    def __init__(self, uid, comm_link, listener, client_handler):
        self.uid = uid
        self.link = comm_link
        self.listener = listener
        self.client_handler = client_handler
        self.users = self.listener.keyfile['users']
    
    def exec_command(self, cmd, msg, sig): pass

class PillowTalkProcessor(ServerCommandProcessor):
    
    def __init__(self, uid, comm_link, listener, client_handler):
        super(PillowTalkProcessor, self).__init__(uid, comm_link, listener, client_handler)
    
    def exec_command(self, cmd, msg, sig):
        
        def message(msg):
            m = self.link.recieved_message(msg)
            self._send(m, self.uid)
            
        def request_auth(msg): 
            self.link.name = msg
            self.link.partner_secret_hash = self.users[self.link.name]['pass_hash']
            self.link.request_auth()
            
        def sign_auth(msg): self.link.sign_auth(msg)
        def verify_auth(msg): 
            if self.link.verify_auth(msg): print 'server verified client'
        
        def verification_result(msg, sig):
            msg = qcrypt.denormalize(msg)
            msg_vr = auth.verify_signature(self.link.secret, self.link.salt, msg, sig)
            vr = bool(int(msg[0]))
            if not msg_vr: return
            if vr: print 'client verified server'
            else: self.link.comm.close()
            
        def request_pub_key(): self.link.request_pub_key()
        def set_pub_key(msg, sig): self.link.set_pub_key(msg, sig)
        def set_aes_key(msg, sig): self.link.set_aes_key(msg, sig)
        
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
            
    def _send(self, mesg, fromCli):
        name = self.listener.get_client(fromCli).name
        u = self.users[name]
        n = u['l_name'] + ', ' + u['f_name']
        msg = n+': '+mesg
        for x in self.client_handler.active_clients:
            try:
                link = self.listener.get_client(x)
                link.send_message(msg)
            except:
                pass
