from socket import *
import thread
import sys, re, os, nDDB, qcrypt, keyfile
import authenticator as auth
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from CommGenerics import SocketGeneric
from network import CommunicationLink

END_MARK = 'STOP'
END_LEN = 4

class tcpServer:

    def __init__(self, host='', port=21567, bufsize=4096):
        self.HOST = host
        self.PORT = port
        self.BUFSIZE = bufsize
        self.ADDR = (self.HOST, self.PORT)
        self.cliList = []
        self.activeCli = []
        self.hosts = {}
        self.hosts_cliNum = {}
        
        self.keyfile = keyfile.load_server_keyfile('server_key')
        self.key = RSA.generate(1, os.urandom)
        self.key.__setstate__(self.keyfile['key'])
        
        self.secret = qcrypt.denormalize(self.keyfile['secret'])
        self.salt = self.keyfile['salt']
        
        self.users = self.keyfile['users']

    def startServer(self):
        tcpSerSock = socket(AF_INET, SOCK_STREAM)
        tcpSerSock.bind(self.ADDR)
        tcpSerSock.listen(5)
        
        while 1:
            print 'waiting for connection...'
            self.cliList.append('')
            sock, addr = tcpSerSock.accept()
            cli_sockg = SocketGeneric('', self.PORT, self.BUFSIZE)
            cli_sockg.ADDR = addr
            cli_sockg.HOST = addr[0]
            cli_sockg.sock = sock
            link = CommunicationLink(cli_sockg, self.secret, self.salt, None)
            link.pri_key = self.key
            print link.__class__
            self.cliList[self.cliList.__len__()-1] = link
            print '...connected to: ', addr

            lock = thread.allocate_lock()
            lock.acquire()
            thread.start_new_thread(self._client, \
                                    ((self.cliList.__len__()-1), addr, lock))
        tcpSerSock.close()

    def _client(self, cliNum, address, lock):
        try:
            self.activeCli.append(cliNum)
            
            link = self.cliList[cliNum]
            
            print link.__class__
            cli_sockg = link.comm
            
            print 'about to start setup'
            
            def syscommands(data):
                try: d = nDDB.decode(data)
                except: return
                if (not (d.has_key('type') or d.has_key('value'))): return 
                
                command = d['type']
                msg = d['value']
                
                if command == 'stop':  cli_sockg.close()
            
            cli_sockg.set_proc_syscommand(syscommands)
            
            def commands(data):
                try: d = nDDB.decode(data)
                except: return
                if (not (d.has_key('type') or d.has_key('value'))): return 
                
                command = d['type']
                msg = d['value']
                if d.has_key('signature'): sig = d['signature']
                else: sig = None
                
                try:
                    self.exec_command(cliNum, command, msg, sig)
                except Exception, e:
                    print e, e.args, e.message, e.__class__, e.__dict__, e.__doc__
                
            
            cli_sockg.set_proc_command(commands)
            
            print 'commands setup'
        
        except Exception, e:
            print e
        
        while not cli_sockg.closed:
            try:
                data = cli_sockg.recieve()
            except Exception, e:
                print e
        
        for x in range(self.activeCli.__len__()):
            if self.activeCli[x] == cliNum:
                del self.activeCli[x]
                break
        print 'disconnected from: ', address
        lock.release()
    
    def _send(self, mesg, fromCli):
        name = self.cliList[fromCli].name
        for x in self.activeCli:
            try:
                link = self.cliList[x]
                u = self.users[name]
                n = u['l_name'] + ', ' + u['f_name']
                msg = n+': '+mesg
                link.send_message(msg)
            except:
                pass
            
    def exec_command(self, cliNum, cmd, msg, sig=None):
        link = self.cliList[cliNum]
        cli_sockg = link.comm
        
        def message(msg):
            m = link.recieved_message(msg)
            self._send(m, cliNum)
            
        def request_auth(msg): 
            link.name = msg
            link.partner_secret_hash = self.users[link.name]['pass_hash']
            link.request_auth()
            
        def sign_auth(msg): link.sign_auth(msg)
        def verify_auth(msg): 
            if link.verify_auth(msg): print 'server verified client'
        
        def verification_result(msg, sig):
            msg = qcrypt.denormalize(msg)
            msg_vr = auth.verify_signature(self.secret, self.salt, msg, sig)
            vr = bool(int(msg[0]))
            if not msg_vr: return
            if vr: print 'client verified server'
            else: cli_sockg.close()
            
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

server = tcpServer()
server.startServer()
