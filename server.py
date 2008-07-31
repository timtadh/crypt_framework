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
        print self.keyfile
        self.key = RSA.generate(1, os.urandom)
        self.key.__setstate__(self.keyfile['key'])
        
        self.secret = qcrypt.denormalize(self.keyfile['secret'])
        self.salt = self.keyfile['salt']
        
        self.users = self.keyfile['users']
        
        self.cliInfo = {}
        self.authentications = {}
        self.authenticated = []

    def startServer(self):
        tcpSerSock = socket(AF_INET, SOCK_STREAM)
        tcpSerSock.bind(self.ADDR)
        tcpSerSock.listen(5)
        
        while 1:
            print 'waiting for connection...'
            self.cliList.append('')
            sock, addr = tcpSerSock.accept()
            socketGen = SocketGeneric('', self.PORT, self.BUFSIZE)
            socketGen.ADDR = addr
            socketGen.HOST = addr[0]
            self.cliList[self.cliList.__len__()-1] = socketGen
            print '...connected to: ', addr

            lock = thread.allocate_lock()
            lock.acquire()
            thread.start_new_thread(self._client, \
                                    ((self.cliList.__len__()-1), addr, lock))
        tcpSerSock.close()

    def _client(self, cliNum, address, lock):
        self.activeCli.append(cliNum)
        cli_sockg = self.cliList[cliNum]
        link = CommunicationLink(cli_sockg, self.secret, self.salt, None)
        
        def syscommands(data):
            try: d = nDDB.decode(data)
            except: return
            
            if (not (d.has_key('type') or d.has_key('value'))): return 
            
            command = d['type']
            msg = d['value']
            
            if command == 'stop':
                if link.authenticated:
                    sig = d['signature']
                    vr = auth.verify_signature(link.secret, link.salt, msg, sig)
                    if not vr: return
                cli_sockg.close()
        
        cli_sockg.set_proc_syscommand(syscommands)
        
        def commands(data):
            try: d = nDDB.decode(data)
            except: return
            
            if (not (d.has_key('type') or d.has_key('value'))): return 
            
            command = d['type']
            msg = d['value']
            
            if command == 'message':
                try:
                    m = link.recieved_message(msg)
                    self._send(m. cliNum)
                except: pass
            
            elif command ==:
                
            
        cli_sockg.set_proc_syscommand(syscommands)
        
        while not cli_sockg.closed:
            data = cli_sockg.recieve()
            print data
                    
        self.cliList[cliNum].close()
        for x in range(self.activeCli.__len__()):
            if self.activeCli[x] == cliNum:
                del self.activeCli[x]
                break
        print 'disconnected from: ', address
        lock.release()

    def _process_msg(self, cliNum, d, lock):
        signature = d['signature']
        msg_e = d['value']
        #vr = auth.verify_signature(self.secret, self.salt, msg_e, signature)
        if 1:
            msg = qcrypt.aes_decrypt(msg_e, self.cliInfo[cliNum]['aeskey'])
            print msg
            self._send(msg, cliNum)
            lock.release()
        else:
            print 'incorrect message signature'
        
    def _sign_msg(self, cliNum, msg):
        return auth.sign_msg(self.users[self.cliInfo[cliNum]['login_name']]['pass_hash'], msg)
    
    def _send(self, mesg, exceptCli=-1):
        for x in self.activeCli:
            try:
                print 'sending', x
                u = self.users[self.cliInfo[exceptCli]['login_name']]
                n = u['l_name'] + ', ' + u['f_name']
                msg = qcrypt.aes_encrypt(n+': '+mesg, self.cliInfo[x]['aeskey'])
                #signature = self._sign_msg(x, msg)
                signature = 0
                print msg
                self.send_dict(self.cliList[x], {'type':'message', 'value':msg, 'signature':signature})
            except:
                pass
            
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

server = tcpServer()
server.startServer()
