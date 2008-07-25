from socket import *
import thread
import sys, re, os, nDDB, qcrypt, keyfile
import authenticator as auth
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

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
            self.cliList[self.cliList.__len__()-1], addr = tcpSerSock.accept()
            print '...connected to: ', addr

            lock = thread.allocate_lock()
            lock.acquire()
            thread.start_new_thread(self._client, \
                                    ((self.cliList.__len__()-1), addr, lock))
        tcpSerSock.close()

    def _client(self, cliNum, address, lock):
        self.activeCli.append(cliNum)
        while 1:
            data = ''
            while data[-3:] != '>~>': data += self.cliList[cliNum].recv(self.BUFSIZE)
            print data
            print cliNum, self.authenticated, cliNum in self.authenticated, self.activeCli
            
            if not data: break
            d = nDDB.decode(data)
            
            if d and d.has_key('type') and d.has_key('value'):
                
                if d['type'] == 'message' and cliNum in self.authenticated: 
                    l = thread.allocate_lock()
                    l.acquire()
                    thread.start_new_thread(self._process_msg, (cliNum, d, l))
                
                elif d['type'] == 'request_auth':
                    login_name = d['value']
                    cli_secret_hash = self.users[login_name]['pass_hash']
                    ran_str = os.urandom(64)
                    a = auth.create_auth(cli_secret_hash, ran_str)
                    self.authentications.update({cliNum:ran_str})
                    cli = self.cliList[cliNum]
                    cli.sendall(nDDB.encode({'type':'sign_auth', 'value':a}))
                
                elif d['type'] == 'sign_auth':
                    a = d['value']
                    cli_secret_hash = self.users[login_name]['pass_hash']
                    signed_a = auth.sign_auth(self.secret, self.salt, cli_secret_hash, a)
                    cli = self.cliList[cliNum]
                    cli.sendall(nDDB.encode({'type':'verify_auth', 'value':signed_a}))
                
                elif d['type'] == 'verify_auth':
                    print 'VERIFY AUTH REACHED'
                    cli = self.cliList[cliNum]
                    if self.authentications.has_key(cliNum):
                        login_name = d['value']['login_name']
                        signed_a = d['value']['signed_a']
                        ran_str = self.authentications[cliNum]
                        vr = auth.verify_auth(self.secret, self.salt, ran_str, signed_a)
                        cli.sendall(nDDB.encode({'type':'verification_result', 'value':str(int(vr))}))
                        if vr:
                            print 'client verified'
                            self.authenticated.append(cliNum)
                            if self.cliInfo.has_key(cliNum):
                                self.cliInfo[cliNum]['login_name'] = login_name
                            else:
                                self.cliInfo.update({cliNum:{'pubkey':None, 'aeskey':None, 'login_name':login_name}})
                        else:
                            break
                    else:
                        cli.sendall(nDDB.encode({'type':'verification_result', 'value':'0'}))
                
                elif d['type'] == 'verification_result':
                    try:
                        vr = bool(int(d['value']))
                        if not vr: 
                            print 'verification failed'
                            break
                        print 'client verified server'
                    except:
                        print 'verification failed'
                        break
                
                elif d['type'] == 'getkey' and cliNum in self.authenticated:
                    print 'about to send key'
                    cli = self.cliList[cliNum]
                    k = self.key.publickey().__getstate__()
                    k = qcrypt.normalize(nDDB.encode(k))
                    signature = self._sign_msg(cliNum, k)
                    cli.sendall(nDDB.encode({'type':'key', 'value':k, 'signature':signature}))
                    print 'key sent'
                    
                elif d['type'] == 'setpubkey' and cliNum in self.authenticated:
                    print 'about to try and set pub key'
                    signature = d['signature']
                    k_dict = d['value']
                    vr = auth.verify_signature(self.secret, self.salt, k_dict, signature)
                    print 'verification: ', vr
                    if vr:
                        k_dict = nDDB.decode(qcrypt.denormalize(d['value']))
                        k = RSA.generate(1, os.urandom)
                        k.__setstate__(keyfile.proc_key_dict(k_dict))
                        if self.cliInfo.has_key(cliNum):
                            self.cliInfo[cliNum]['pubkey'] = k
                        else:
                            self.cliInfo.update({cliNum:{'pubkey':k, 'aeskey':None, 'login_name':None}})
                        self.cliList[cliNum].sendall('pubkeyset')
                    else:
                        print 'incorrect message signature'
                    
                
                elif d['type'] == 'setaeskey' and cliNum in self.authenticated:
                    signature = d['signature']
                    msg_e = d['value']
                    vr = auth.verify_signature(self.secret, self.salt, msg_e, signature)
                    if vr:
                        k = qcrypt.pub_decrypt(msg_e, self.key)
                        if self.cliInfo.has_key(cliNum):
                            self.cliInfo[cliNum]['aeskey'] = k
                        else:
                            self.cliInfo.update({cliNum:{'pubkey':None, 'aeskey':k, 'login_name':None}})
                        self.cliList[cliNum].sendall('aeskeyset')
                    else:
                        print 'incorrect message signature'
                    
                    
                elif d['type'] == 'stop':
                    #self.cliList[cliNum].sendall(data)
                    break
                    
                else:
                    print 'no matching command for current state'
                    
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
                self.cliList[x].sendall(nDDB.encode({'type':'message', 'value':msg, 'signature':signature}))
            except:
                pass
            
    

server = tcpServer()
server.startServer()
