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
                    self.send_dict(cli, {'type':'sign_auth', 'value':a})
                
                elif d['type'] == 'sign_auth':
                    a = d['value']
                    cli_secret_hash = self.users[login_name]['pass_hash']
                    signed_a = auth.sign_auth(self.secret, self.salt, cli_secret_hash, a)
                    cli = self.cliList[cliNum]
                    self.send_dict(cli, {'type':'verify_auth', 'value':signed_a})
                
                elif d['type'] == 'verify_auth':
                    print 'VERIFY AUTH REACHED'
                    cli = self.cliList[cliNum]
                    if self.authentications.has_key(cliNum):
                        login_name = d['value']['login_name']
                        signed_a = d['value']['signed_a']
                        ran_str = self.authentications[cliNum]
                        vr = auth.verify_auth(self.secret, self.salt, ran_str, signed_a)
                        self.send_dict(cli, {'type':'verification_result', 'value':str(int(vr))})
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
                        self.send_dict(cli, {'type':'verification_result', 'value':'0'})
                
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
                    self.send_dict(cli, {'type':'key', 'value':k, 'signature':signature})
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
                    break
                    
                else:
                    print 'no matching command for current state'