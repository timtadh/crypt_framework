# Generic Network Functions

from Crypto.PublicKey import RSA
import authenticator as auth
import qcrypt, os, keyfile, nDDB, sys
from dec_factories import create_existance_check_dec, create_value_check_dec

END_MARK = 'STOP'
END_LEN = 4
AES_SET_MSG = 'AES Key Set'

auth_msg_check = create_existance_check_dec('auth_msg')
pub_key_check = create_existance_check_dec('pub_key')
pri_key_check = create_existance_check_dec('pri_key')
aes_key_check = create_existance_check_dec('aes_key')
partner_secret_hash_check = create_existance_check_dec('partner_secret_hash')
authenticated_exist_check = create_existance_check_dec('authenticated')
authenticated_true_check = create_value_check_dec('authenticated', True)
key_agreement_true_check = create_value_check_dec('key_agreement', True)

class CommunicationLink(object):
    
    def __init__(self, comm, secret, salt, partner_secret_hash):
        self.comm = comm
        self.secret = secret
        self.salt = salt
        self.partner_secret_hash = partner_secret_hash
        self.auth_msg = None
        self.pub_key = None
        self.pri_key = None
        self.authenticated = None
        self.aes_key = None
        self.key_agreement = False
    
    def send(self, msg_type, msg, signature=None):
        if signature: d = {'type':msg_type, 'value':msg, 'signature':signature}
        else: d = {'type':msg_type, 'value':msg}
        try: self.comm.send_dict(d)
        except Exception, e: 
            print e
    
    def begin_auth(self, extra_info=None):
        self.send('request_auth', extra_info)
    
    @partner_secret_hash_check
    def request_auth(self):
        auth_msg = os.urandom(64)
        a = auth.create_auth(self.partner_secret_hash, auth_msg)
        self.send('sign_auth', a)
        self.auth_msg = auth_msg
        return auth_msg
    
    @partner_secret_hash_check
    def sign_auth(self, auth_msg):
        signed_a = auth.sign_auth(self.secret, self.salt, self.partner_secret_hash, auth_msg)
        self.send('verify_auth', signed_a)
    
    @auth_msg_check
    @partner_secret_hash_check
    def verify_auth(self, new_auth_msg):
        vr = auth.verify_auth(self.secret, self.salt, self.auth_msg, new_auth_msg)
        msg = str(int(vr))+os.urandom(7)
        sig = auth.sign_msg(self.partner_secret_hash, msg)
        msg = qcrypt.normalize(msg)
        self.send('verification_result', msg, sig)
        self.authenticated = vr
        return vr
        
    @pri_key_check
    @authenticated_exist_check
    @authenticated_true_check
    @partner_secret_hash_check
    def request_pub_key(self):
        k = self.pri_key.publickey().__getstate__()
        msg = qcrypt.normalize(nDDB.encode(k))
        signature = auth.sign_msg(self.partner_secret_hash, msg)
        self.send('set_pub_key', msg, signature)
    
    @authenticated_exist_check
    @authenticated_true_check
    @partner_secret_hash_check
    def set_pub_key(self, msg, signature):
        vr = auth.verify_signature(self.secret, self.salt, msg, signature)
        if vr:
            k_dict = nDDB.decode(qcrypt.denormalize(msg))
            k = RSA.generate(1, os.urandom)
            k.__setstate__(keyfile.proc_key_dict(k_dict))
        else:
            print 'incorrect message signature'
            k = None
        self.pub_key = k
    
    @authenticated_exist_check
    @authenticated_true_check
    @pub_key_check
    @partner_secret_hash_check
    def send_new_aes_key(self):
        self.aes_key = qcrypt.create_aes_key()
        k = qcrypt.pub_encrypt(self.aes_key, self.pub_key)
        signature = auth.sign_msg(self.partner_secret_hash, k)
        self.send('set_aes_key', k, signature)
        self.key_agreement = False
        return self.aes_key
    
    @pri_key_check
    @authenticated_exist_check
    @authenticated_true_check
    @partner_secret_hash_check
    def set_aes_key(self, msg_e, signature):
        vr = auth.verify_signature(self.secret, self.salt, msg_e, signature)
        if vr:
            k = qcrypt.pub_decrypt(msg_e, self.pri_key)
            self.aes_key = k
            self.key_agreement = True
            msg = qcrypt.aes_encrypt(AES_SET_MSG, self.aes_key)
            signature = auth.sign_msg(self.partner_secret_hash, msg)
            self.send('confirm_aeskey', msg, signature)
        else:
            k = None
            self.send('bad_aeskey', None)
            self.key_agreement = False
            print 'incorrect message signature'
        self.aes_key = k
        return k
    
    @aes_key_check
    @pub_key_check
    @authenticated_exist_check
    @authenticated_true_check
    @partner_secret_hash_check
    def confirm_aes_key_set(self, msg, signature):
        vr = auth.verify_signature(self.secret, self.salt, msg, signature)
        if vr:
            msg_d = qcrypt.aes_decrypt(msg, self.aes_key)
            if msg_d == AES_SET_MSG: self.key_agreement = True
            else: 
                self.key_agreement = False
                self.aes_key = None
        else:
            self.key_agreement = False
            print 'incorrect message signature'
        return self.key_agreement
            
    @aes_key_check
    @key_agreement_true_check
    @authenticated_exist_check
    @authenticated_true_check
    @partner_secret_hash_check
    def send_message(self, msg):
        msg = qcrypt.aes_encrypt(msg, self.aes_key)
        self.send('message', msg)
    
    @aes_key_check
    @key_agreement_true_check
    @authenticated_exist_check
    @authenticated_true_check
    @partner_secret_hash_check
    def recieved_message(self, msg):
        msg_d = qcrypt.aes_decrypt(msg, self.aes_key)
        return msg_d