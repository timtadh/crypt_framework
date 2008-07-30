# Generic Network Functions

from Crypto.PublicKey import RSA
import authenticator as auth
import qcrypt, os, keyfile

END_MARK = 'STOP'
END_LEN = 4
AES_SET_MSG = 'AES Key Set'

def create_existance_check_dec(attr):
    def dec(f, *args, **kwargs):
        def h(*args, **kwargs):
            if len(args) <= 0: raise Exception, 'must be applied to a class method'
            attrs = dir(args[0])
            if '__dict__' in attrs and args[0].__dict__.has_key(attr):
                if args[0].__dict__[attr] != None:
                    return f(*args, **kwargs)
                else:
                    raise Exception, attr + ' must not be None'
            elif '__contains__' in attrs and args[0].__contains__(attr):
                if args.__getattribute__(attr) != None:
                    return f(*args, **kwargs)
                else:
                    raise Exception, attr + ' must not be None'
            else:
                raise Exception, 'could not detirmine the existance of ' + attr + ' in args[0]'
        return h
    return dec

def create_value_check_dec(attr, desired_value):
    def dec(f, *args, **kwargs):
        '''Assumes that an existance check has already been done'''
        def h(*args, **kwargs):
            attrs = dir(args[0])
            if ('__dict__' in attrs):
                if (args[0].__dict__[attr] != desired_value):  raise Exception, attr + ' must equal ' + desired_value
                return f(*args, **kwargs)
            else:
                if args.__getattribute__(attr) != desired_value: raise Exception, attr + ' must equal ' + desired_value
                return f(*args, **kwargs)
        return h
    return dec

auth_msg_check = create_existance_check_dec('auth_msg')
pub_key_check = create_existance_check_dec('pub_key')
pri_key_check = create_existance_check_dec('pri_key')
aes_key_check = create_existance_check_dec('aes_key')
authenticated_exist_check = create_existance_check_dec('authenticated')
authenticated_true_check = create_value_check_dec('authenticated', True)
key_agreement_true_check = create_value_check_dec('key_agreement', True)

class CommunicationLink(object):
    
    def __init__(self, sock, secret, salt, partner_secret_hash):
        self.sock = sock
        self.secret = secret
        self.salt = salt
        self.partner_secret_hash = partner_secret_hash
        self.auth_msg = None
        self.pub_key = None
        self.pri_key = None
        self.authenticated = None
        self.aes_key = None
        self.key_agreement = False

    def read_data(self):
        data = ''
        while data == '':
            try:
                while data[(-3-END_LEN):] != '>~>STOP': data += self.sock.recv(1024)
            except:
                data = ''
                continue
        data = data[:-1*END_LEN]
        return data
    
    def send_dict(self, msg_dict):
        self.sock.sendall(nDDB.encode(msg_dict)+END_MARK)
    
    def begin_auth(self, extra_info=None):
        self.send_dict({'type':'request_auth', 'value':extra_info})
    
    def request_auth(self):
        auth_msg = os.urandom(64)
        a = auth.create_auth(self.partner_secret_hash, auth_msg)
        self.send_dict({'type':'sign_auth', 'value':a})
        self.auth_msg = auth_msg
        return ran_str
        
    def sign_auth(self, auth_msg):
        signed_a = auth.sign_auth(self.secret, self.salt, self.partner_secret_hash, auth_msg)
        self.send_dict({'type':'verify_auth', 'value':signed_a})
    
    @auth_msg_check
    def verify_auth(self, new_auth_msg):
        vr = auth.verify_auth(self.secret, self.salt, self.auth_msg, new_auth_msg)
        self.send_dict({'type':'verification_result', 'value':str(int(vr))})
        self.authenticated = vr
        return vr
        
    @pri_key_check
    @authenticated_exist_check
    @authenticated_true_check
    def request_pub_key(self):
        k = self.pri_key.publickey().__getstate__()
        msg = qcrypt.normalize(nDDB.encode(k))
        signature = auth.sign_msg(self.users[self.cliInfo[cliNum]['login_name']]['pass_hash'], msg)
        self.send_dict({'type':'key', 'value':msg, 'signature':signature})
    
    @authenticated_exist_check
    @authenticated_true_check
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
    def send_new_aes_key(self):
        self.aes_key = qcrypt.normalize(qcrypt.create_aes_key())
        k = qcrypt.pub_encrypt(self.aes_key, self.pub_key)
        signature = auth.sign_msg(self.partner_secret_hash, k)
        send_dict({'type':'setaeskey', 'value':k, 'signature':signature})
        self.key_agreement = False
        return self.aes_key
    
    @pri_key_check
    @authenticated_exist_check
    @authenticated_true_check
    def set_aes_key(self, msg_e, signature):
        vr = auth.verify_signature(self.secret, self.salt, msg_e, signature)
        if vr:
            k = qcrypt.pub_decrypt(msg_e, self.pri_key)
            self.key_agreement = True
            msg = qcrypt.aes_encrypt(AES_SET_MSG, self.aes_key)
            signature = auth.sign_msg(self.partner_secret_hash, msg)
            send_dict({'type':'confirm_aeskey', 'value':msg, 'signature':signature})
        else:
            k = None
            self.key_agreement = False
            print 'incorrect message signature'
        self.aes_key = k
        return k
    
    @aes_key_check
    @pub_key_check
    @authenticated_exist_check
    @authenticated_true_check
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
