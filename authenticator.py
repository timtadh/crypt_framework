#Implements a challenge-response authentication scheme

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import qcrypt, os

debug = False

def __saltedhash(string, salt):
    sha256 = SHA256.new()
    sha256.update(string)
    sha256.update(qcrypt.denormalize(salt))
    for x in xrange(100000): 
        sha256.update(sha256.digest())
        if x % 10: sha256.update(salt)
    return sha256

def saltedhash_bin(string, salt):
    return __saltedhash(string, salt).digest()

def saltedhash_hex(string, salt):
    return __saltedhash(string, salt).hexdigest()

def __hash(string):
    sha256 = SHA256.new()
    sha256.update(string)
    for x in xrange(100000): sha256.update(sha256.digest())
    return sha256

def hash_bin(string):
    return __hash(string).digest()

def hash_hex(string):
    return __hash(string).hexdigest()

def create_auth(secret_hash_normalized, random_str):
    if len(random_str)%16 != 0: raise Exception, 'not len(random_str) === 16 mod 16'
    aes = AES.new(qcrypt.denormalize(secret_hash_normalized), AES.MODE_CBC)
    ciphertext = qcrypt.normalize(aes.encrypt(random_str))
    if debug:
        print '\n------create_auth------'
        print secret_hash_normalized
        print ciphertext
        print '-----create_auth-------\n'
    return ciphertext

def sign_auth(secret, salt, secret_hash_normalized, auth_normalized):
    auth = qcrypt.denormalize(auth_normalized)
    aes = AES.new(saltedhash_bin(secret, salt), AES.MODE_CBC)
    plaintext = aes.decrypt(auth)
    aes = AES.new(qcrypt.denormalize(secret_hash_normalized), AES.MODE_CBC)
    ciphertext = qcrypt.normalize(aes.encrypt(plaintext))
    if debug:
        print '\n------sign_auth------'
        print saltedhash_hex(secret, salt)
        print secret_hash_normalized
        print ciphertext
        print '-----sign_auth-------\n'
    return ciphertext

def verify_auth(secret, salt, org_random_str, auth_normalized):
    auth = qcrypt.denormalize(auth_normalized)
    aes = AES.new(saltedhash_bin(secret, salt), AES.MODE_CBC)
    new_random_str = aes.decrypt(auth)
    if debug:
        print '\n------verify_auth------'
        print saltedhash_hex(secret, salt)
        print qcrypt.normalize(org_random_str)
        print qcrypt.normalize(new_random_str)
        print '------verify_auth------\n'
    return bool(org_random_str == new_random_str)

def sign_msg(secret_hash_normalized, msg):
    plaintext, spaces_added = qcrypt._appendSpaces(msg)
    aes = AES.new(qcrypt.denormalize(secret_hash_normalized), AES.MODE_CBC)
    ciphertext = aes.encrypt(plaintext)
    signature = hash_hex(ciphertext)
    return signature

def verify_signature(secret, salt, msg, signature):
    plaintext, spaces_added = qcrypt._appendSpaces(msg)
    aes = AES.new(saltedhash_bin(secret, salt), AES.MODE_CBC)
    ciphertext = aes.encrypt(plaintext)
    new_signature = hash_hex(ciphertext)
    return bool(new_signature == signature)

if __name__ == '__main__':
    debug = True
    
    s_pass = 'leigh'
    c_pass = 'tim'
    s_salt = qcrypt.normalize(os.urandom(32))
    c_salt = qcrypt.normalize(os.urandom(32))
    s_ps_h = saltedhash_hex(s_pass, s_salt)
    c_ps_h = saltedhash_hex(c_pass, c_salt)
    ran_str = os.urandom(32) #should be larger in reality. this is so it fits on my screen
    
    print '\n------random_str------'
    print qcrypt.normalize(ran_str)
    print '------random_str------\n'
    
    a1 = create_auth(c_ps_h, ran_str)
    a2 = sign_auth(c_pass, c_salt, s_ps_h, a1)
    r = verify_auth(s_pass, s_salt, ran_str, a2)
    print r