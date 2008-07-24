#Implements a challenge-response authentication scheme

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import qcrypt

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

def create_auth(secret, salt, random_str):
    plaintext, spaces_added = qcrypt._appendSpaces(random_str)
    aes = AES.new(saltedhash_bin(secret, salt), AES.MODE_CBC)
    ciphertext = aes.encrypt(plaintext)
    ciphertext = hash_hex(ciphertext)
    return ciphertext

def sign_auth(secret, salt, auth_normalized):
    auth = qcrypt.denormalize(auth_normalized)
    plaintext, spaces_added = qcrypt._appendSpaces(auth)
    aes = AES.new(saltedhash_bin(secret, salt), AES.MODE_CBC)
    ciphertext = aes.encrypt(plaintext)
    ciphertext = hash_hex(ciphertext)
    print '\n------sign_auth------'
    print saltedhash_hex(secret, salt)
    print ciphertext
    print '-----sign_auth-------\n'
    return ciphertext

def verify_auth(secret_hash_normalized, org_auth_normalized, new_auth_normalized):
    org_auth = qcrypt.denormalize(org_auth_normalized)
    org_auth, spaces_added = qcrypt._appendSpaces(org_auth)
    aes = AES.new(qcrypt.denormalize(secret_hash_normalized), AES.MODE_CBC)
    org_auth = aes.encrypt(org_auth)
    org_auth = hash_hex(org_auth)
    print '\n------verify_auth------'
    print secret_hash_normalized
    print org_auth
    print new_auth_normalized
    print '------verify_auth------\n'
    return bool(org_auth == new_auth_normalized)

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