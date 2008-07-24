#Administration tools for eChat

import re, os, nDDB, qcrypt
import authenticator as auth
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

def create_client_user(login_name, f_name, l_name, password, salt_bin, email):
    salt = qcrypt.normalize(salt_bin)
    pass_hash = auth.saltedhash_hex(password, salt)
    d = {'login_name':login_name, 'f_name':f_name, 'l_name':l_name, 'salt':salt, 'email':email}
    return d

def create_server_user(login_name, f_name, l_name, pass_hash, email):
    d = {'login_name':login_name, 'f_name':f_name, 'l_name':l_name, 'pass_hash':pass_hash, 'email':email}
    return d

def create_key():
    key = RSA.generate(4096, os.urandom)
    return key.__getstate__()

def create_secret():
    return qcrypt.normalize(os.urandom(256))
    
def create_server_keyfile(user_list):
    key = create_key()
    secret = create_secret()
    salt = qcrypt.normalize(os.urandom(64))
    user_dict = {}
    for user in user_list:
        user_dict.update({user['login_name']:user})
    d = {'key':key, 'secret':secret, 'salt':salt, 'users':user_dict}
    return d

def create_client_keyfile(server_secret_hash, user):
    key = create_key()
    secret_hash = auth.hash_hex(secret)
    d = {'key':key, 'server_secret_hash':server_secret_hash, 'user':user}
    return d
    
def save_keyfile(k, path):
    nDDB.saveAdvanceDDB(path, k)

def proc_key_dict(d):
    for k in d.keys():
        try:
            d[k] = long(d[k])
        except:
            pass
    return d

def load_keyfile(path):
    k = nDDB.openAdvanceDDB(path)
    k['key'] = proc_key_dict(k['key'])
    return k
