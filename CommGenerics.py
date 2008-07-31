#communications generics for the CommunicationLink Class

import socket, nDDB
from dec_factories import create_existance_check_dec, create_value_check_dec

class CommGenericBase(object):
    
    def __init__(self):
        def defualt_proc(): pass
        self.proc_syscommand = defualt_proc
    def connect(self): pass
    def send(self, msg): pass
    def recieve(self): pass
    def send_dict(self, d): pass
    def listen(self): pass
    def close(self): pass
    def set_proc_syscommand(self, proc_func):
        self.proc_syscommand = proc_func

closed_false_check = create_value_check_dec('closed', False)

class SocketGeneric(CommGenericBase):
    
    END_MARK = '<<STOP>>'
    END_LEN = 8
    
    def __init__(self, host, port, bufsize=1024):
        super(SocketGeneric, self).__init__()
        def defualt_proc(): pass
        self.proc_command = defualt_proc
        self.sock = None
        self.HOST = host
        self.PORT = port
        self.BUFSIZE = bufsize
        self.ADDR = (self.HOST, self.PORT)
        self.closed = False
     
    def connect(self):
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.sock.connect(self.ADDR)
    
    @closed_false_check
    def send(self, msg):
        self.sock.sendall(msg+END_MARK)
    
    def send_dict(self, d): 
        self.send(nDDB.encode(msg_dict))
    
    @closed_false_check
    def recieve(self): 
        data = ''
        while data == '':
            try:
                while data[(-1*self.END_LEN):] != self.END_MARK: data += self.sock.recv(self.BUFFSIZE)
            except:
                data = ''
                continue
        data = data[:-1*self.END_LEN]
        self.proc_syscommand(data)
        self.proc_command(data)
        return data
    
    def close(self):
        self.closed = True
        self.sock.close()
    
    @closed_false_check
    def listen(self):
        self.sock.listen(5)
        
    def set_proc_command(self, proc_func):
        self.proc_command = proc_func