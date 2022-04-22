import socket
import threading

def main():
    relay_server = DNS_Relay(('',53))
    relay_server.run()

class DNS_Relay:
    def __init__(self,name_server):
        self.name_server = name_server
        self.BUFFER_SIZE = 512
        # URL - IP dict 
        self.url_ip = {}
        self.load_file('src/cache.txt')
        # DNS ID - response address dict 
        self.trans = {}
        # relay server 
        self.relay_addr = ('8.8.8.8',53) # Google DNS Server

    def load_file(self,cache_file):
        f = open(cache_file,'r',encoding='utf-8')
        for line in f:
            ip,name = line.split(' ')
            self.url_ip[name.strip('\n')] = ip
        f.close()

    def run(self):
        server_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        server_socket.bind(self.name_server)
        server_socket.setblocking(False)
        print("Server running...")
        while True:
            try:
                data,addr = server_socket.recvfrom(self.BUFFER_SIZE)
                threading.Thread(target=self.handle,args=(server_socket,data,addr)).start()
            except:
                continue 

    def handle(self,server_socket,data,addr):
        # print("Packet intercepted from " + addr)
        dns_package = DNS_Package(data)
        if dns_package.QR == 1:
            if dns_package.ID in self.trans:
                addr = self.trans[dns_package.ID]
                self.trans.pop(dns_package.ID)
            print('Succes: '+dns_package.qname)
        else:
            qname = dns_package.qname
            if 'www.'+qname in self.url_ip:
                qname = 'www.'+qname
            
            if qname in self.url_ip: # direct response
                data = dns_package.generate_response(self.url_ip[qname])
                print('Succes: '+qname + " " + self.url_ip[qname])
            else: # relay
                self.trans[dns_package.ID] = addr
                addr = self.relay_addr
                print('Relay: '+qname)
        
        server_socket.sendto(data,addr)


# see https://datatracker.ietf.org/doc/html/rfc1035#section-4 for package format
class DNS_Package:
    def __init__(self,data):
        self.data = data
        #ID
        self.ID = data[:2]
        # QR
        self.QR = data[2] >> 7
        #query内容解析
        self.qname, self.qtype, self.qclass = self.get_question_parts(data[12:])
    
    def get_question_parts(self,dns_question):
        state = 0
        expected_length = 0
        # QNAME format: 
        # i.e. 6google.3com0
        domain_name = ''
        x = 0
        y = 0
        for byte in dns_question:
            if state == 1:
                if byte != 0:
                    domain_name += chr(byte)
                x += 1
                if x == expected_length:
                    state = 0
                    x = 0
                if byte == 0:
                    break
            else:
                if byte !=0 and domain_name != '':
                    domain_name += '.'
                state = 1
                expected_length = byte
            y += 1

        question_type = dns_question[y:y+2]
        question_class = dns_question[y+2:y+4]

        return (domain_name,question_type,question_class)
        
    def generate_response(self,ip):
        dns_header = self.build_header()
        dns_question = self.data[12:]
        dns_answer = self.build_answer(ip)
        
        return dns_header+dns_question+dns_answer
    
    def build_header(self):
        # ID
        ID = self.ID

        # FLAGS
        FLAGS = self.get_flags(self.data[2:4])

        # Question Count
        QDCOUNT = b'\x00\x01'
        
        # Nameserver Count
        NSCOUNT = b'\x00\x00'

        # Additonal Count
        ARCOUNT = b'\x00\x00'
        
        # Answer Count
        ANCOUNT = b'\x00\x01'

        return ID+FLAGS+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT


    def build_answer(self,ip):
        # NAME
        # pointer back to the name in querie part(message compression)
        rbytes = b'\xc0\x0c'

        # TYPE
        rbytes += self.qtype

        # CLASS
        rbytes += self.qclass

        # TTL
        rbytes += b'\x00\x00\x01\x90'

        # RDLENGTH (length in octets of the RDATA field)
        # In our case an ip address is represented by 4 octets
        rbytes += b'\x00\x04'

        # RDATA
        for part in ip.split('.'):
            rbytes += bytes([int(part)])
        
        return rbytes
    
    def get_flags(self,flags):
        byte1 = flags[0]
        byte2 = flags[1]
        # set QR to 1(Response): xxxx xxxx | 1000 0000 = 1xxx xxxx
        byte1 |= 128
        # set RCODE to 0(No error condition): xxxx xxxx & 1111 0000 = xxxx 0000
        byte2 &= 240
        return bytes([byte1,byte2])

if __name__ == '__main__':
    main()
