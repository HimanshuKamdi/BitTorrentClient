from socket import *
import struct
import time
from bitstring import BitArray
import math
import hashlib
import sys
import time
from bcoding import bencode, bdecode
import logging
import os
import requests
import struct
import random
import errno
from time import sleep
from bcoding import bdecode
import socket
from urllib.parse import urlparse
from socket import *
import traceback
import torrent
from threading import Thread
from torrent import *

CONSTANT_HANDSHAKE_LEN = 68
BLOCK_LENGTH_CONS = 16384

KEEP_ALIVE      = None
CHOKE           = 0
UNCHOKE         = 1 
INTERESTED      = 2
UNINTERESTED    = 3
HAVE            = 4
BITFIELD        = 5
REQUEST         = 6
PIECE           = 7
CANCEL          = 8
PORT            = 9

MESSAGE_LENGTH_SIZE     = 4
MESSAGE_ID_SIZE         = 1

class Peer():
    def __init__( self, IP, Port, info_hash, client_peer_id ):

        self.peer_sock = socket( AF_INET, SOCK_STREAM )
        self.peer_sock.settimeout(3)
        self.IP = IP
        self.Port = Port
        self.unique_id = IP + ' ' +str(Port)
        self.max_peer = 55
        self.handshake_flag = False
        self.peer_connection = False
        self.protocol = "BitTorrent protocol"
        self.unique_id  = '(' + self.IP + ' : ' + str(self.Port) + ')'
        self.peer_id = None
        self.client_peer_id = client_peer_id
        self.info_hash = info_hash
        self.bitfield_pieces = []
        self.am_choking         = True              # client choking peer
        self.am_interested      = False             # client interested in peer
        self.peer_choking       = True              # peer choking client
        self.peer_interested    = False             # peer interested in clinet
        # keep alive timeout : 10 second
        self.keep_alive_timeout = 10
        # keep alive timer
        self.keep_alive_timer = None

    # For handshaking with peer
    def handshake( self ):
        if self.handshake_flag == True:
            return False
        # Create connection
        if self.create_connection() == False:
            return False
        handshake_message = self.build_handshake_message()
        #self.peer_sock.send( msg )
        self.send_data( handshake_message )
        raw_response = self.receive_data( CONSTANT_HANDSHAKE_LEN )
        if raw_response is None:
            return False
        a = self.handshake_response_validation( raw_response )
        if a is None:
            return False
        self.peer_id = a
        self.handshake_flag = True
        return True

    def create_connection( self ):
        try:
            self.peer_sock.connect(( self.IP, self.Port))
            self.peer_connection = True
            return True

        except:
            self.peer_connection = False
            return False

    def build_handshake_message( self ):
        reserved = 0x0000000000000000
        msg  = struct.pack("!B", len(self.protocol))
        msg += struct.pack("!19s", self.protocol.encode())
        msg += struct.pack("!Q", reserved)
        msg += struct.pack("!20s", self.info_hash)
        msg += struct.pack("!20s", self.client_peer_id )
        return msg

    def send_data( self, data ):
        data_len = 0
        n = len( data )
        while( data_len < n):
            try:
                data_len += self.peer_sock.send( data[data_len:])
            except:
                return False
        return True

    def receive_data( self, len_response ):
        if self.peer_connection == False:
            return

        peer_raw_data = b''
        recv_data_len = 0
        req_size = len_response

        while( recv_data_len < len_response ):
            try:
                chunk = self.peer_sock.recv( req_size )
            except:
                chunk = b''
            
            if( len(chunk) == 0):
                return None
            
            peer_raw_data += chunk
            req_size -= len(chunk)
            recv_data_len += len(chunk)

        return peer_raw_data


    def handshake_response_validation( self, raw_response ):

        len_of_response = len( raw_response)

        if( len_of_response != CONSTANT_HANDSHAKE_LEN ):
            return None

        peer_info_hash = raw_response[28:48]
        peer_id = raw_response[48:68]

        if( peer_info_hash != self.info_hash ):
            return None
        if( peer_id == self.client_peer_id ):
            return None

        return peer_id

    def create_response_message( self, message_length, message_id, message_payload ):
        message  = struct.pack("!I", message_length)
        if message_id != None:
            message += struct.pack("!B", message_id)
        if message_payload != None:
            message += message_payload
        return message

    def send_keep_alive( self ):
        message_length = 0
        message_id = None
        message = self.create_response_message( message_length, message_id, None )
        if self.send_data( message ):
            return True
        else:
            return False 

    def send_interested_message( self ):
        message_length = 1
        message = self.create_response_message( message_length, INTERESTED, None )
        if self.send_data( message):
            self.am_interested = True
            return True
        else:
            self.am_interested = False
            return False

    def send_request_message( self, piece_index, block_offset, block_length):
        message_length  = 13                                # 4 bytes message length
        message_id      = REQUEST                           # 1 byte message id
        payload         = struct.pack("!I", piece_index)    # 12 bytes payload
        payload        += struct.pack("!I", block_offset) 
        payload        += struct.pack("!I", block_length)
        message = self.create_response_message( message_length, REQUEST, payload )
        if self.send_data( message ):
            return True
        else:
            return False

    def send_cancel_message( self, piece_index, block_offset, block_length ):
        message_length  = 13                                # 4 bytes message length
        message_id      = CANCEL                           # 1 byte message id
        payload         = struct.pack("!I", piece_index)    # 12 bytes payload
        payload        += struct.pack("!I", block_offset) 
        payload        += struct.pack("!I", block_length)
        message = self.create_response_message( message_length, REQUEST, payload )
        if self.send_data( message ):
            return True
        else:
            return False

    def initialize_bitfield(self):
        if not self.handshake_flag:
            return self.bitfield_pieces

        flag = True
        while( flag ):
            response_message = self.pwm_response_handler()
            if response_message == None:
                flag = False

        return self.bitfield_pieces


    def pwm_response_handler(self ):
        response = self.recieve_peer_wire_message()
        if response == None:
            return None
        
        msg_length  = response[0]
        msg_id      = response[1]
        msg_payload = response[2]

        if( msg_length == 0 ):
            self.recieved_keep_alive()
        else:
            if msg_id == 0:
                self.peer_choking = True
            if msg_id == 1:
                self.peer_choking = False
            if msg_id == 2:
                self.peer_interested = True
            if msg_id == 3:
                self.peer_interested = False

            if msg_id == 5:
                self.bitfield_pieces = self.extract_bitfield( msg_payload )

        return response

    def extract_bitfield( self, message_payload ):
        bitfield_pieces = []
        for i, byte_value in enumerate( message_payload ):
            num = 128
            for j in range(8):
                if( num & byte_value ):
                    bitfield_pieces.append(1)
                else:
                    bitfield_pieces.append(0)
                num = num // 2
        return bitfield_pieces

    def recieve_peer_wire_message(self):
        raw_msg_length = self.receive_data( MESSAGE_LENGTH_SIZE )
        if raw_msg_length is None or len(raw_msg_length) < MESSAGE_LENGTH_SIZE:
            return None

        msg_length = struct.unpack_from("!I", raw_msg_length)[0]
        if msg_length == 0:
            return [msg_length, None, None]

        raw_msg_ID =  self.receive_data( MESSAGE_ID_SIZE)
        if raw_msg_ID is None:
            return None
        
        msg_id  = struct.unpack_from("!B", raw_msg_ID)[0]

        if msg_length == 1:
            return [ msg_length, msg_id, None]
       
        payload_length = msg_length - 1
        
        msg_payload = self.receive_data( payload_length )
        if msg_payload is None:
            return None
        
        self.keep_alive_timer = time.time()

        return [ msg_length, msg_id, msg_payload ]

    def recieved_keep_alive(self):
        self.keep_alive_timer = time.time()

    def is_peer_has_piece( self, piece_index ):
        try:
            if self.bitfield_pieces[piece_index] == 1:
                return True
            else:
                return False
        except:
            return False

    def check_download_condition( self):
        if self.handshake_flag != True:
            return False

        if self.am_interested != True:
            return False
        
        if self.peer_choking != False:
            return False
        
        return True

    # client interested
    # peer unchoke
    def download_piece(self, piece_index, piece_length, torrent ):
        if self.send_interested_message() == False:
            return False, None
        
        self.pwm_response_handler()
        if self.peer_choking == True:
            return False, None

        if self.is_peer_has_piece( piece_index ) == False:
            return False, None

        recieved_piece = b''  
        block_offset = 0 
        block_length = 0

        flag = 0
        while block_offset < piece_length:
            if piece_length - block_offset >= BLOCK_LENGTH_CONS :
                block_length = BLOCK_LENGTH_CONS
            else:
                block_length = piece_length - block_offset
            
            block_data = self.download_block( piece_index, block_offset, block_length )
            if block_data:
                flag = 0
                recieved_piece += block_data
                block_offset   += block_length
                torrent.downloaded_length += block_length 
            else:
                flag += 1
            
            if flag == 3 :
                return False, None
        
        print("successfully downloaded and validated piece", piece_index )
        return True, recieved_piece

    def download_block(self, piece_index, block_offset, block_length ):

        if self.check_download_condition() == False:
            return None
        
        if self.send_request_message( piece_index, block_offset, block_length) == False:
            return None
        response = self.recieve_peer_wire_message()

        if response == None:
            return None

        msg_id      = response[1]
        msg_payload = response[2]

        if msg_id != PIECE:
            return None

        recv_piece_index  = struct.unpack_from("!I", msg_payload, 0)[0]
        recv_block_offset = struct.unpack_from("!I", msg_payload, 4)[0]
        recv_block_data   = msg_payload[8:]

        if recv_piece_index  != piece_index :
            return None
        if recv_block_offset != block_offset:
            return None
        if len(recv_block_data) != block_length:
            return None

        return recv_block_data
    

class Torrent(object):
    def __init__(self,path):
        self.file_names = []
        self.is_multi_file=False
        self.bitfield = []

        try:
            f=open(path,"rb")
            self.torrent_file = bdecode(f)
            print("Successfully decoded torrent file", path)
        except:
            print("Unable to open torrent file...")
            sys.exit()
        
        if b'encoding' in self.torrent_file.keys() :
            self.encoding = self.torrent_file[b'encoding'].decode()
        else:
            self.encoding = 'UTF-8'
        
        self.piece_length =self.torrent_file['info']['piece length']
        self.pieces = self.torrent_file['info']['pieces']
        self.total_lenth = self.initialize_files()
        self.number_of_pieces = math.ceil(self.total_length / self.piece_length)
        self.downloaded_length = 0
        self.raw_info_hash = bencode(self.torrent_file['info'])
        self.info_hash = hashlib.sha1(self.raw_info_hash).digest()
        self.peer_id = self.generate_peer_id()
        self.announce_list = self.get_trackers()
        for i in range( self.number_of_pieces ):
            self.bitfield.append( 0 )
        
    #structure of info:dict_keys(['length', 'name', 'piece length', 'pieces'])
    def initialize_files(self):
        self.total_length = 0
        root = self.torrent_file['info']['name']
        #for multi-file torrent files
        if 'files' in self.torrent_file['info']:
            self.is_multi_file=True
            if not os.path.exists(root):
                os.mkdir(root)
            for file in self.torrent_file['info']['files']:
                path_file = os.path.join(root, *file["path"])
                if not os.path.exists(os.path.dirname(path_file)):
                    os.makedirs(os.path.dirname(path_file))
                self.file_names.append({"path": path_file , "length": file["length"]})
                self.total_length += int(file["length"])
        #for single file torrent files
        else:
            self.file_names.append({"path": root , "length": self.torrent_file['info']['length']})
            self.total_length = self.torrent_file['info']['length']

    def get_trackers(self):
        if 'announce-list' in self.torrent_file:
            return self.torrent_file['announce-list']
        else:
            return self.torrent_file['announce']

    def generate_peer_id(self):
        seed = str(time.time())
        return hashlib.sha1(seed.encode('utf-8')).digest()  

    def calculate_piece_length( self, index_number ):
        if index_number == self.number_of_pieces-1:
            return self.total_length-self.piece_length * index_number
        else:
            return self.piece_length
        
   
class http_tracker():
    def __init__(self,torrent,tracker_url):
        self.params={
        'info_hash': torrent.info_hash,
        'peer_id': torrent.peer_id,
        'uploaded': 0,
        'downloaded': 0,
        'port': 6881,
        'left': torrent.total_length,
        'event': 'started',
        'compact': 1
        }
        self.tracker_url=tracker_url
        self.peers_list=[]
        self.peer_data={}
        self.complete=None
        self.incomplete=None
        self.interval=None

    def http_request(self):
        bencoded_response=None
        attempt=0
        flag=0
        while attempt<15:
            print("Attempt {} for http request to {}".format(attempt+1,self.tracker_url))
            try:
                bencoded_response = requests.get(self.tracker_url, self.params, timeout=2 )
                # decode the bencoded dictionary to python ordered dictionary 
                raw_response_dict = bdecode(bencoded_response.content)
                #print(raw_response_dict)
                if raw_response_dict !=None:
                    flag=1
                    print("Http request to tracker {} successful\n".format(self.tracker_url))
                    break
            except Exception as error_msg:
                pass
            attempt+=1
        
        if flag==0:
            print("Http request to tracker {} failed\n".format(self.tracker_url))
            return -1

        if flag==1:
            if 'peers' in raw_response_dict:
                raw_peers_data = raw_response_dict['peers']
                for i in range(len(raw_peers_data)):
                    peer_list=raw_peers_data[i]
                    if type(peer_list)!=dict:
                        raw_peers_list = [raw_peers_data[i : 6 + i] for i in range(0, len(raw_peers_data), 6)]
                        for raw_peer_data in raw_peers_list:
                            peer_IP = ".".join(str(int(a)) for a in raw_peer_data[0:4])
                            peer_port = raw_peer_data[4] * 256 + raw_peer_data[5]
                            self.peers_list.append((peer_IP, peer_port))
                    else:
                        peer_IP =peer_list['ip']
                        peer_port = peer_list['port']
                        self.peers_list.append((peer_IP, peer_port))
           
                if 'complete' in raw_response_dict:
                    self.complete = raw_response_dict['complete']
                if 'incomplete' in raw_response_dict:
                    self.incomplete = raw_response_dict['incomplete']
                if 'interval' in raw_response_dict:
                    self.interval = raw_response_dict['interval']
                self.peer_data = {'interval' : self.interval, 'peers' : self.peers_list,
                         'leechers' : self.incomplete, 'seeders'  : self.complete}

            return self.peer_data

class udp_tracker():
    def __init__(self,torrent,tracker_url):
        self.params={
        'info_hash': torrent.info_hash,
        'peer_id': torrent.peer_id,
        'uploaded': 0,
        'downloaded': 0,
        'port': 6881,
        'left': torrent.total_length,
        'event': 'started',
        'compact': 1
        }
        self.tracker_url=tracker_url
        self.ip=None
        self.port=None
        self.peer_list=[]
        self.peer_data={}
        self.connection_id = 0x41727101980                       
        self.action = 0x0                                            
        self.transaction_id = int(random.randrange(0, 255))  
    
    def udp_request(self):
        temp_peer_data={}
        temp_peer_list=[]
        flag=0
        try:
            self.sock = socket(AF_INET, SOCK_DGRAM) 
            self.sock.settimeout(5)
            self.tracker_url=urlparse(self.tracker_url)
            self.ip=gethostbyname(self.tracker_url.hostname)
            self.port=self.tracker_url.port
            connection_payload = self.udp_connection_payload()
            self.connection_id = self.udp_connection_request(connection_payload)
            announce_payload = self.udp_announce_payload()
            self.raw_announce_reponse = self.udp_announce_request(announce_payload)
            temp_peer_data=self.parse_udp_tracker_response(self.raw_announce_reponse)
            temp_peer_list=self.peer_data['peers']
            flag=1
            
        except:
            pass
        if flag==1:
            print("UDP request to tracker {} successful".format(self.tracker_url.netloc))
            self.peer_data.update(temp_peer_data)
            self.peer_list.append(temp_peer_list)
            return self.peer_data 
        else:
            print("UDP request to tracker {} failed".format(self.tracker_url.netloc))
            return -1

    def udp_connection_payload(self):
        conn_request  = struct.pack("!q", self.connection_id)     # first 8 bytes : connection_id
        conn_request += struct.pack("!i", self.action)            # next 4 bytes  : action
        conn_request += struct.pack("!i", self.transaction_id)    # next 4 bytes  : transaction_id
        return conn_request
    
    def udp_connection_request(self,connection_payload):
        self.sock.sendto(connection_payload, (self.ip, self.port))
        try:
            raw_connection_data, conn = self.sock.recvfrom(2048)
            return self.parse_connection_response(raw_connection_data)
        except :
            # print('UDP tracker connection request failed')
            pass
       
    def parse_connection_response(self, raw_connection_data):
        if(len(raw_connection_data) < 16):
            print('UDP tracker wrong reponse length of connection ID !')
        
        response_action = struct.unpack_from("!i", raw_connection_data)[0]       
        
        response_transaction_id = struct.unpack_from("!i", raw_connection_data, 4)[0]
        if(response_transaction_id != self.transaction_id):
            print('UDP tracker wrong response transaction ID !')
        
        reponse_connection_id = struct.unpack_from("!q", raw_connection_data, 8)[0]
        return reponse_connection_id
    
   
    def udp_announce_payload(self):
        self.action = 0x1            
        conn_id =  struct.pack("!q", self.connection_id)    
        action= struct.pack("!i", self.action)  
        trans_id= struct.pack("!i", self.transaction_id)  
        info_hash= struct.pack("!20s", self.params['info_hash'])
        peer_id= struct.pack("!20s", self.params['peer_id'])         
        downloaded= struct.pack("!q", self.params['downloaded'])
        left= struct.pack("!q", self.params['left'])
        uploaded= struct.pack("!q", self.params['uploaded']) 
        event= struct.pack("!i", 0x2) 
        my_ip= struct.pack("!i", 0x0) 
        random_key= struct.pack("!i", int(random.randrange(0, 255)))
        peer_numbers= struct.pack("!i", -1)                   
        response_port= struct.pack("!H", self.params['port'])   
        announce_payload=(conn_id+action+trans_id+info_hash+peer_id+downloaded+left+uploaded+event+my_ip+
        random_key+peer_numbers+response_port)
        return announce_payload

   
    def udp_announce_request(self, announce_payload):
        raw_announce_data = None
        attempt = 0
        while(attempt < 10):
            try:
                self.sock.sendto(announce_payload, (self.ip, self.port))    
                raw_announce_data, conn = self.sock.recvfrom(2048)
                break
            except:
                error_log =  ' failed announce request attempt ' + str(attempt + 1)
                print(error_log)
            attempt = attempt + 1
        return raw_announce_data

    
    def parse_udp_tracker_response(self, raw_announce_reponse):
        if(len(raw_announce_reponse) < 20):
            print('Invalid response length in announcing!')
        response_action = struct.unpack_from("!i", raw_announce_reponse)[0]     
        response_transaction_id = struct.unpack_from("!i", raw_announce_reponse, 4)[0]
        if response_transaction_id != self.transaction_id:
            print('The transaction id in annouce response do not match')
        
        offset = 8
        self.interval = struct.unpack_from("!i", raw_announce_reponse, offset)[0]
        offset = offset + 4
        self.leechers = struct.unpack_from("!i", raw_announce_reponse, offset)[0] 
        offset = offset + 4
        self.seeders = struct.unpack_from("!i", raw_announce_reponse, offset)[0] 
        offset = offset + 4
        self.peers_list = []
        while(offset != len(raw_announce_reponse)):
          
            raw_peer_data = raw_announce_reponse[offset : offset + 6]    
            
            peer_ip = ".".join(str(int(a)) for a in raw_peer_data[0:4])
            
            peer_port = raw_peer_data[4] * 256 + raw_peer_data[5]
           
            self.peers_list.append((peer_ip, peer_port))
            offset = offset + 6
        self.peer_data = {'interval' : self.interval, 'peers': self.peers_list,
                     'leechers' : self.leechers, 'seeders'  : self.seeders}

        if(len(self.peer_data['peers']))==0:
            print("peer ip and port are not received from the tracker")
    
        return self.peer_data


    
class Tracker():
    def __init__(self,torrent):
        self.tracker_urls=[]
        self.peer_data={}
        self.peer_list=[]
        for i in range(len(torrent.announce_list)):
            self.tracker_urls.append(torrent.announce_list[i][0])
    
    def get_peers_from_trackers(self,torrent):
        thread_pool = []
        for tracker_url in self.tracker_urls:
            th = Thread( target = self.get_peers, args=( torrent, tracker_url ))
            thread_pool.append(th)
            th.start()

        for i in thread_pool:
            i.join()
        return self

    def get_peers( self, torrent, tracker_url ):
        if str.startswith(tracker_url,"http"):
            response=http_tracker(torrent,tracker_url).http_request()
            if response !=-1:
                self.peer_data.update(response)
                for p in response['peers']:
                    if p not in self.peer_list:
                        self.peer_list.append(p)
                
        if str.startswith(tracker_url,"udp"):
            response=udp_tracker(torrent,tracker_url).udp_request()        
            if response !=-1:
                self.peer_data.update(response)
                for p in response['peers']:
                    if p not in self.peer_list:
                        self.peer_list.append(p)
