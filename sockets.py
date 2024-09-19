# -*- coding:utf-8 -*-
# @FileName  :main.py
# @Time      :2023/11/11 12:14:11
# @Author    :D0WE1L1N
from socket import *
import os
import errors

from pathlib import Path
from time import sleep
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from random import uniform
from zlib import compress, decompress
from json import dumps, loads
class SimpleTCP():
    '''
    The main class when using TCP
    '''

    def __init__(self, family: AddressFamily = AF_INET, type: SocketKind = SOCK_STREAM
                 , proto: int = -1, fileno: int = None, is_encrypted: bool = True, AES_key: bytes = None) -> None:
        '''
        is_encrypted: use encrypted connection, only for server
        AES_key: use a fixed AES_key, None for random, must be 16 bytes, only for server
        self.Default_message_len: if in encrypted mode, the value must be a multiple of self.BLOCK_SIZE
        MAKE SURE THE DEFAULT_MESSAGE_LEN OF BOTH SERVER AND CLIENT ARE SAME, Or it could be a hassle
        '''
        self.BLOCK_SIZE = 16 # block size of padding text which will be encrypted by AES
        # the block size must be a mutiple of 8
        self.default_encoder = 'utf8'  # the default encoder used in send and recv when the message is not bytes
        if is_encrypted:
            if AES_key == None:
                self.key = get_random_bytes(16)  # generate 16 bytes AES code
            else:
                self.key = AES_key #TODO check the input 
            self.cipher_aes = AES.new(self.key, AES.MODE_ECB)
        else:
            self.key, self.cipher_aes = None, None
        self.default_message_len = 1024 # length of some basic message, it's best not to go below 1024 bytes
        self.s = socket(family, type, proto, fileno)  # main socket
        # self.password = self.padding_packets(password, 20)[0]
    def accept(self) -> tuple:
        '''
        Accept with information exchange and key exchange
        '''
        self.s, address = self.s.accept()
        if self.key == None:
            is_encrypted = False
        else:
            is_encrypted = True
        info_dict = {
            'is_encrypted' : is_encrypted}
        info_dict = dumps(info_dict).encode(encoding=self.default_encoder)
        self.s.send(self.turn_to_bytes(len(info_dict)))
        self.s.send(info_dict)
        if is_encrypted:
            public_key = self.s.recv(450)
            rsa_public_key = RSA.import_key(public_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
            encrypted_aes_key = cipher_rsa.encrypt(self.key)
            self.s.send(encrypted_aes_key)
        # TODO
        return address
    def connect(self, Address: tuple) -> None:
        '''
        Conect with information exchange and key exchange
        '''
        self.s.connect(Address)
        info_dict_len = int(self.s.recv(2).decode(encoding=self.default_encoder))
        info_dict = self.s.recv(info_dict_len).decode(encoding=self.default_encoder)
        info = loads(info_dict)
        if info['is_encrypted'] == True:
            tmp_key = RSA.generate(2048)
            private_key = tmp_key.export_key()
            public_key = tmp_key.publickey().export_key()
            self.s.send(public_key)
            rsa_private_key = RSA.import_key(private_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
            encrypted_aes = self.s.recv(256).rstrip(b"\x00")
            self.key = cipher_rsa.decrypt(encrypted_aes)
            self.cipher_aes = AES.new(self.key, AES.MODE_ECB)
        else:
            self.key, self.cipher_aes = None, None
    def turn_to_bytes(self, message) -> bytes:
        '''
        Turn str, int, etc. to bytes using {self.default_encoder}
        '''
        type_of_message = type(message)
        if type_of_message == str:
            message = message.encode(encoding=self.default_encoder)
        elif type_of_message == bytes:
            pass
        else:
            try:
                message = str(message).encode(encoding=self.default_encoder)
            except:
                raise TypeError(
                    'Unexpected type "{}" of {}'.format(type_of_message, message))
        return message

    def padding_packets(self, message: bytes, target_length: int = None) -> tuple:
        '''
        Pad the packet to {target_length} bytes with b' ', used in not-encrypted mode
        The packet must be smaller then {target_length}
        target_length = None : use self.default_message_len
        '''
        message = self.turn_to_bytes(message)
        if target_length == None:
            target_length = self.default_message_len
        if len(message) > target_length:
            raise errors.MessageLengthError(
                'the length {} bytes of the message is bigger than {} bytes, please use self.send_large_small and self.recv instead'.format(str(len(message)), target_length))
        pad_num = target_length-len(message)
        message += b' ' * pad_num
        return (message, pad_num)
    def pad_packets_to_mutiple(self, data: bytes, block_size: int == None) -> bytes:
        '''
        Pad the data to make the length of it become a mutiple of Blocksize, used in encrypted mode
        target_length = None : use self.BLOCK_SIZE
        '''
        padding_length = block_size - (len(data) % block_size)
        if padding_length == 0:
            padding_length = block_size  # 如果数据长度为16的倍数，额外填充一个完整块
        padding = bytes([padding_length]) * padding_length
        padded_data = data + padding
        return padded_data
    def unpad_packets_to_mutiple(self, padded_data: bytes, block_size: int == None) -> bytes:
        '''
        Unpad the data to make the length of it become a mutiple of Blocksize, used in encrypted mode
        target_length = None : use self.BLOCK_SIZE
        '''
        if block_size == None:
            block_size = self.BLOCK_SIZE
        padding = padded_data[-1]
        if padding > block_size or any(byte != padding for byte in padded_data[-padding:]):
            raise ValueError("Invalid padding")
        return padded_data[:-padding]
    def send_large(self, message) -> None:
        '''
        Send message with the socket
        can accept bytes, str, int, etc.
        every non-bytes message will be encoded with self.default_encoder
        Every packet is forced to be filled to {self.default_message_len} bytes
        '''
        message = self.turn_to_bytes(message)
        message = compress(message)
        message_list = [message[i:i + self.default_message_len]
                        for i in range(0, len(message), self.default_message_len)]
        message_list_len = len(message_list)
        self._send(self.padding_packets(
            self.turn_to_bytes(message_list_len))[0])
        message_index = 0
        for message in message_list:
            message_padded = self.padding_packets(message)
            message = message_padded[0]
            self._send(message)
            message_index += 1
            if message_index == message_list_len:
                pad_num = message_padded[1]
                self._send(self.padding_packets(
                    self.turn_to_bytes(str(pad_num)))[0])

    def send(self, message) -> None:
        '''
        Send a message with the socket
        can accept bytes, str, int, etc.
        The data should not be larger than 9999 bytes
        It can be used at any time 
        Use self.send_large and recv_large if you want to send a big message
        '''
        message = self.turn_to_bytes(message)
        try:
            message_len = self.padding_packets(
                self.turn_to_bytes(len(message)), target_length=4)[0]
        except errors.MessageLengthError:
            raise errors.MessageLengthError(
                'The length of message is longer than 9999 bytes({} bytes), please use send_large instead'.format(str(len(message))))
        self._send(message_len)
        self._send(message)

    def sendfile(self, file_location: str) -> None:
        '''
        Send a file with the socket
        THE LOCATION MUST BE A FILE, NOT A DIR
        {self.default_message_len} bytes are read and sent in a single pass
        '''
        if os.path.exists(file_location) and not os.path.isdir(file_location):
            with open(file_location, 'rb') as file:
                self.send_large(file.read())
            self.send_large('EOF')  # Must to use send large, but this is bad
        else:
            raise FileExistsError(
                'the file {} does not exist or it is a dir'.format(file_location))

    def unpadding_packets(self, data: bytes, pad_num: int) -> bytes:
        '''
        Delete the blank bytes at the back of the message
        pad_num : number of the blank bytes
        pad_num = -1, delete all the blank bytes the the back(or use .rstrip() directly is ok)
        '''
        if pad_num == -1:
            data = data.rstrip()
        else:
            while pad_num > 0 and data[-1:] == b' ':
                data = data[:-1]
                pad_num -= 1
        return data

    def send_dir(self, src_path: str) -> None:
        target_path = os.path.basename(src_path)

        def send_file_in_dir(src_path: str, target_path: str):
            if not os.path.exists(src_path):
                raise FileExistsError('Path {} does not exists'.format(src_path))
            filelist_src = os.listdir(src_path)  # Used to return a file name and directory name
            for file in filelist_src:  # Go through all the files or folders
                src_path_read_new = os.path.join(
                    os.path.abspath(src_path), file)
                target_path_write_new = os.path.join(target_path, file)
                if os.path.isdir(src_path_read_new):  # Determine whether the read path is a directory folder, and perform recursion if it is a folder
                    send_file_in_dir(src_path_read_new,
                                     target_path_write_new)  # recursion
                else:  # If it is a file, send it
                    self.send('FILE')
                    self.send(target_path_write_new)
                    self.sendfile(src_path_read_new)
        send_file_in_dir(src_path, target_path)
        self.send('END')

    def _send(self, message: bytes) -> None:
        '''
        The basic method to encrypted and send data 
        MUST BE A MUTIPLE OF THE BLOCK SIZE IN ENCRYPTED MODE
        '''
        if self.cipher_aes != None:
            output_message = self.cipher_aes.encrypt(self.pad_packets_to_mutiple(message, self.BLOCK_SIZE))
            # plainmessage = unpad(self.cipher_aes.decrypt(output_message), self.BLOCK_SIZE)
        else:
            output_message = message
        self.s.send(output_message)  # The TCP mode

    def _recv(self, length: int) -> bytes:
        '''
        The basic method to decrypted and recv data
        '''
        if self.cipher_aes != None:
            if length % 16 == 0:
                length += 16
            length = (length + self.BLOCK_SIZE-1) // self.BLOCK_SIZE * self.BLOCK_SIZE # round up to multiple of 16
            message = self.s.recv(length)
            message = self.cipher_aes.decrypt(message)
            message = self.unpad_packets_to_mutiple(message, self.BLOCK_SIZE)
        else:
            message = self.s.recv(length)
        return message # The TCP mode
    def recv_dir(self, target_path: str, is_overwrite: bool = False) -> None:
        '''
        The method to recv dir from self.send_dir
        target_path : the path to save the dir
        is_overwrite : Overwrite a file when a file with the same name appears, otherwise raise an error
        '''
        while True:
            typeofmessage = self.recv(is_decode=True)
            if typeofmessage == 'FILE':
                recv_target_path = os.path.join(target_path, self.recv())
                self.savefile(os.path.dirname(recv_target_path), os.path.basename(
                    recv_target_path), is_overwrite=is_overwrite)
            elif typeofmessage == 'END':
                return True
            else:
                raise RuntimeError(
                    'Unknown header type of dir_send {}, do you use the wrong method to send a dir? please use self.send_dir instead'.format(typeofmessage))

    def recv_large(self, is_decode: bool = True):
        '''
        The return type can be bytes or string
        The method to recv message WHICH IS SENT BY self.send_large
        is_decode : decode the message with {self.default_encoder}
        '''
        message_listlen = self._recv(self.default_message_len).decode(
            encoding=self.default_encoder).rstrip()
        message_listlen = int(message_listlen)
        message = b''
        for i in range(0, message_listlen):
            mes = self._recv(self.default_message_len)
            if i == message_listlen - 1:
                mes_padnum = int(self._recv(self.default_message_len).decode(
                    encoding=self.default_encoder))
            else:
                mes_padnum = 0
            mes = self.unpadding_packets(mes, mes_padnum)
            message += mes
        message = decompress(message)
        if is_decode:
            message = message.decode(encoding=self.default_encoder)
        return message

    def recv(self, is_decode: bool = True):
        '''
        The return type can be bytes or string
        The method to recv message WHICH IS SENT BY self.send
        is_decode : decode the message with {self.default_encoder}
        '''
        message_len = self._recv(4).rstrip()
        message_len = int(message_len.decode(encoding=self.default_encoder))
        message = self._recv(message_len)
        if is_decode:
            message = message.decode(encoding=self.default_encoder)
        return message

    def savefile(self, savepath: str, filename: str = 'File_from_python_socket', is_overwrite: bool = False) -> None:
        '''
        Receive and save file sent using self.send_largefile directly
        savepath : path to save, MUST BE A DIR
        filename : name of the file
        is_overwrite : Overwrite a file when a file with the same name appears, otherwise raise an error
        '''
        if filename != None:
            file_location = os.path.join(savepath, filename)
        else:
            file_location = savepath
            filename = os.path.basename(savepath)
            savepath = os.path.dirname(savepath)
        if os.path.exists(file_location) and not is_overwrite:
            raise FileExistsError(
                'Already has a file named {} in {}'.format(file_location, savepath))
        Path(savepath).mkdir(parents=True, exist_ok=True)
        with open(file_location, 'wb') as file:
            while True:
                a = self.recv_large(is_decode=False)
                if a != 'EOF'.encode(encoding=self.default_encoder):
                    file.write(a)
                    file.flush()
                else:
                    break

    def recvfile(self) -> bytes:
        '''
        Only receive file sent using self.send_largefile
        '''
        output = b''
        while True:
            a = self.recv_large(is_decode=False)
            if a != 'EOF'.encode(encoding=self.default_encoder):
                output += a
            else:
                break
        return output

    def finite_number_reconnect(self, host: str, port: int, retries: int = 5, delay_time: int = 2, addressfamliy_of_new_socket=AF_INET, type_of_new_socket=SOCK_STREAM) -> bool:
        '''
        ONLY FOR TCP
        The method to excute the Exponential backoff reconnect
        After each connection failure, the exponential backoff algorithm is used to calculate the next wait time, that is, twice the current wait time is randomized, and the smaller value of it than max_delay is used as the next wait time. Make no more than max_attempts to reconnect.
        retries : Number of reconnections
        delay_time : Time between reconnections
        addressfamliy_of_new_socket : addressfamliy of new socket
        type_of_new_socket : type of new socket
        return True when the reconnect is successful, otherwise return False
        example:
            try:
                connect()
                something_may_cause_connect_error()
            except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError, ConnectionError): # or more
                if finite_number_reconnect(your_ip, your_port):
                    do_something_else()
                else:
                    print('failed to reconnect')
            self.s.close()
        '''
        self.s.close()
        self.s = socket(addressfamliy_of_new_socket, type_of_new_socket)
        current_retries = 0
        while current_retries < retries:
            try:
                self.s.connect((host, port))
            except:
                current_retries += 1
                sleep(delay_time)
            else:
                return True
        return False

    def exponential_backoff_reconnect(self, host: str, port: int,
                                      max_attempts: int = 10, base_delay: int = 1, max_delay: int = 10,
                                      addressfamliy_of_new_socket=AF_INET, type_of_new_socket=SOCK_STREAM) -> bool:
        '''
        ONLY FOR TCP
        The method to excute the Exponential backoff reconnect
        After each connection failure, the exponential backoff algorithm is used to calculate the next wait time, that is, twice the current wait time is randomized, and the smaller value of it than max_delay is used as the next wait time. Make no more than max_attempts to reconnect.
        max_attempts : the maximum number of reconnections
        base_delay : the initial wait time
        max_delay : the maximum wait time
        addressfamliy_of_new_socket : addressfamliy of new socket
        type_of_new_socket : type of new socket
        return True when the reconnect is successful, otherwise return False
        example:
            try:
                connect()
                something_may_cause_connect_error()
            except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError, ConnectionError): # or more
                if exponential_backoff_reconnect(your_ip, your_port):
                    do_something_else()
                else:
                    print('failed to reconnect')
            self.s.close()
        '''
        self.s.close()
        self.s = socket(addressfamliy_of_new_socket,
                        type_of_new_socket)  # TODO
        attempts = 0
        delay = base_delay
        while attempts < max_attempts:
            try:
                self.s.connect((host, port))
            except Exception as e:
                print(e)
                sleep(delay)
                delay = min(max_delay, uniform(0, delay * 2))
                attempts += 1
            else:
                return True
        return False
# TODO: UDP part
# class SimpleUDP(SimpleTCP):
#     '''
#     The main class of SimpleUDP
#     the only thing different is self._send, self._recv and some init settings
#     '''
#     def __init__(self, IP: str, PORT: int, family: AddressFamily = AF_INET, type: SocketKind = SOCK_DGRAM, proto: int = -1, fileno: int | None = None) -> None:
#         '''
#         Change some basic settings
#         '''
#         super().__init__(family, type, proto, fileno)
#         self.IP = IP
#         self.PORT = PORT
#     def _send(self, message: bytes) -> None:
#         '''
#         Change the send method to UDP
#         '''
#         self.s.sendto(message, (self.IP, self.PORT))
#     def _recv(self, length: int) -> bytes:
#         '''
#         Change the recv method to UDP
#         '''
#         return self.s.recvfrom(length)[0]
