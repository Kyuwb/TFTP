import os
import stat
import time
import subprocess
import socket
import string
import struct
import ipaddress
import re

###############################################################
##                                                           ##
##              PROTOCOL CONSTANTS AND TYPES                 ##
##                                                           ##     
###############################################################

MAX_DATA_LEN = 512           # bytes    
MAX_BLOCK_NUMBER = 2**16 - 1 # 0..65535
INACTIVITY_TIMEOUT = 25.0    # segs
DEFAULT_MODE = 'octet'
DEFAULT_BUFFER_SIZE = 1024   # bytes
MODE_NETASCII = "netascii"

# TFTP message opcodes

RRQ = 1 # Read Request
WRQ = 2 # Write Request
DAT = 3 # Data Transfer
ACK = 4 # Acknowledge
ERR = 5 # Error packet: what the server responds if a read/write 
        # can't be processed, read and write errors during file 
        # transmission also cause this message to be sent, and 
        # transmission is then terminated. The error number gives a
        # numeric error code, followed by and ASCII error message that
        # might contain additional, operating system specific 
        # information.


ERR_NOT_DEFINED = 0
ERR_FILE_NOT_FOUND = 1 
ERR_ACCESS_VIOLATION = 2
DISK_FULL_OR_ALLOC_EXC = 3
ILLEGAL_TFTP_OP = 4
UNKOWN_TRANSF_ID = 5
FILE_ALREADY_EXISTS = 6
NO_SUCH_USER = 7

ERROR_MESSAGES = {
    ERR_NOT_DEFINED: 'Not defined, see error message(if any).',
    ERR_FILE_NOT_FOUND: 'File not found',
    ERR_ACCESS_VIOLATION: 'Access violation',
    DISK_FULL_OR_ALLOC_EXC: 'Disk full or allocation exceeded.',
    ILLEGAL_TFTP_OP: 'Illegal TFTP operation',
    UNKOWN_TRANSF_ID: 'Unkown Transfer ID',
    FILE_ALREADY_EXISTS: 'File already exists',
    NO_SUCH_USER: 'No such user'

}

DEFAULT_MODE = 'octet'

INET4Address = tuple[str, int]        # TCP/UDP address => IPv4 and port
###############################################################
##                                                           ##
##                 SEND AND RECEIVE FILES                    ##
##                                                           ##     
###############################################################

def get_file(server_addr: INET4Address, filename: str):
    """
    Get the remote file given by 'filename' through a TFTP RRQ
    connection to remote server at 'server_addr'.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # generalizar para timeout global
        sock.settimeout(INACTIVITY_TIMEOUT)
        with open(filename, 'wb') as out_file:
            rrq = pack_rrq(filename)
            next_block_number = 1
            sock.sendto(rrq, server_addr) 
            # Acrescentar ao código: nº bytes transferidos, apanhar o contador
            # de bytes do programa, esta função pode devolver quantos bytes 
            # efetivamente transferidos
            while True:
                packet, server_addr = sock.recvfrom(DEFAULT_BUFFER_SIZE)
                opcode = unpack_opcode(packet)
                """
                Podemos fazer import enum as Enum e utilizar o match, sendo
                necessário adaptar todas as outras funções -> ver vídeo aula    
                match opcode:
                    case DAT:
                        pass

                    case ERR:
                        error_code, error_msg = unpack_err(packet)
                        raise Err(error_code, error_msg)
                    
                    case _:
                        error_msg = f"Invalid packet opcode: {opcode}. Expecting {DAT=}."
                        raise ProtocolError(f)
                """    
                
                if opcode == DAT:
                    block_number, data = unpack_dat(packet)
                    if block_number not in (next_block_number, next_block_number - 1):
                        error_msg = (
                            f"Unexpected block number: {block_number}. Expecting one of"
                            f"{next_block_number} or {next_block_number - 1}"
                        )
                        raise ProtocolError(error_msg)

                    if block_number == next_block_number:
                       out_file.write(data)
                       next_block_number += 1

                    ack = pack_ack(block_number)
                    sock.sendto(ack, server_addr)
                    # if sair um número de 1 a 3, se número for 2, não envia o ack <<<<<<<

                    if len(data) < MAX_DATA_LEN:
                        break
                elif opcode == ERR:
                    error_code, error_msg = unpack_err(packet)
                    raise Err(error_code, error_msg)
                
                else:
                    error_msg = f"Invalid packet opcode: {opcode}. Expecting {DAT=}."
                    raise ProtocolError(error_msg)

def put_file(server_addr: INET4Address, local_filename: str, remote_filename: str = None):
    """
    Put the local file given by 'local_filename' to the remote server at 'server_addr'
    through a TFTP WRQ connection.

    If 'remote_filename' is not provided, the remote file will have the same name as the local file.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Generalize for global timeout
        sock.settimeout(INACTIVITY_TIMEOUT)
        with open(local_filename, 'rb') as in_file:
            wrq = pack_wrq(remote_filename)
            sock.sendto(wrq, server_addr)
            block_number = 0

            file_size = os.path.getsize(local_filename)
            print(f"Uploading '{local_filename}' ({file_size} bytes) to server at {server_addr}...")

            while True:
                ack_packet, server_addr = sock.recvfrom(DEFAULT_BUFFER_SIZE)
                ack_opcode = unpack_opcode(ack_packet)
                if ack_opcode == ACK:
                    ack_block_number = unpack_ack(ack_packet)
                    if ack_block_number == block_number:
                        block_number += 1
                    else:
                        error_msg = (
                            f"Unexpected ACK block number: {ack_block_number}."
                            f"Expecting: {block_number}."
                        )
                        raise ProtocolError(error_msg)

                    data = in_file.read(MAX_DATA_LEN)
                    dat_packet = pack_dat(block_number, data)
                    sock.sendto(dat_packet, server_addr)

                    progress = in_file.tell() / file_size
                    percentage = int(progress * 100)
                    # Print both percentage progress and bytes-sent bar
                    print(f"\r[{percentage}%] {'#' * int(progress * 20)} [{in_file.tell()}/{file_size} bytes]", end='', flush=True)

                    if len(data) < MAX_DATA_LEN:
                        print(f"\nUpload complete.")
                        print(f"File '{local_filename}' uploaded as '{remote_filename}'")
                        break
                elif ack_opcode == ERR:
                    error_code, error_msg = unpack_err(ack_packet)
                    raise Err(error_code, error_msg)

                else:
                    error_msg = (
                        f"Invalid packet opcode: {ack_opcode}."
                        f"Expecting {ACK=} or {ERR=}."
                    )
                    raise ProtocolError(error_msg)
#:

def encontrarpasta_tftp(root="/"):
    for pasta_raiz, pastas,  in os.walk(root):
        if "tftproot" in pastas:
            return os.path.join(pasta_raiz, "tftproot")
    return None

def dir_file():
    caminho_da_pasta_tftp = encontrarpasta_tftp()
    if caminho_da_pasta_tftp:
        try:
            arquivos = os.listdir(caminho_da_pasta_tftp)
            print("Arquivos na pasta do servidor TFTP:")
            for arquivo in arquivos:
                print(arquivo)
        except FileNotFoundError:
            print("O diretório do servidor TFTP não foi encontrado.")
    else:
        print("Não foi possível encontrar a pasta do servidor TFTP.")     
            

##############################################################
##                                                          ## 
##              Utilities and stuff                         ##
##                                                          ##
############################################################## 
# Define pack_opcode function
def pack_opcode(opcode):
    # implementation of the function
    pass

# Define pack_rrq_with_size function using pack_opcode
def pack_rrq_with_size(filename):
    rrq_opcode = pack_opcode(RRQ)
    # implementation of the function
    pass

# Modify the RRQ packet creation to include file size
def pack_rrq_with_size(filename: str):
    rrq_opcode = pack_opcode(RRQ)
    filename_bytes = filename.encode("utf-8")
    mode_bytes = MODE_NETASCII.encode("utf-8")
    size_bytes = pack_size(os.path.getsize(filename))  # Include file size

    return rrq_opcode + filename_bytes + NULL_BYTE + mode_bytes + NULL_BYTE + size_bytes

# Modify the DAT packet creation to include file size
def pack_dat_with_size(block_number: int, data: bytes):
    dat_opcode = pack_opcode(DAT)
    block_number_bytes = pack_block_number(block_number)
    size_bytes = pack_size(len(data))  # Include data size

    return dat_opcode + block_number_bytes + size_bytes + data


##############################################################
##                                                          ## 
##              PACKET PACKING AND UNPACKING                ##
##                                                          ##
############################################################## 



def pack_rrq(filename: str, mode: str = DEFAULT_MODE) -> bytes:
    return _pack_rrq_wrq(RRQ, filename, mode)
#:

def pack_wrq(filename):
    return struct.pack(f"!H{len(filename)}s", Opcode.WRQ.value, filename.encode())
#:
def _pack_rrq_wrq(opcode: int, filename: str, mode: str = DEFAULT_MODE) -> bytes:
    if not is_ascii_printable(filename):
        raise TFTPValueError(f"Invalid filename: {filename}. Not ASCII printable")
    filename_bytes = filename.encode() + b'\x00'
    mode_bytes = mode.encode() + b'\x00'
    fmt = f'!H{len(filename_bytes)}s{len(mode_bytes)}s'
    return struct.pack(fmt, opcode, filename_bytes, mode_bytes)
#:

def unpack_rrq(packet: bytes) -> tuple[str, str]:
    return _unpack_rrq_wrq(RRQ, packet)
#:
def unpack_wrq(packet: bytes) -> tuple[str, str]:
    return _unpack_rrq_wrq(WRQ, packet)
#:

def _unpack_rrq_wrq(opcode: int, packet: bytes) -> tuple[str, str]:
    received_opcode = unpack_opcode(packet)
    if opcode != received_opcode:
        raise TFTPValueError(f'Invalid opcode: {received_opcode}. Expected opcode: {opcode}')
    delim_pos = packet.index(b'\x00', 2)
    filename = packet[2: delim_pos].decode()
    mode = packet[delim_pos + 1:-1].decode()
    return filename, mode
#:

def pack_dat(block_number:int, data: bytes) -> bytes:
    if not 0 <= block_number <= MAX_BLOCK_NUMBER:
        err_msg = f'Block number {block_number} larger than allowed ({MAX_BLOCK_NUMBER})'
        raise TFTPValueError(err_msg)
    if len(data) > MAX_DATA_LEN:
        err_msg = f'Data size {block_number} larger than allowed ({MAX_DATA_LEN})'
        raise TFTPValueError(err_msg)
    
    fmt = f'!HH{len(data)}s'
    return struct.pack(fmt, DAT, block_number, data)
#:

def unpack_dat(packet: bytes) -> tuple[int, bytes]:
    opcode, block_number = struct.unpack('!HH', packet[:4])
    if opcode != DAT:
        raise TFTPValueError(f'Invalid opcode {opcode}. Expecting {DAT=}.')
    return block_number, packet[4:]
#:

def pack_ack(block_number: int) -> bytes:
    if not 0 <= block_number <= MAX_BLOCK_NUMBER:
        err_msg = f'Block number {block_number} larger than allowed ({MAX_BLOCK_NUMBER})'
        raise TFTPValueError(err_msg)
    
    return struct.pack(f'!HH', ACK, block_number)
#:

def unpack_ack(packet: bytes) -> int:
    opcode, block_number = struct.unpack('!HH', packet)
    if opcode != ACK:
        raise TFTPValueError(f'Invalid opcode {opcode}. Expecting {DAT=}.')
    return block_number
#:

def pack_err(error_code: int, error_msg: str | None = None) -> bytes:
    if error_code not in ERROR_MESSAGES:
        raise TFTPValueError(f'Invalid error code {error_code}')
    if error_msg is None:
        error_msg = ERROR_MESSAGES[error_code]
    error_msg_bytes = error_msg.encode() + b'\x00'
    fmt = f'!HH{len(error_msg_bytes)}s'
    return struct.pack(fmt, ERR, error_code, error_msg_bytes)
#:

def unpack_err(packet: bytes) -> tuple[int, str]:
    opcode, error_code = struct.unpack('!HH', packet[:4])
    if opcode != ERR:
        raise TFTPValueError(f'Invalid opcode: {opcode}. Expected opcode: {ERR=}')
    return error_code, packet[4:-1].decode()
#:

def unpack_opcode(packet: bytes) -> int:
    opcode, *_ = struct.unpack('!H', packet[:2])
    if opcode not in (RRQ, WRQ, DAT, ACK, ERR):
        raise TFTPValueError(f'Invalid opcode {opcode}')
    return opcode
#:
def pack_wrq(filename: str, mode: str = DEFAULT_MODE) -> bytes:
    return _pack_rrq_wrq(WRQ, filename, mode)

def unpack_wrq(packet: bytes) -> tuple[str, str]:
    return _unpack_rrq_wrq(WRQ, packet)


# Falta fazer o wwq! <<<<<<<<<<<<
# Gravar com um nome diferente localmente com o nome que tem remotamente <<<<<<<<<

###############################################################
##                                                           ##
##                  ERRORS AND EXCEPTIONS                    ##
##                                                           ##     
###############################################################

class TFTPValueError(ValueError):
    pass
#:

class NetworkError(Exception):
    """
    Any network error, like "host not found", timeouts, etc.
    """
#:
    
class ProtocolError(NetworkError):
    """
    A protocol error like unexpected or invalid opcode, wrong block 
    number, or any other invalid protocol parameter.
    """
#:
    
class Err(Exception):
    """
    An error sent by the server. It may be caused because a read/write
    can't be processed. Read and write errors during file transmission
    also cause this message to be sent, and transmission is then 
    terminated. The error number gives a numeric error code, followed
    by an ASCII error message that might contain additional, operating
    system specific information.
    """
    def __init__(self, error_code: int, error_msg: str):
        super().__init__(f'TFTP Error {error_code}')
        self.error_code = error_code
        self.error_msg = error_msg
    #:
#:
def is_ascii_printable(txt: str) -> bool:
    return set(txt).issubset(string.printable)
    # ALTERNATIVA: return not set(txt) - set(string.printable)
