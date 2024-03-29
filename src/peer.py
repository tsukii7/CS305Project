import sys
import os
import math

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import select
import util.simsocket as simsocket
import struct
import socket
import util.bt_utils as bt_utils
import hashlib
import argparse
import pickle
import time
import matplotlib.pyplot as plt

"""
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
"""
BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512 * 1024
HEADER_LEN = struct.calcsize("HBBHHII")
MAX_PAYLOAD = 1024
TIME_OUT = 10
ALPHA = 0.125
BETA = 0.25

CRASH_TIME_OUT = 5
addr = None

config = None
ex_output_file = None
ex_received_chunk = dict()
ex_downloading_chunkhash = dict()
ex_sending_chunkhash = []
session_dict = {}
crashed_chunkhash_list = []


class Session:
    def __init__(self, sender_socket, receiver_socket, chunk_hash):
        self.sender_socket = sender_socket
        self.receiver_socket = receiver_socket
        self.chunk_hash = chunk_hash
        self.timer = None
        self.ack_timer = None
        self.sending_buffer = None
        self.sending_buffer_size = 5
        self.sending_window_frontier = 0
        self.sending_window_backend = 0
        self.expected_seq_num = 1
        self.expected_ack_num = 1
        self.is_finished = False
        self.last_ack = None
        self.dup_ack_cnt = 1
        self.estimated_rtt = None
        self.dev_rtt = None
        self.timeout_interval = 1
        self.cwnd = 1  # 拥塞窗口
        self.ssthresh = 64
        self.cwnd_size = [self.cwnd]

    def send_all_in_sending_window(self):
        l = self.sending_window_backend
        r = self.sending_window_frontier
        for i in range(l, r):
            chunk_data = self.sending_buffer[(i - l) * MAX_PAYLOAD:(i + 1 - l) * MAX_PAYLOAD]
            # print("Seq: " + str(i + self.expected_ack_num))
            data_header = struct.pack("HBBHHII", socket.htons(52305), 3, 3, socket.htons(HEADER_LEN),
                                      socket.htons(HEADER_LEN + len(chunk_data)),
                                      socket.htonl(i + 1), socket.htonl(0))
            self.sender_socket.sendto(data_header + chunk_data, self.receiver_socket)
        self.timer = time.time()

    def send_other_in_buffer(self):
        # print("sending_window_frontier: " + str(self.sending_window_frontier))
        # print("sending_window_backend: " + str(self.sending_window_backend))
        # 根据cwnd大小调整发送缓冲区大小
        self.sending_buffer_size = math.floor(self.cwnd)
        l = self.sending_window_frontier
        r = self.sending_window_backend + self.sending_buffer_size
        for i in range(l, r):
            chunk_data = self.sending_buffer[(i - self.sending_window_backend) * MAX_PAYLOAD:(
                                                                                                     i + 1 - self.sending_window_backend) * MAX_PAYLOAD]
            data_header = struct.pack("HBBHHII", socket.htons(52305), 3, 3, socket.htons(HEADER_LEN),
                                      socket.htons(HEADER_LEN + len(chunk_data)),
                                      socket.htonl(i + 1), 0)
            self.sender_socket.sendto(data_header + chunk_data, self.receiver_socket)
            if i == self.sending_window_backend:
                self.timer = time.time()
            self.sending_window_frontier += 1

    def window_visual(self, window_size):
        plt.title("Window Size")
        plt.xlabel('time')
        plt.ylabel('cwnd')
        plt.plot(window_size, label='cwnd')
        plt.show()
        print(window_size)
        plt.savefig('cwnd.png')


def request_crash_chunkhash(sock):
    global crashed_chunkhash_list
    print("request_crash_chunkhash")
    print(f"crashed_chunkhash_list {crashed_chunkhash_list}")

    request_chunkhash = bytes()
    for hash in crashed_chunkhash_list:
        request_chunkhash += hash
    whohas_header = struct.pack("HBBHHII", socket.htons(52305), 3, 0, socket.htons(HEADER_LEN),
                                socket.htons(HEADER_LEN + len(request_chunkhash)), socket.htonl(0), socket.htonl(0))
    whohas_pkt = whohas_header + request_chunkhash

    # Step3: flooding whohas to all peers in peer list
    peer_list = config.peers
    for p in peer_list:
        if int(p[0]) != config.identity:
            sock.sendto(whohas_pkt, (p[1], int(p[2])))


def process_crash(crash_hash):
    print("process_crash")
    print(f"crash_hash {crash_hash}")
    global crashed_chunkhash_list

    crashed_chunkhash_list.append(crash_hash)
    hash_str = bytes.hex(crash_hash)
    ex_downloading_chunkhash[hash_str] = 0
    ex_received_chunk[hash_str] = bytes()


def process_download(sock, chunkfile, outputfile):
    '''
    if DOWNLOAD is used, the peer will keep getting files until it is done
    '''
    print('PROCESS GET SKELETON CODE CALLED.  Fill me in! I\'ve been doing! (', chunkfile, ',     ', outputfile, ')')
    global ex_output_file
    global ex_received_chunk
    global ex_downloading_chunkhash

    ex_output_file = outputfile
    # Step 1: read chunkhash to be downloaded from chunkfile
    download_hash = bytes()
    with open(chunkfile, 'r') as cf:
        lines = cf.readlines()
        for line in lines:
            index, datahash_str = line.strip().split(" ")
            ex_received_chunk[datahash_str] = bytes()
            ex_downloading_chunkhash[datahash_str] = 0

            # hex_str to bytes
            datahash = bytes.fromhex(datahash_str)
            download_hash += datahash

    # Step2: make WHOHAS pkt
    # |2byte magic|1byte type |1byte team|
    # |2byte  header len  |2byte pkt len |
    # |      4byte  seq                  |
    # |      4byte  ack                  |
    whohas_header = struct.pack("HBBHHII", socket.htons(52305), 3, 0, socket.htons(HEADER_LEN),
                                socket.htons(HEADER_LEN + len(download_hash)), socket.htonl(0), socket.htonl(0))
    whohas_pkt = whohas_header + download_hash

    # Step3: flooding whohas to all peers in peer list
    peer_list = config.peers
    for p in peer_list:
        if int(p[0]) != config.identity:
            sock.sendto(whohas_pkt, (p[1], int(p[2])))


def process_inbound_udp(sock):
    # Receive pkt
    global config
    global ex_sending_chunkhash
    # global start_timer
    global session_dict
    global crashed_chunkhash_list

    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack("HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    # print("struct.unpack  Seq: " + str(socket.ntohl(Seq)))
    # print("struct.unpack  Ack: " + str(socket.ntohl(Ack)))

    if Type == 0:
        print("received a WHOHAS pkt")
        # received an WHOHAS pkt
        # see what chunk the sender has
        whohas_chunk_hash_list = []
        for i in range(0, len(data), 20):
            whohas_chunk_hash_list.append(data[i:i + 20])
        ihave_chunk_hash = bytes()
        for i in range(len(whohas_chunk_hash_list)):
            whohas_chunk_hash = whohas_chunk_hash_list[i]
            # bytes to hex_str
            chunkhash_str = bytes.hex(whohas_chunk_hash)
            ex_sending_chunkhash = chunkhash_str

            print(f"whohas: {chunkhash_str}, has: {list(config.haschunks.keys())}")
            if chunkhash_str in config.haschunks:
                ihave_chunk_hash += bytes.fromhex(chunkhash_str)

        # send back IHAVE pkt
        if len(ihave_chunk_hash) > 0:
            ihave_header = struct.pack("HBBHHII", socket.htons(52305), 3, 1, socket.htons(HEADER_LEN),
                                       socket.htons(HEADER_LEN + len(ihave_chunk_hash)), socket.htonl(0),
                                       socket.htonl(0))
            ihave_pkt = ihave_header + ihave_chunk_hash
            sock.sendto(ihave_pkt, from_addr)

    elif Type == 1:
        print("received an IHAVE pkt")
        # received an IHAVE pkt
        # see what chunk the sender has
        get_chunk_hash_list = []
        for i in range(0, len(data), 20):
            get_chunk_hash_list.append(data[i:i + 20])
        get_chunk_hash = get_chunk_hash_list[0]
        if get_chunk_hash in crashed_chunkhash_list:
            crashed_chunkhash_list.remove(get_chunk_hash)
            print(f"remove crash_hash {get_chunk_hash}")

        chunkhash_str = bytes.hex(get_chunk_hash)
        chunk_hash_list = list(ex_downloading_chunkhash.keys())
        for hash in chunk_hash_list:
            # ex_downloading_chunkhash[hash] == 0 判断是否发送对应chunk_hahs的GET请求
            if chunkhash_str == hash and ex_downloading_chunkhash[hash] == 0:
                # send back GET pkt
                get_header = struct.pack("HBBHHII", socket.htons(52305), 3, 2, socket.htons(HEADER_LEN),
                                         socket.htons(HEADER_LEN + len(get_chunk_hash)), socket.htonl(0),
                                         socket.htonl(0))
                get_pkt = get_header + get_chunk_hash
                sock.sendto(get_pkt, from_addr)
                session = Session(from_addr, sock, get_chunk_hash)
                session.expected_seq_num = 1
                session_dict[(from_addr, addr)] = session
                ex_downloading_chunkhash[hash] = 1
                break
            # TODO:在全局变量中存储其他peer已有但未请求的chunk_hash
        save_chunk_hash = get_chunk_hash_list[1:]

    elif Type == 2:
        print("received an GET pkt")
        # received a GET pkt
        chunk_hash = data[:20]
        session = Session(sock, from_addr, chunk_hash)
        session_dict[(addr, from_addr)] = session
        chunkhash_str = bytes.hex(chunk_hash)
        # 根据cwnd大小调整发送缓冲区大小
        session.sending_buffer_size = math.floor(session.cwnd)
        session.sending_buffer = config.haschunks[chunkhash_str][:MAX_PAYLOAD * session.sending_buffer_size]
        session.send_other_in_buffer()



    elif Type == 3:
        print("received an DATA pkt")
        # received a DATA pkt
        if (from_addr, addr) not in session_dict:
            return
        session = session_dict[(from_addr, addr)]
        if session is None:
            return
        session.ack_timer = time.time()
        # if session is None or session.is_finished :
        #     return
        Seq_num = socket.ntohl(Seq)
        print(f" Seq:{Seq_num}")
        print("received a DATA Seq with " + str(Seq_num))
        if Seq_num != session.expected_seq_num:
            print(f"expected_seq_num: {session.expected_seq_num}")
            ack_header = struct.pack("HBBHHII", socket.htons(52305), 3, 4, socket.htons(HEADER_LEN),
                                     socket.htons(HEADER_LEN),
                                     socket.htonl(0), socket.htonl(session.expected_seq_num - 1))
            print(f"last Ack:{socket.ntohl(socket.htonl(session.expected_seq_num - 1))}")
            ack_pkt = ack_header
            sock.sendto(ack_pkt, from_addr)
        else:
            session.expected_seq_num = session.expected_seq_num + 1
            chunk_hash = session.chunk_hash
            chunkhash_str = bytes.hex(chunk_hash)
            ex_received_chunk[chunkhash_str] += data
            # print("*************************************************************************************")
            # print( bytes.hex(data))
            # print("*************************************************************************************")
            # send back ACK
            ack_header = struct.pack("HBBHHII", socket.htons(52305), 3, 4, socket.htons(HEADER_LEN),
                                     socket.htons(HEADER_LEN),
                                     socket.htonl(0), Seq)
            print(f" Ack:{socket.ntohl(Seq)}")
            ack_pkt = ack_header

            sock.sendto(ack_pkt, from_addr)

            # see if finished
            # print("len(ex_received_chunk[chunkhash_str]): " + str(len(ex_received_chunk[chunkhash_str])))
            # print("CHUNK_DATA_SIZE: " + str(CHUNK_DATA_SIZE))
            if len(ex_received_chunk[chunkhash_str]) == CHUNK_DATA_SIZE:
                # finished downloading this chunkdata!
                # dump your received chunk to file in dict form using pickle
                session.is_finished = True
                session_dict[(from_addr, addr)] = None
                with open(ex_output_file, "wb") as wf:
                    pickle.dump(ex_received_chunk, wf)

                # add to this peer's haschunk:
                config.haschunks[chunkhash_str] = ex_received_chunk[chunkhash_str]

                # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
                print(f"GOT {ex_output_file}")

                # The following things are just for illustration, you do not need to print out in your design.
                sha1 = hashlib.sha1()
                sha1.update(ex_received_chunk[chunkhash_str])
                received_chunkhash_str = sha1.hexdigest()
                print(f"Expected chunkhash: {chunkhash_str}")
                print(f"Received chunkhash: {received_chunkhash_str}")
                success = chunkhash_str == received_chunkhash_str
                print(f"Successful received: {success}")
                if success:
                    print("Congrats! You have completed the example!")
                else:
                    print("Example fails. Please check the example files carefully.")
        # else:
        # print("Seq != session.expected_seq_num Seq:" + str(Seq_num) + " expected_seq_num: " + str(
        #     session.expected_seq_num))

    elif Type == 4:
        print("received an ACK pkt")
        # received an ACK pkt
        ack_num = socket.ntohl(Ack)
        session = session_dict[(addr, from_addr)]
        chunk_hash = session.chunk_hash
        if session.last_ack is not None and session.last_ack == ack_num:
            session.dup_ack_cnt += 1
        else:
            session.dup_ack_cnt = 1
        session.last_ack = ack_num
        if session.dup_ack_cnt == 3:
            print("Duplicate ACK")
            session.cwnd = 1
            session.cwnd_size.append(session.cwnd)
            session.ssthresh = max(math.floor(session.ssthresh / 2), 2)
            session.send_all_in_sending_window()
            return
        if session.expected_ack_num == ack_num:
            # estimate RTT
            sample_rtt = time.time() - session.timer
            if session.estimated_rtt is None:
                session.estimated_rtt = sample_rtt
            if session.dev_rtt is None:
                session.dev_rtt = sample_rtt / 2
            session.estimated_rtt = (1 - ALPHA) * session.estimated_rtt + ALPHA * sample_rtt
            session.dev_rtt = (1 - BETA) * session.dev_rtt + BETA * abs(sample_rtt - session.estimated_rtt)
            session.timeout_interval = session.estimated_rtt + 4 * session.dev_rtt
            # congestion control
            if session.cwnd < session.ssthresh:  # slow start
                session.cwnd += 1
            else:
                session.cwnd = session.cwnd + 1 / session.cwnd  # 使用cwnd时需要向下取整
            session.cwnd_size.append(session.cwnd)
            session.expected_ack_num = session.expected_ack_num + 1
            chunkhash_str = bytes.hex(chunk_hash)
            if (ack_num) * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
                # finished
                print(f"finished sending {chunkhash_str}")
                #######################################################
                # session.timer = None
                session_dict[(addr, from_addr)] = None
                # print(f"finished sending {ex_sending_chunkhash}")
                session.window_visual(session.cwnd_size)
                pass
            else:
                session.sending_window_backend += 1
                if session.sending_window_backend == session.sending_window_frontier:
                    session.timer = None
                else:
                    session.timer = time.time()
                left = session.sending_window_backend * MAX_PAYLOAD
                # 根据cwnd大小调整发送缓冲区大小
                session.sending_buffer_size = math.floor(session.cwnd)
                right = MAX_PAYLOAD * (session.sending_window_backend + session.sending_buffer_size)
                session.sending_buffer = config.haschunks[chunkhash_str][left:min(right, CHUNK_DATA_SIZE)]
                session.send_other_in_buffer()
        # else:
        #     print("ack_num != session.expected_ack_num Seq:" + str(ack_num) + " expected_seq_num: " + str(
        #         session.expected_ack_num))


def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass


def peer_run(config):
    global session_dict
    global addr
    global CRASH_TIME_OUT
    global crashed_chunkhash_list

    addr = (config.ip, config.port)
    print(addr)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    time_out = config.timeout
    crash_cnt = 0
    print(f"default timeout {time_out}")

    try:
        while True:
            # TODO: 遍历session.timer，判断发送是否超时，若超时，则重传data，重置计时
            for session in list(session_dict.values()):
                if session is None:
                    continue
                print(f"timeout_interval: {session.timeout_interval}")
                if time_out == 0:
                    time_out = session.timeout_interval
                if session.timer is not None and time.time() - session.timer > time_out:
                    print("session time out")
                    print(f"Timeout: {time_out} seconds")
                    session.cwnd = 1
                    session.ssthresh = max(math.floor(session.ssthresh / 2), 2)
                    session.cwnd_size.append(session.cwnd)
                    session.send_all_in_sending_window()
                if session.ack_timer is not None and time.time() - session.ack_timer > CRASH_TIME_OUT:
                    print("session crashed")
                    process_crash(session.chunk_hash)
                    session_dict[(session.sender_socket, addr)] = None

            crash_cnt = (crash_cnt + 1) % 10
            if crash_cnt == 9 and len(crashed_chunkhash_list) > 0:
                request_crash_chunkhash(sock)

            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
                # No pkt nor input arrives during this period
                pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == '__main__':
    """
    -p: Peer list file, it will be in the form "*.map" like nodes.map.
    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in bt_utils. The loaded dictionary has the form: {chunkhash: chunkdata}
    -m: The max number of peer that you can send chunk to concurrently. If more peers ask you for chunks, you should reply "DENIED"
    -i: ID, it is the index in nodes.map
    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.
    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT. If it is set, you should not change this time out.
        The timeout will be set when running test scripts. PLEASE do not change timeout if it set.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument('-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument('-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument('-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    peer_run(config)