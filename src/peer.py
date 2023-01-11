import sys
import os

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

"""
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
"""
BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512 * 1024
HEADER_LEN = struct.calcsize("HBBHHII")
MAX_PAYLOAD = 1024
TIME_OUT = 3

config = None
ex_output_file = None
ex_received_chunk = dict()
# {chunk_hash:0(not GET)/chunk_hash:1(already GET)}
ex_downloading_chunkhash = dict()
ex_sending_chunkhash = []
start_timer = -1
ack_present = 1
is_timeout = False
retrans_chunk = None
retrans_addr = None


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
    global start_timer
    global ack_present
    global is_timeout
    global retrans_chunk
    global retrans_addr

    # TODO: 根据from_addr(socket)从全局变量中读取正在传输的chunk_hash(如有）
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack("HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]

    if Type == 0:
        # received an WHOHAS pkt
        # see what chunk the sender has
        whohas_chunk_hash_list = []
        for i in range(0, len(data), 20):
            whohas_chunk_hash_list.append(data[i:i + 20])
        # whohas_chunk_hash = data[:20]
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
        # received an IHAVE pkt
        # see what chunk the sender has
        get_chunk_hash_list = []
        for i in range(0, len(data), 20):
            get_chunk_hash_list.append(data[i:i + 20])
        if len(get_chunk_hash_list) == 1:
            get_chunk_hash = get_chunk_hash_list[0]
            chunkhash_str = bytes.hex(get_chunk_hash)
            chunk_hash_list = list(ex_downloading_chunkhash.keys())
            for hash in chunk_hash_list:
                # print("chunk hash:" + chunkhash_str)
                # print("hash:" + hash)
                # ex_downloading_chunkhash[hash] == 0 判断是否发送对应chunk_hahs的GET请求
                if chunkhash_str == hash and ex_downloading_chunkhash[hash] == 0:
                    # send back GET pkt
                    get_header = struct.pack("HBBHHII", socket.htons(52305), 3, 2, socket.htons(HEADER_LEN),
                                             socket.htons(HEADER_LEN + len(get_chunk_hash)), socket.htonl(0),
                                             socket.htonl(0))
                    get_pkt = get_header + get_chunk_hash
                    sock.sendto(get_pkt, from_addr)
                    # TODO:在完成三次握手后，在全局变量中建立{socket:chunk_hash}映射
                    ex_downloading_chunkhash[hash] = 1
                    break
        else:
            # TODO:在全局变量中存储其他peer已有但未请求的chunk_hash
            save_chunk_hash = get_chunk_hash_list[1:]

    elif Type == 2:
        # received a GET pkt
        # TODO: 移除报文中的chunk_hash
        chunk_hash = data[:20]
        chunkhash_str = bytes.hex(chunk_hash)
        # print("DATA chunkhash_str:" + chunkhash_str)
        chunk_data = config.haschunks[chunkhash_str][:MAX_PAYLOAD]

        # send back DATA
        chunk_hash_chunk_data = chunk_hash + chunk_data
        data_header = struct.pack("HBBHHII", socket.htons(52305), 3, 3, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN + len(chunk_hash_chunk_data)), socket.htonl(1), 0)
        sock.sendto(data_header + chunk_hash_chunk_data, from_addr)
        # TODO:添加全局变量计时器
        start_timer = time.time()
        ack_present = 1


    elif Type == 3:
        # received a DATA pkt
        chunk_hash = data[:20]
        chunkhash_str = bytes.hex(chunk_hash)
        # print("chunkhash_str:" + str(chunkhash_str))
        # print("data:" + str(bytes.hex(data)))
        # print("ex_received_chunk key:" + str(list(ex_received_chunk.keys())))
        # print("ex_received_chunk value:" + str(list(ex_received_chunk.values())))
        ex_received_chunk[chunkhash_str] += data[20:]

        # send back ACK
        # ack_pkt = struct.pack("HBBHHII", socket.htons(52305), 3, 4, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN),
        #                       0, Seq)
        ack_header = struct.pack("HBBHHII", socket.htons(52305), 3, 4, socket.htons(HEADER_LEN),
                                 socket.htons(HEADER_LEN + len(chunk_hash)),
                                 0, Seq)
        ack_pkt = ack_header + chunk_hash

        sock.sendto(ack_pkt, from_addr)

        # see if finished
        if len(ex_received_chunk[chunkhash_str]) == CHUNK_DATA_SIZE:
            # finished downloading this chunkdata!
            # dump your received chunk to file in dict form using pickle
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
            # TODO: 重置{socket:chunk_hash=None}表明没有正在传输的chunk
            if success:
                print("Congrats! You have completed the example!")
            else:
                print("Example fails. Please check the example files carefully.")

    elif Type == 4:
        # received an ACK pkt
        # TODO:结束上一个计时器
        ack_num = socket.ntohl(Ack)
        if ack_num == ack_present:
            is_timeout = False
            start_timer = -1
            chunk_hash = data[:20]
            chunkhash_str = bytes.hex(chunk_hash)
            if (ack_num) * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
                # finished
                print(f"finished sending {chunkhash_str}")
                # print(f"finished sending {ex_sending_chunkhash}")
                pass
            else:
                left = (ack_num) * MAX_PAYLOAD
                right = min((ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                # next_data = config.haschunks[ex_sending_chunkhash][left: right]
                next_data = config.haschunks[chunkhash_str][left: right]
                # send next data
                data_header = struct.pack("HBBHHII", socket.htons(52305), 3, 3, socket.htons(HEADER_LEN),
                                          socket.htons(HEADER_LEN + len(chunk_hash + next_data)),
                                          socket.htonl(ack_num + 1),
                                          0)
                retrans_chunk = data_header + chunk_hash + next_data
                retrans_addr = from_addr
                sock.sendto(data_header + chunk_hash + next_data, from_addr)
                # TODO:开始新的计时器
                start_timer = time.time()
                ack_present = ack_num + 1

    if is_timeout:  # 超时重传
        is_timeout = False
        sock.sendto(retrans_chunk, retrans_addr)
        start_timer = time.time()



def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass


def peer_run(config):
    global is_timeout
    global start_timer

    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    try:
        while True:
            # TODO: 遍历计时器，判断是否超时，若超时，则重传data，重置计时
            if start_timer != -1 and time.time() - start_timer > TIME_OUT:
                is_timeout = True
                start_timer = time.time()
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
