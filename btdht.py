import struct
import socket
import binascii
import threading
import os
import random
import asyncio
import bencoder
import kad
import collections

ID_LENGTH = 160
KBUCKET_K = 8
ANNOUNCE_IMPLIED_PORT = 1
TRANSACTION_ID_MOD = 10000
ANNOUNCEMENT_STORAGE_SIZE = 5000


class DHTQueryTimeoutError(BaseException):
    pass


def encode_id(id):
    assert isinstance(id, int)
    assert id < 2 ** ID_LENGTH
    return binascii.unhexlify('{:040X}'.format(id))


def decode_id(data):
    assert isinstance(data, bytes)
    assert len(data) <= ID_LENGTH
    return int(binascii.hexlify(data), base=16)


class PeerContactInfo:
    def __init__(self, ip, port):
        if not isinstance(ip, str):
            ip = socket.inet_ntoa(ip)

        self.ip = ip
        self.port = port

    @property
    def packed_ip(self):
        return socket.inet_aton(self.ip)

    def encode(self):
        return self.bin_format.pack(self.packed_ip, self.port)

    @staticmethod
    def decode(data):
        ip, port = PeerContactInfo.bin_format.unpack(data)
        return PeerContactInfo(ip, port)

    bin_format = struct.Struct('!4sH')


class NodeContactInfo:
    def __init__(self, id, ip, port):
        if not isinstance(ip, str):
            ip = socket.inet_ntoa(ip)
        if not isinstance(id, int):
            id = decode_id(id)

        self.id = id
        self.ip = ip
        self.port = port

    @property
    def packed_ip(self):
        return socket.inet_aton(self.ip)

    @property
    def packed_id(self):
        return encode_id(self.id)

    def encode(self):
        return self.bin_format.pack(self.packed_id, self.packed_ip, self.port)

    @staticmethod
    def decode(data):
        id, ip, port = NodeContactInfo.bin_format.unpack(data)
        return NodeContactInfo(id, ip, port)

    @staticmethod
    def iter_decode(data):
        for id, ip, port in NodeContactInfo.bin_format.iter_unpack(data):
            yield NodeContactInfo(id, ip, port)

    bin_format = struct.Struct('!20s4sH')


class DHTNode:
    def __init__(self, id, ip, port, client_version=b'DS00', loop=None, krpc_timeout=5.0):
        if not isinstance(id, int):
            id = decode_id(id)
        if not isinstance(ip, str):
            ip = socket.inet_ntoa(ip)

        self.id = id
        self.ip = ip
        self.port = port
        self.version = client_version
        self.krpc_timeout = krpc_timeout
        self.kbucket = kad.KBucket(KBUCKET_K, ID_LENGTH, id)
        self.event_bootstrap_done = asyncio.Event()

        self._kbucket_lock = threading.Lock()
        self._transaction_counter = random.randrange(TRANSACTION_ID_MOD)
        self._transaction_counter_lock = threading.Lock()
        self._transaction_map = {}

        self._query_handler_method_map = {
            b'ping': self._ping_received,
            b'find_node': self._find_node_received,
            b'get_peers': self._get_peers_received,
            b'announce_peer': self._announce_peer_received
        }
        self._query_future_map = {}

        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop
        self.transport = None
        self.protocol = None

        self.announcements = AnnouncementStorage(ANNOUNCEMENT_STORAGE_SIZE)
        self.good_nodes = {self.id}

    async def async_bind(self):
        transport, protocol = await self._loop.create_datagram_endpoint(
            lambda: DHTProtocol(self), local_addr=(self.ip, self.port)
        )
        self.transport = transport
        self.protocol = protocol

    def bind(self):
        self._loop.run_until_complete(self.async_bind())

    def unbind(self):
        self.transport.close()
        self.transport = None
        self.protocol = None

    async def async_query(self, method_name, ip, port, timeout=None, *args, **kwargs):
        if timeout is None:
            timeout = self.krpc_timeout
        method = getattr(self, '_send_' + method_name)
        transaction_id = method(*args, ip=ip, port=port, **kwargs)
        future = self._loop.create_future()
        future_key = (ip, port, transaction_id)
        self._query_future_map[future_key] = future
        future.__dht_method_name = method_name

        def timeout_check():
            if future_key in self._query_future_map:
                del self._query_future_map[future_key]
            if not future.done():
                future.set_exception(DHTQueryTimeoutError)

        self._loop.call_later(timeout, timeout_check)
        return await future

    def _send_ping(self, ip, port):
        transaction_id = self._generate_transaction_id()
        payload = {
            b't': transaction_id,
            b'y': b'q',
            b'q': b'ping',
            b'a': {b'id': self.packed_id},
        }
        self.transport.sendto(bencoder.encode(payload), (ip, port))
        return transaction_id

    def _send_find_node(self, id, ip, port):
        transaction_id = self._generate_transaction_id()
        payload = {
            b't': transaction_id,
            b'y': b'q',
            b'q': b'find_node',
            b'a': {
                b'id': self.packed_id,
                b'target': encode_id(id),
            },
        }
        self.transport.sendto(bencoder.encode(payload), (ip, port))
        return transaction_id

    def _send_get_peers(self, info_hash, ip, port):
        transaction_id = self._generate_transaction_id()
        payload = {
            b't': transaction_id,
            b'y': b'q',
            b'q': b'get_peers',
            b'a': {
                b'id': self.packed_id,
                b'info_hash': encode_id(info_hash),
            },
        }
        self.transport.sendto(bencoder.encode(payload), (ip, port))
        return transaction_id

    def _send_announce_peer(self, info_hash, token, ip, port):
        transaction_id = self._generate_transaction_id()
        payload = {
            b't': transaction_id,
            b'y': b'q',
            b'q': b'announce_peer',
            b'a': {
                b'id': self.packed_id,
                b'info_hash': encode_id(info_hash),
                b'token': token,
                b'port': self.port,
                b'implied_port': ANNOUNCE_IMPLIED_PORT,
            },
        }
        self.transport.sendto(bencoder.encode(payload), (ip, port))
        return transaction_id

    def _send_error(self, code, msg, ip, port):
        transaction_id = self._generate_transaction_id()
        if isinstance(msg, str):
            msg = msg.encode('utf-8')
        payload = {
            b't': b'E' + transaction_id,
            b'y': b'e',
            b'e': [code, msg],
        }
        self.transport.sendto(bencoder.encode(payload), (ip, port))
        return transaction_id

    def _ping_received(self, arg, ip, port):
        node_id = arg.get(b'id')
        if not node_id:
            return None
        return {b'id': self.packed_id}

    def _find_node_received(self, arg, ip, port):
        node_id = arg.get(b'id')
        target_id = arg.get(b'target')
        if not node_id or not target_id:
            return None
        node_id = decode_id(node_id)
        target_id = decode_id(target_id)
        result = b''
        for id, (ip, port) in self.kbucket.find_nodes(target_id):
            result += NodeContactInfo(id, ip, port).encode()
        #print('find_node {:040X} wants {:040X}'.format(node_id, target_id))
        return {b'id': self.packed_id, b'nodes': result}

    def _get_peers_received(self, arg, ip, port):
        node_id = arg.get(b'id')
        info_hash = arg.get(b'info_hash')
        if not node_id or not info_hash:
            return None
        node_id = decode_id(node_id)
        info_hash = decode_id(info_hash)

        #print('get_peers {:040X} wants {:040X}'.format(node_id, info_hash))

        values = self.announcements.search(info_hash)
        if values:
            result = b''
            for id, ip, port in values:
                result += NodeContactInfo(id, ip, port).encode()
            return {b'id': self.packed_id, b'values': result, b'token': os.urandom(8)}
        else:
            result = b''
            for id, (ip, port) in self.kbucket.find_nodes(info_hash):
                result += NodeContactInfo(id, ip, port).encode()
            return {b'id': self.packed_id, b'nodes': result, b'token': os.urandom(8)}

    def _announce_peer_received(self, arg, ip, port):
        node_id = arg.get(b'id')
        info_hash = arg.get(b'info_hash')
        if not node_id or not info_hash:
            return None
        node_id = decode_id(node_id)
        info_hash = decode_id(info_hash)
        self.announcements.add(info_hash, node_id, ip, port)
        print('announce_peer {}/{} {:040X} has {:040X}'.format(
            len(self.announcements.queue), self.announcements.max_size, node_id, info_hash
        ))
        return {b'id': self.packed_id}

    async def bootstrap(self, bootstrap_nodes):
        self.kbucket.remove(self.id)

        async def ping(ip, port):
            try:
                await self.async_query('ping', ip, port)
            except DHTQueryTimeoutError:
                pass

        await asyncio.wait(
            [asyncio.ensure_future(ping(socket.gethostbyname(ip), port), loop=self._loop) for ip, port in bootstrap_nodes],
            loop=self._loop
        )
        if len(list(self.kbucket.keys())) == 0:
            raise RuntimeError('bootstrap failed: cannot contact any bootstrap nodes: [{}]'.format(
                ', '.join('{}:{}'.format(ip, port) for ip, port in bootstrap_nodes)
            ))

        while not self.bootstraped:
            await self.keep_dht()

        self.event_bootstrap_done.set()

    async def keep_dht(self):
        async def ping(ip, port):
            try:
                await self.async_query('ping', ip, port)
            except DHTQueryTimeoutError:
                pass

        for id, (ip, port) in self.kbucket.items():
            if id in self.good_nodes:
                continue
            try:
                r = await self.async_query('find_node', ip, port, id=self.id)
            except DHTQueryTimeoutError:
                continue
            self.good_nodes.add(id)
            if b'nodes' not in r:
                continue
            for info in NodeContactInfo.iter_decode(r[b'nodes']):
                if info.id == self.id:
                    self._update_kbucket(self.id, info.ip, info.port)
                else:
                    asyncio.ensure_future(ping(info.ip, info.port), loop=self._loop)
        self.good_nodes = set(random.sample(self.good_nodes, len(self.good_nodes) // 2))
        self.good_nodes.add(self.id)

    def feed_datagram(self, data, addr):
        """called when received a UDP datagram"""
        ip, port = addr

        try:
            msg = bencoder.decode(data)
        except:
            return

        try:
            transaction_id = msg[b't']
            message_type = msg[b'y']
        except KeyError:
            return

        if message_type == b'q':    # received a query
            query_type = msg.get(b'q')
            arg = msg.get(b'a')
            if not query_type or not arg:
                return
            method = self._query_handler_method_map.get(query_type)
            if not method:
                return
            response = method(arg, ip, port)
            if not response:
                return
            payload = {
                b't': transaction_id,
                b'y': b'r',
                b'r': response,
            }
            self.transport.sendto(bencoder.encode(payload), addr)

            remote_id = arg.get(b'id')
            if remote_id is not None:
                self._update_kbucket(decode_id(remote_id), ip, port)
        elif message_type == b'r':    # received a response
            arg = msg.get(b'r')
            if not arg:
                return
            future_key = (ip, port, transaction_id)
            future = self._query_future_map.get(future_key)
            if not future:
                return
            del self._query_future_map[future_key]
            future.set_result(arg)

            remote_id = arg.get(b'id')
            if remote_id is not None:
                self._update_kbucket(decode_id(remote_id), ip, port)
        else:
            return

    def _update_kbucket(self, id, ip, port):
        self.kbucket.add(id, (ip, port))

    def _generate_transaction_id(self):
        with self._transaction_counter_lock:
            self._transaction_counter += 1
            self._transaction_counter %= TRANSACTION_ID_MOD
        return str(self._transaction_counter).encode('latin-1')

    @property
    def packed_id(self):
        return encode_id(self.id)

    @property
    def bootstraped(self):
        return self.kbucket.get(self.id) is not None




class DHTProtocol(asyncio.Transport):
    def __init__(self, dht_instance):
        self.dht_instance = dht_instance
        self.transport = None

    def connection_lost(self, exc):
        print(exc)

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.dht_instance.feed_datagram(data, addr)

    def error_received(self, exc):
        print(exc)

    @property
    def loop(self):
        return self.dht_instance._loop


class AnnouncementStorage:
    def __init__(self, max_size):
        self.max_size = max_size
        self.queue = collections.deque()

    def add(self, info_hash, id, node_ip, node_port):
        value = (info_hash, id, node_ip, node_port)
        if value in self.queue:
            self.queue.remove(value)
        if len(self.queue) == self.max_size:
            self.queue.pop()
        self.queue.append(value)

    def remove(self, info_hash, id, node_ip, node_port):
        value = (info_hash, id, node_ip, node_port)
        if value in self.queue:
            self.queue.remove(value)

    def search(self, info_hash):
        result = []
        for i, id, ip, port in self.queue:
            if i == info_hash:
                result.append((id, ip, port))
        return result
