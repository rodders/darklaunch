#!/usr/bin/env python

import os, sys, pwd

from twisted.internet import epollreactor
# Epoll scales better on linux than select()
epollreactor.install()

from collections import defaultdict 

import pcapy
from pcapy import open_live
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from twisted.cred import portal, checkers 
from twisted.conch import manhole, manhole_ssh
from txZMQ import ZmqFactory, ZmqEndpoint, ZmqPubConnection

import dpkt
import sys
import struct

import zmq

#sys.setcheckinterval(500000)

# pcap settings
DEV          = "eth1"  # interface to listen on
MAX_LEN      = 1510         # max size of packet to capture
PROMISCUOUS  = 1            # promiscuous mode?
READ_TIMEOUT = 10           # in milliseconds

# Data packets on port 80 (ignore SYN, FIN + ACK
#PCAP_FILTER  = r'(%s) and tcp dst port 7033 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' %(valid)
#PCAP_FILTER  = r'tcp dst port 7033 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
#PCAP_FILTER   = r'tcp dst port 7033' # and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
PCAP_FILTER   = sys.argv[2]
# empty => get everything (or we could use a BPF filter)
MAX_PKTS      = -1      # number of packets to capture; -1 => no limit

context = zmq.Context()
socket = context.socket(zmq.PUSH)
socket.bind('tcp://0.0.0.0:%s' % sys.argv[1] )
socket.setsockopt(zmq.SWAP, 50000)
socket.setsockopt(zmq.HWM, 7500)

class RespPrinter(Protocol):

    def dataReceived(self, data):
        print data

def run_pcap(f):
    # start the packet capture
    p = open_live(DEV, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
    p.setfilter(PCAP_FILTER)
    print "Listening on %s: net=%s, mask=%s" % (DEV, p.getnet(), p.getmask())

    stock_decoder = None

    def ph(hdr, data, decoder=stock_decoder):
        # thread safety: call from the main twisted event loop
        reactor.callFromThread(f, data);

    p.loop(MAX_PKTS, ph)

def message_queue(uri):
    # Quick implementation until such a time as we can get smarter
    #pub_connection.publish(uri)
    socket.send(uri)

def format_ip(ip):
    return '.'.join((str(byte) for byte in struct.unpack('> B B B B', ip)))

class Echo(Protocol):

    def __init__(self, reactor):
        self.converstations = defaultdict(list)
        reactor.callInThread(run_pcap, self.pcapDataReceived)

    def pcapDataReceived(self, data):

        eth = dpkt.ethernet.Ethernet(data)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP and eth.data.p != dpkt.ip.IP_PROTO_TCP:
            return

        ip = eth.data
        tcp = ip.data
        key = (ip.src, ip.dst, tcp.sport, tcp.dport)

        if key in self.converstations:
            data = self.converstations[key]

            if not tcp.data.strip():
                return

            data.append(tcp.data)

            if tcp.flags in (dpkt.tcp.TH_PUSH + dpkt.tcp.TH_ACK,):
                del self.converstations[key]
                for l in ''.join(data).split("\n"):
                    if l.startswith("GET"):
                        message_queue(l.split()[1])
                    elif l.startswith("POST"):
                        message_queue(''.join(data))

            elif tcp.flags not in (dpkt.tcp.TH_FIN,):
                self.converstations[key] = data
        elif tcp.data and tcp.flags not in (dpkt.tcp.TH_FIN,):
            self.converstations[key].append(tcp.data)

def main():
    e = Echo(reactor)

    realm = manhole_ssh.TerminalRealm() 
    namespace = {}
    namespace.update(locals())
    del namespace['namespace']
    namespace.update(globals())
    def getManhole(_): return manhole.Manhole(namespace) 
    realm.chainedProtocolFactory.protocolFactory = getManhole
    p = portal.Portal(realm) 
    p.registerChecker(checkers.InMemoryUsernamePasswordDatabaseDontUse(admin='chamone'))
    f = manhole_ssh.ConchFactory(p) 
    reactor.listenTCP(int(sys.argv[1]) + 1000, f)

    reactor.run()

if __name__ == "__main__":
    main()
