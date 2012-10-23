#!/usr/bin/env python

import zmq
from zmq.eventloop import ioloop
ioloop.install()
from zmq.eventloop.zmqstream import ZMQStream
from tornado import httpclient
from tornado import gen

import sys
from lxml.etree import XMLSyntaxError

from urllib2 import urlparse
from urllib import urlencode

PULL_ENDPOINT = sys.argv[1]
VICTIMS = sys.argv[2:]

httpclient.AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")
http_client = httpclient.AsyncHTTPClient(max_clients=10000)

loop = ioloop.IOLoop.instance()

context = zmq.Context()
socket = context.socket(zmq.PULL)
socket.connect(PULL_ENDPOINT)
stream = ZMQStream(socket)

current_count = 0
prior_count = 0

def fetch(response):
    if response.error:
        print response.error
        print response.request.url
        print response.request.body
        print response.body
    try:
        pass
    except XMLSyntaxError as xe:
        print xe

@gen.engine
def victimise(victim, request):
    try:
        lines = request.split('\n')
        uri = lines[0].split(' ')[1]
        body = lines[-1]

        raw_url = victim + uri
        scheme, netloc, path, raw_query, fragment = urlparse.urlsplit(raw_url)
        query = urlparse.parse_qs(raw_query)
        url = urlparse.urlunsplit((scheme, netloc, path, urlencode(query, True), fragment))
        if body:
            http_client.fetch(url, fetch, method="POST", body=body, use_gzip=False)
    except:
        pass

def process_url(requests):
    for request in requests:
        victimise(VICTIMS[0], request)

stream.on_recv(process_url)
loop.start()
