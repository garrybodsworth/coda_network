#!/usr/bin/env python2.6
# encoding: utf-8
##############################################################################
##############################################################################
##############################################################################
###
### connect.py
###
### This is for doing CONNECT to remote servers using urllib2.
###
##############################################################################
##############################################################################
##############################################################################

import socket
import select

from coda_network import urllib2
from coda_network import httplib

# Slight specialisation of HTTPSConnection to not do anything else apart from
# the connect to the remote server.
class HTTPSConnectConnection(httplib.HTTPSConnection):
    """
    This class performs a CONNECT to allow daisy chaining sockets.
    """

    def request(self, method, url, body=None, headers={}):
        """Send a complete request to the server."""
        if self._tunnel_host:
            self.connect_response = self._tunnel(self._tunnel_host, self._tunnel_port, self._tunnel_headers)
        # Because we want the vanilla socket then we don't perform any more
        # communication.

# Slight specialisation of HTTPSHandler to return the socket in the response
# structure so we can perform the CONNECT operations correctly.
class HTTPSConnectHandler(urllib2.HTTPSHandler):
    """
    Perform the connect.
    NOTE: Do it this way so we reuse the maximum amount of code so we can
    get the correct behaviour when punching thorugh proxies.
    """

    http_class = HTTPSConnectConnection

    def __init__(self, debuglevel=0, cert=None):
        urllib2.HTTPSHandler.__init__(self, debuglevel=debuglevel)
        self.cert = cert

    def create_response(self, h, r, full_url):
        # Pick apart the HTTPResponse object to get the addinfourl
        # object initialized properly.

        # Wrap the HTTPResponse object in socket's file object adapter
        # for Windows.  That adapter calls recv(), so delegate recv()
        # to read().  This weird wrapping allows the returned object to
        # have readline() and readlines() methods.

        # XXX It might be better to extract the read buffering code
        # out of socket._fileobject() and into a base class.

        r.recv = r.read
        fp = socket._fileobject(r, close=True)

        resp = urllib2.addinfourl(fp, r.msg, full_url)
        resp.code = r.status
        resp.msg = r.reason
        # We expose the socket for CONNECT.
        resp.connect_sock = h.sock
        return resp


###########################################################################
#
def build_connect_opener(cert=None, proxy_handlers=None, auth_handlers=None):
    """Builds the list of opener objects required for the specific type of request."""
    handlers = [HTTPSConnectHandler(cert=cert)]

    if proxy_handlers:
        handlers.extend(proxy_handlers)

    if auth_handlers:
        handlers.extend(auth_handlers)

    return urllib2.build_opener(*handlers)
#
###########################################################################


###########################################################################
#
def create_connect_handle(host, proxy_handlers, auth_handlers=None, cert=None, timeout_sec=None):
    """
    Wraps handle connect creation.
    """
    url_req = urllib2.Request(host)

    url_opener = build_connect_opener(cert, proxy_handlers, auth_handlers)

    if timeout_sec:
        return url_opener.open(url_req, timeout=timeout_sec)

    return url_opener.open(url_req)
#
###########################################################################


###########################################################################
#
def socket_read_write(soc, connection, max_idling=20, socket_timeout=20, chunk_size=8192):
    """Handle the socket communication."""
    iw = [soc, connection]
    ow = []
    count = 0
    while 1:
        count += 1
        (ins, outs, errs) = select.select(iw, ow, iw, socket_timeout)
        if errs:
            break

        if ins:
            for i in ins:
                if i is soc:
                    out = connection
                else:
                    out = soc
                data = i.recv(chunk_size)
                if data:
                    out.send(data)
                    count = 0

        else:
            # SOCKET: no data after socket_timeout? kill it
            break

        if count == max_idling:
            break
#
###########################################################################


###########################################################################
#
def do_connect_chain(host, port, proxy_handlers, auth_handlers, connection, outputfile, protocol_version):
    scheme = 'http'
    if port == 443:
        scheme = 'https'

    sock = None
    handle = None
    try:
        if proxy_handlers:
            handle = create_connect_handle('%s://%s:%d' % (scheme, host, port), proxy_handlers, auth_handlers)
            sock = handle.connect_sock
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))

        outputfile.write("%s 200 Connection established\r\n" % protocol_version)
        outputfile.write("Proxy-agent: %s\r\n" % "blah")
        outputfile.write("\r\n")

        socket_read_write(sock, connection, 100)

    finally:
        if sock:
            sock.close()

        if handle:
            handle.close()

        if connection:
            connection.close()
#
###########################################################################
