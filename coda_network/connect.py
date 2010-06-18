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
