#!/usr/bin/env python2.6
# encoding: utf-8
##############################################################################
##############################################################################
##############################################################################
###
### mini_proxy.py
###
### A mini proxy to fire up on demand.
###
##############################################################################
##############################################################################
##############################################################################

import BaseHTTPServer
from SocketServer import ForkingMixIn
import sys
from optparse import OptionParser
import socket
import urllib
import logging

from coda_network import urllib2
from coda_network import ntlm_auth
from coda_network.utilities import create_download_handle
from coda_network.connect import do_connect_chain

DEFAULT_PORT = 8088

class ProxyResponder(BaseHTTPServer.BaseHTTPRequestHandler):
    def __init__(self, request, address, server):
        self.method = 'GET'
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, request, address, server)

    def do_GET(self):
        # Any GET attempt we assume is someone using the normal HTTP proxy
        # type interface
        try:
            self.method = 'GET'
            logging.log(1, 'GET request: %s %s' % (self.path, self.client_address[0]))
            self.handle_proxy_interface()
        except Exception, e:
            logging.exception('do_GET failed with %r' % e)

    def do_POST(self):
        try:
            self.method = 'POST'
            logging.log(1, 'POST request: %s %s' % (self.path, self.client_address[0]))
            self.handle_proxy_interface('')
        except Exception, e:
            logging.exception('do_POST failed with %r' % e)

    def do_CONNECT(self):
        try:
            logging.log(1, 'do_CONNECT PATH %r' % self.path)

            host, port = urllib.splitport(self.path)
            if port == None:
                port = 443
            else:
                port = int(port)

            do_connect_chain(host, port, self.server.get_proxy_handlers(), self.connection, self.wfile, self.protocol_version)

        except Exception, e:
            logging.exception('%r' % e)

    def handle_proxy_interface(self, postdata=None):
        try:
            url = self.path
            if self.headers.has_key('content-length'):
                content_length = self.headers.getheader('content-length')
                content_length = int(content_length)
                postdata = self.rfile.read(content_length)

            logging.debug('Executing urllib2 with URL %r' % url)

            handle = None
            try:
                handle = create_download_handle(url,
                                        postdata,
                                        self.server.get_proxy_handlers(),
                                        None,
                                        None)

                self._do_send_code(200)
                self._do_send_headers(handle.info().items())
                self._do_send_content(handle)

            except urllib2.HTTPError, e:
                logging.error('%r' % e)
                # Generic HTTP error handling:
                self._do_send_code(e.code)

            except Exception, e:
                logging.exception('%r' % e)
                self._do_send_code(404)

            finally:
                if handle:
                    handle.close()

            # DOWNLOAD_OK
            logging.debug('Complete %s' % (url))

        except Exception, e:
            logging.exception('%r' % e)

    def _do_send_code(self, code):
        try:
            self.send_response(code)
        except socket.error:
            logging.exception('')
        except Exception:
            logging.exception('')

    def _do_send_headers(self, extra_headers):
        try:
            for header, value in extra_headers:
                self.send_header(header, value)
            self.end_headers()
        except socket.error:
            logging.exception('')
        except Exception:
            logging.exception('')

    def _do_send_content(self, data):
        def read_in_chunks(file_object, chunk_size=8192):
            # Lazy function (generator) to read a file piece by piece.
            while True:
                data = file_object.read(chunk_size)
                if not data:
                    break
                yield data

        try:
            # Lets use 8k - might be reasonable.
            for chunky_data in read_in_chunks(data, 8192):
                self.wfile.write(chunky_data)
        except socket.error:
            logging.exception('')
        except Exception:
            logging.exception('')


class ProxyServer(ForkingMixIn, BaseHTTPServer.HTTPServer):
    proxy_handlers = None

    def set_proxy_handlers(self, proxy_handlers):
        self.proxy_handlers = proxy_handlers

    def get_proxy_handlers(self):
        return self.proxy_handlers

def start_server(listen_address, listen_port, proxy_handlers):
    proxy_server = ProxyServer((listen_address, listen_port), ProxyResponder)
    proxy_server.set_proxy_handlers(proxy_handlers)
    logging.debug('Starting proxy server %s on %s' % (listen_address, listen_port))
    proxy_server.serve_forever()

def parse_proxy(proxy_type, address, user, password, realm):
    if proxy_type and address:
        proxy_handler = urllib2.ProxyHandler({'http': address,
                                            'https': address})
        if proxy_type == 'noauth':
            return [proxy_handler]
        elif proxy_type == 'basic':
            password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
            password_mgr.add_password(None, address, user, password)
            return [proxy_handler, urllib2.ProxyBasicAuthHandler(password_mgr)]
        elif proxy_type == 'digest':
            password_mgr = urllib2.HTTPPasswordMgr()
            password_mgr.add_password(realm, address, user, password)
            return [proxy_handler, urllib2.ProxyDigestAuthHandler(password_mgr)]
        elif proxy_type == 'ntlm':
            password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
            user_and_domain = '%s\\%s' % (realm, user)
            password_mgr.add_password(None, address, user_and_domain, password)
            return [proxy_handler, ntlm_auth.ProxyNtlmAuthHandler(password_mgr)]

    return []

def main():
    parser = OptionParser(usage='Usage: %prog [options] (-h for help)')
    parser.add_option('--listen-address', dest='listen_address', default='', help='Listening address of the proxy')
    parser.add_option('--port', dest='port', default='%s' % DEFAULT_PORT, help='Listening port of the proxy')
    parser.add_option('--proxy-type', dest='proxy_type', default=None, help='Type of proxy to connect to [noauth, basic, digest, ntlm]')
    parser.add_option('--proxy', dest='proxy_address', default=None, help='Address of the upstream proxy')
    parser.add_option('--user', dest='user', default=None, help='User name for an authenticated proxy')
    parser.add_option('--password', dest='password', default=None, help='Password for authenticated proxy')
    parser.add_option('--realm', dest='realm', default=None, help='Real for digest, also is domain for NTLM')
    options, args = parser.parse_args()

    proxy_handlers = []
    if options.proxy_type:
        proxy_handlers = parse_proxy(options.proxy_type,
                                    options.proxy_address,
                                    options.user,
                                    options.password,
                                    options.realm)

    start_server(options.listen_address, int(options.port), proxy_handlers)

    return 0

if __name__ == "__main__":
    sys.exit(main())
