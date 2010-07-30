#!/usr/bin/env python2.6
# encoding: utf-8
##############################################################################
##############################################################################
##############################################################################
###
### mini_cache.py
###
### Copyright (c) 2010 Cambridge Visual Networks Ltd.
###
### A mini cache to fire up on demand.
###
##############################################################################
##############################################################################
##############################################################################

import threading
import sys
from optparse import OptionParser
import BaseHTTPServer
import socket
import urllib
import logging
import StringIO
import ssl

from coda_network import urllib2

THE_INTERWEBS = {
('http://news.bbc.co.uk/', ''):
                {
                'code' : 200,
                'response': 'VVVVVVV',
                'headers' : [],
                },
('https://camvine.codaview.com/', ''):
                {
                'code' : 200,
                'response': 'YYYYYYY',
                'headers' : [],
                },
}

class ProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def __init__(self, request, address, obj):
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, request, address, obj)

    def do_GET(self):
        # Any GET attempt we assume is someone using the normal HTTP proxy
        # type interface
        try:
            logging.log(1, 'GET request: %s %s' % (self.path, self.client_address[0]))
            self.handle_proxy_interface('GET')
        except Exception, e:
            logging.exception('do_GET failed with %r' % e)

    def do_POST(self):
        "post decides on the path which handler it should call."
        try:
            logging.log(1, 'POST request: %s %s' % (self.path, self.client_address[0]))
            self.handle_proxy_interface('POST')
        except Exception, e:
            logging.exception('do_POST failed with %r' % e)

    def do_CONNECT(self):
        self.wfile.write("%s 200 Connection established\r\n" % self.protocol_version)
        self.wfile.write("Proxy-agent: %s\r\n" % "blah")
        self.wfile.write("\r\n")
        self.connection = ssl.wrap_socket(self.connection, server_side=True, keyfile='server.key', certfile='server.crt')

        # rewrite request line, url to abs
        first_line = ''
        while True:
            chr = self.connection.read(1)
            # EOF?
            if chr == '':
                # bad request
                self.connection.close()
                return
            # newline(\r\n)?
            if chr == '\r':
                chr = self.connection.read(1)
                if chr == '\n':
                    # got
                    break
                else:
                    # bad request
                    self.connection.close()
                    return
            # newline(\n)?
            if chr == '\n':
                # got
                break
            first_line += chr
        # got path, rewrite
        (method, path, ver) = first_line.split()

        # forward https request
        self.connection.settimeout(1)
        while True:
            try:
                data = self.connection.read(8192)
            except ssl.SSLError, e:
                if str(e).lower().find('timed out') == -1:
                    # error
                    self.connection.close()
                    return
                # timeout
                break
            if data != '':
                pass
            else:
                # EOF
                break
        self.connection.setblocking(True)

        host, port = urllib.splitport(self.path)
        if port == None:
            port = 443
        else:
            port = int(port)
        postdata = ''
        response = THE_INTERWEBS[('https://%s%s' % (host, path), postdata)]

        self.connection.send('HTTP/1.1 %s OK\r\n' % (response['code'], ))
        self.connection.send('Content-Length: %s\r\n' % (len(response['response']), ))
        self.connection.send('\r\n')
        self.connection.send(response['response'])

        # clean
        self.connection.shutdown(socket.SHUT_WR)
        self.connection.close()

    def handle_proxy_interface(self, method):
        try:
            url = self.path
            if method == 'GET':
                postdata = ''

            elif method == 'POST':
                content_length = self.headers.getheader('content-length')
                content_length = int(content_length)
                postdata = self.rfile.read(content_length)

            logging.debug('Executing urllib2 with URL %r' % url)

            try:
                response = THE_INTERWEBS[(url, postdata)]
                self._do_send_code(response['code'])
                self._do_send_headers([('Content-Length', len(response['response']))])
                self._do_send_content(StringIO.StringIO(response['response']))

            except Exception, e:
                logging.exception('%r' % e)
                self._do_send_code(404)

            # DOWNLOAD_OK
            logging.debug('Complete %s %s' % (url, postdata))

        except Exception, e:
            logging.exception('%r' % e)

    def _do_send_code(self, code):
        """Send the response code."""
        try:
            self.send_response(code)
        except socket.error:
            logging.exception('')
        except Exception:
            logging.exception('')

    def _do_send_headers(self, extra_headers):
        """Send the headers to the requestee."""
        try:
            for header, value in extra_headers:
                self.send_header(header, value)
            self.end_headers()
        except socket.error:
            logging.exception('')
        except Exception:
            logging.exception('')

    def _do_send_content(self, data):
        """Send the content of the response."""
        def read_in_chunks(file_object, chunk_size=8192):
            """Lazy function (generator) to read a file piece by piece.
            Default chunk size: 8k."""
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

class ProxyServer(object):
    # Run a proxy server in a separate thread
    def __init__(self, port):
        self.port = port

    def start(self):
        # Don't worry about performance as requests will be sequential.
        self.request_server = BaseHTTPServer.HTTPServer(('', self.port), ProxyHandler)
        self.request_thread = threading.Thread(target=self.request_server.serve_forever)
        self.request_thread.setDaemon(True)
        self.request_thread.start()

    def stop(self):
        if self.request_server:
            self.request_server.shutdown()
            del self.request_server
            self.request_server = None
        if self.request_thread:
            self.request_thread.join()
            del self.request_thread
            self.request_thread = None

def main():
    parser = OptionParser(usage='Usage: %prog [options] (-h for help)')
    parser.add_option('-p', '--port', dest='port', default='8088')
    options, args = parser.parse_args()

    proxy_server = 'http://localhost:%s' % options.port
    proxy_handler = urllib2.ProxyHandler({
                                        'http': proxy_server,
                                        'https': proxy_server,
                                        })

    proxy = ProxyServer(int(options.port))
    proxy.start()

    headers = None
    timeout_sec = 5
    for url, postdata in THE_INTERWEBS:
        print '****************'
        url_req = urllib2.Request(url, postdata)
        if headers:
            for item, val in headers:
                url_req.add_header(item, val)

        handlers = [proxy_handler]
        url_opener = urllib2.build_opener(*handlers)

        handle = None
        if timeout_sec:
            handle = url_opener.open(url_req, timeout=timeout_sec)

        print handle.info().items()
        print handle.read()
        print '****************'

    proxy.stop()

    return 0

if __name__ == "__main__":
    sys.exit(main())
