#!/usr/bin/env python
# encoding: utf-8
##############################################################################
##############################################################################
##############################################################################
###
### Test network configuration
###
##############################################################################
##############################################################################
##############################################################################

# Example commandline: python test_network_config.py --url https://encrypted.google.com --proxy-type noauth --proxy http://192.168.1.100:3128

import sys
from optparse import OptionParser

# Here we are monkey patching socket so that we see ALL connections.
import socket
old_create_connection = socket.create_connection
def new_create_connection(host_port, timeout):
    print '******************** SOCKET CONNECTING  HOST %s PORT %s ********************' % host_port
    return old_create_connection(host_port, timeout)
socket.create_connection = new_create_connection

from coda_network import urllib2
from coda_network import ntlm_auth
from coda_network.utilities import create_download_handle

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
            if realm != None:
                password_mgr = urllib2.HTTPPasswordMgr()
                password_mgr.add_password(realm, address, user, password)
            else:
                password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
                password_mgr.add_password(None, address, user, password)
            return [proxy_handler, urllib2.ProxyDigestAuthHandler(password_mgr)]
        elif proxy_type == 'ntlm':
            password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
            user_and_domain = '%s\\%s' % (realm, user)
            password_mgr.add_password(None, address, user_and_domain, password)
            return [proxy_handler, ntlm_auth.ProxyNtlmAuthHandler(password_mgr)]

    return []

def make_request(url, postdata='', proxy_handlers=None):
    handlers = [urllib2.HTTPHandler(debuglevel=100), urllib2.HTTPSHandler(debuglevel=100)]
    if proxy_handlers:
        handlers.extend(proxy_handlers)

    opener = urllib2.build_opener(*handlers)

    url_req = urllib2.Request(url, postdata)

    handle = None
    try:
        handle = opener.open(url_req)
        print '****************************** HEADERS ******************************'
        print handle.info()
        print '****************************** CONTENT ******************************'
        print handle.read()

    except urllib2.HTTPError as e:
        print 'Error code:', e.code, 'Exception:', str(e)

    except urllib2.URLError as e:
        code, errstr = e.reason
        print 'Error code:', code, 'Exception:', errstr

    except Exception as e:
        print 'Exception:', str(e)

    finally:
        if handle:
            handle.close()
            handle = None

def main():
    parser = OptionParser(usage='Usage: %prog [options] (-h for help)')
    parser.add_option('--url', dest='url', help='The URL to request')
    parser.add_option('--post', dest='post', default=None, help='The postdata for the URL')
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

    make_request(options.url, options.post, proxy_handlers)

    return 0

if __name__ == "__main__":
    sys.exit(main())

