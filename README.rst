============
coda_network
============

Author: Garry Bodsworth
Website: http://www.fragmentedmemory.com

Thanks to Camvine http://www.camvine.com for allowing the source to be published.

The changes are based on the Python 2.6 maintenance branch so it should in theory work with all versions of 2.6 Python (and I suppose possibly the 2.7 release).  The changes were maintained as patched derived classes, but now they are integrated into urllib2 and httplib directly in an attempt to eventually get these changes or something similar to them upstream.

In the repository there are the new httplib/urllib2 files which can be dropped in.  They have been made part of a coda_network package along with a few other helper files.

The Files
=========

**urllib2.py**
Based off http://svn.python.org/view/python/branches/release26-maint/Lib/urllib2.py?view=markup revision 81637
The only public API change is that Request now has an optional "method" parameter.

**httplib.py**
Based off http://svn.python.org/view/python/branches/release26-maint/Lib/httplib.py?view=markup revision 81688
The only public API change is that the HTTPResponse object has a tunnel True/False parameter so we know if the response is from a normal request or a tunnelling request.

**utilities.py**
Some simple wrappers I use to expose the functionality.  This also provides a really basic do_download functions to do downloading with minimum of fuss.  This stuff is a bit specific to me.

**connect.py**
This is to allow connecting to a vanilla socket whilst reusing all the proxy auto code (rather than the rather painful process of not being able to reuse it).

**oauth_auth.py**
This provides the HTTP authentication handlers for OAuth authentication.

**oauth subdirectory**
The helper functions for making OAuth requests.  Some of this is cribbed from http://github.com/simplegeo/python-oauth2  I tried to factor out all the OAuth specific stuff so that it has minimal dependencies on the logic of how requests are made.

**ntlm_auth.py**
This provides the proxy and HTTP authentication handlers.

**ntlm subdirectory**
This is a copy of a portion of the code from python-ntlm http://code.google.com/p/python-ntlm/

**mini_proxy.py**
A proxy written using the new funky networking code that can connect to upstream proxies of the following type: noauth, basic, digest, ntlm.

Fixes and features provided
===========================

* The request object now provides a method.  This is handy for doing requests like OPTIONS which are necessary for cross-domain javascript or proper HEAD requests.
* Allow digest proxy authentication to work by retrieving the correct location and the correct password because these were previously designed only for HTTP auto.  Also for digest auto of proxies it requires the CONNECT information to generate the digest correctly.
* Remove the cyclic dependency in constructing the response passed to the higher levels thanks to a member function being assigned to a member variable.  This is done in the simplest way possible by wrapper the receiver in a simple class adapter, it could have been done by using weakmethods, but it works.
* Tunnelling HTTPS through proxies is fixed.
* Added the optional socket_keepalive in order to do deliberately long-lived connections (for long-poll).  This is available for HTTP and HTTPS.
* A very important part with CONNECT errors was to make sure it is exposed at the right time.  This then allows for proxies and other things that require retrying to work.  Previously a socket error was thrown immediately, whereas now it is exposed through the getresponse() function which allows the call stack to make the right judgements on the error code.
* Allow the specification of a certificate for HTTPS connections such that secure connections to remote servers can be made.
* Rather than using simple socket sends when doing tunnelling it now uses the standard HTTPConnection putrequest(), putheader() and endheaders().
* Improve some of the messaging in the error handling so we can reason about some of the errors.
* Add the ability for connections to be kept alive with Keep-Alive when the connection/proxy connection specifies it.  I noticed digest is really not happy with this.
* Add NTLM authentication using the python-ntlm files for generating the hashes which in turn is from NTLMAPS as far as I can see.  This works for both proxies and www-authenticate.  The connection Keep-Alive is really important for NTLM as the Windows servers require the socket connection to be kept open continually.

What coda_network can do
========================

* Use the following proxy types - normal, basic authentication, digest authentication, NTLM authentication.
* Authenticate websites - basic authentication, digest authentication, NTLM authentication.
* Request types - any you can think of.

Known limitations
=================
Digest authentication of a website when going through a proxy seems broken.  This is probably due to the source of the request in generating the hash.  It is such corner case that I am not looking into it right now.

MINI PROXY
==========

This is a small but fully functioning tool for use as a proxy.  This will also connect to upstream proxies so can be used as say a bridge to connect to NTLM resources or indeed to the Internet in a hostile Windows network environment.

Options:

* -h, --help            show this help message and exit
* --listen-address = Listening address of the proxy
* --port = Listening port of the proxy
* --proxy-type = Type of proxy to connect to [noauth, basic, digest, ntlm]
* --proxy = Address of the upstream proxy
* --user = User name for an authenticated proxy
* --password = Password for authenticated proxy
* --realm= = Real for digest, also is domain for NTLM

Example invocations:

* python mini_proxy.py
    This will just act as a simple proxy gateway.
* python mini_proxy.py --port=8912
    This will just act as a simple proxy gateway but on port 8912.
* python mini_proxy.py --proxy-type=basic --user=myuser --password=mypassword --proxy=http://192.168.100.100:8080
    This will act as a proxy to an basic authentication proxy.
* python mini_proxy.py --proxy-type=digest --user=myuser --password=mypassword --realm=myrealm --proxy=http://192.168.100.100:8080
	This will act as a proxy to a digest authenticated proxy.
* python mini_proxy.py --proxy-type=ntlm --user=myuser --password=mypassword --realm=mydomain --proxy=http://192.168.100.100:8080
    This will act as a proxy to an NTLM Threat Management Gateway oojimaflip.

FAQ
===

**What versions of Python are supported?**
  It was written and tested on a Linux system with 2.6.4.  It has worked with a couple of different revisions of 2.6.  Version 2.7 has been tested as the code has been rebased on the trunk of that (see the README in the original directory).

**Any plans to port to Python 3.0, 3.1, 3.2, etc?**
  Nope.  I don't have a need for it right now, but I think it should be possible to port these fixes when the time comes.
