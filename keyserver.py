#!/usr/bin/env python

import os
import re
import sys
import ssl
import cgi
import socket
import base64
import urllib
import getopt
import cPickle as pickle
import binascii
import threading
import SocketServer
import BaseHTTPServer
import SimpleHTTPServer
from urlparse import parse_qs, urlparse
try:
    from pgpdump.utils import crc24
    import pgpdump
except ImportError:
    print "This keyserver requires pgpdump package. Aborting!"
    sys.exit()

application_version = '0.1'

class HttpRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def http_host(self):
        """Return the current server host, e.g. 'localhost'"""
        #rsplit removes port
        return self.headers.get('host', 'localhost').rsplit(':', 1)[0]

    def server_url(self):
        """Return the current server URL, e.g. 'http://localhost:33411/'"""
        return '%s://%s' % (self.headers.get('x-forwarded-proto', 'http'),
                            self.headers.get('host', 'localhost'))

    def send_http_response(self, code, msg):
        """Send the HTTP response header"""
        self.wfile.write('HTTP/1.1 %s %s\r\n' % (code, msg))

    def send_http_redirect(self, destination):
        self.send_http_response(302, 'Moved Temporarily')
        self.wfile.write('Location: %s\r\n\r\n' % destination)

    def send_standard_headers(self, header_list=[],
                              cachectrl='private', mimetype='text/html'):
        """
        Send common HTTP headers plus a list of custom headers:
        - Cache-Control
        - Content-Type

        This function does not send the HTTP/1.1 header, so
        ensure self.send_http_response() was called before

        Keyword arguments:
        header_list -- A list of custom headers to send, containing key-value tuples
        cachectrl   -- The value of the 'Cache-Control' header field
        mimetype    -- The MIME type to send as 'Content-Type' value
        """
        if mimetype.startswith('text/') and ';' not in mimetype:
            mimetype += ('; charset=utf-8')
        self.send_header('Cache-Control', cachectrl)
        self.send_header('Content-Type', mimetype)
        for header in header_list:
            self.send_header(header[0], header[1])
        self.end_headers()

    def send_full_response(self, message, code=200, msg='OK', mimetype='text/html',
                           header_list=[], suppress_body=False):
        """
        Sends the HTTP header and a response list

        message       -- The body of the response to send
        header_list   -- A list of custom headers to send,
                         containing key-value tuples
        code          -- The HTTP response code to send
        mimetype      -- The MIME type to send as 'Content-Type' value
        suppress_body -- Set this to True to ignore the message parameter
                         and not send any response body
        """
        message = unicode(message).encode('utf-8')
        self.log_request(code, message and len(message) or '-')
        #Send HTTP/1.1 header
        self.send_http_response(code, msg)
        #Send all headers
        if code == 401:
            self.send_header('WWW-Authenticate',
                             'Basic realm=MP%d' % (time.time()/3600))
        #If suppress_body == True, we don't know the content length
        contentLengthHeaders = []
        if not suppress_body:
            contentLengthHeaders = [ ('Content-Length', len(message or '')) ]
        self.send_standard_headers(header_list=header_list + contentLengthHeaders,
                                   mimetype=mimetype,
                                   cachectrl="no-cache")
        #Response body
        if not suppress_body:
            self.wfile.write(message or '')

    def send_file(self, filename):
        # FIXME: Do we need more security checks?
        if '..' in filename:
            code, msg = 403, "Access denied"
        else:
            try:
                fpath = os.path.realpath(filename)
                fd = open(filename)
                mimetype = mimetypes.guess_type(fpath)[0] or "application/octet-stream"
                message = fd.read()
                fd.close()
                code, msg = 200, "OK"
            except IOError, e:
                if e.errno == 2:
                    code, msg, mimetype = 404, "File not found", 'text/plain'
                elif e.errno == 13:
                    code, msg, mimetype = 403, "Access denied", 'text/plain'
                else:
                    code, msg, mimetype = 500, "Internal server error", 'text/plain'
                message = ""

        self.log_request(code, message and len(message) or '-')
        self.send_http_response(code, msg)
        self.send_standard_headers(header_list=[
                                     ('Content-Length', len(message or ''))
                                   ],
                                   mimetype=mimetype,
                                   cachectrl="must-revalidate=False, max-age=3600")
        self.wfile.write(message or '')


    def do_POST(self, method='POST'):
        (scheme, netloc, path, params, query, frag) = urlparse(self.path)

        print "Got %s request! : %s" % (method, self.path)

        post_data = { }
        try:
            ue = 'application/x-www-form-urlencoded'
            clength = int(self.headers.get('content-length', 0))
            ctype, pdict = cgi.parse_header(self.headers.get('content-type', ue))
            if ctype == 'multipart/form-data':
                post_data = cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={'REQUEST_METHOD': method,
                             'CONTENT_TYPE': self.headers['Content-Type']}
                )
            elif ctype == ue:
                if clength > 5*1024*1024:
                    raise ValueError(_('OMG, input too big'))
                post_data = cgi.parse_qs(self.rfile.read(clength), 1)
            else:
                raise ValueError(_('Unknown content-type'))

        except (IOError, ValueError), e:
            r = '<p>POST FAILBOT: %s</p>' % e
            self.send_full_response(r, code=500)
            return None
        return self.do_GET(post_data=post_data, method=method)

    def urlmapper_action(self, path, post_data):
        if path == "/":
            return "text/html", self.build_html_index()
        elif path == '/pks/lookup':
            return "text/plain", self.search(path)
        elif path == '/pks/add':
            return "text/plain", self.get_key(post_data)
        else:
            print path
            return "text/html", path

    def get_key(self, post_data):
        # Accessing these objects is starting to get ugly...
        key = self.server.server.database.add_key(post_data["keytext"][0])

        # Save the database
        self.server.server.database.save_db()

    def search(self, path):
        (scheme, netloc, path, params, query, frag) = urlparse(self.path)
        count = 0
        results = ""

        # Decode the URL escaping
        query = urllib.unquote(query)

        # Extract the query string from the URL query
        search = re.search(r'search=(.*)=?', query)
        if search:
            search = search.group(1)
        else:
            # No search string
            return

        all_keys = self.server.server.database.list_keys()

        # Client is searching for index results
        if "index" in query:
            # Search within the PGPKey's data for the query string
            for key in all_keys:
                search_area = key.meta.values() + key.user.values()
                for value in search_area:
                    if search in str(value):
                        results += key.search_result_format() + "\n"
                        count += 1

            info = "info:%s:%s\n" % (1, count)

            return info + results

        # Client expects a single key file
        elif "get" in query:
            # Strip the prefix off the fingerprint
            search = search[2:]

            for key in all_keys:
                if key.fingerprint == search or key.id == search:
                     return key.output_asc(self.server)

    def do_GET(self, post_data={}, method='GET'):
        (scheme, netloc, path, params, query, frag) = urlparse(self.path)

        query_data = parse_qs(query)

        # Static things!
        if path == '/favicon.ico':
            return self.send_file('favicon.ico')
        if path.startswith('/static/'):
            return self.send_file(path[len('/static/'):])

        html_variables = {
            'http_host': self.headers.get('host', 'localhost'),
            'http_hostname': self.http_host(),
            'http_method': method,
            'url_protocol': self.headers.get('x-forwarded-proto', 'http'),
        }

        mimetype, content = self.urlmapper_action(path, post_data)
        self.send_full_response(content, mimetype=mimetype)

    def build_html_index(self):
        keylist = ""

        keys = self.server.server.database.list_keys()
        info = "info:%s:%s\n" % (1, len(keys))
        for key in keys:
            keylist += "<p><pre>" + key.search_result_format() + "</pre></p>\n\n"

        page = """
        <html>
            <head>
            </head>
            <body>
            <h1>Keys</h1>
            <p><pre>%(info)s</pre></p>
            %(keylist)s
            </body>
        </html>
        """ % {"info": info, "keylist": keylist}
        return page


class HttpKeyServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    def __init__(self, server):
        BaseHTTPServer.HTTPServer.__init__(self, ( server.address, server.port ), HttpRequestHandler)
        self.server = server
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sspec = (server.address or 'localhost', self.socket.getsockname()[1])
        print "HTTP server running on %s:%s" % (server.address, server.port)

    def finish_request(self, request, client_address):
        try:
            BaseHTTPServer.HTTPServer.finish_request(self, request, client_address)
        except socket.error:
            pass
        if self.server.quitting: self.shutdown()


class HttpWorker(threading.Thread):
    def __init__(self, server):
        threading.Thread.__init__(self)
        self.httpd = HttpKeyServer(server)
        self.server = server
        # self.httpd.socket = ssl.wrap_socket(self.httpd.socket, certfile=server.pem, server_side=True)

    def run(self):
        self.server_running = True
        self.httpd.serve_forever()

    def quit(self):
        print "Shutting down HTTP server."
        if self.httpd: self.httpd.shutdown()
        self.httpd = None
        self.server_running = False

    def server_status(self):
        if self.server_running:
            print "Server is running on %s:%d." % (self.server.address, self.server.port)
        else:
            print "Server is not running."

class PGPKey:
    def __init__(self):
        self.user = {}
        self.meta = {}
        self.fingerprint = ""
        self.id = ""
        self.binary = 0

    def search_result_format(self):
        try:
            pub = "pub:%s:%s:%s:%s:%s::\n" % (
                self.fingerprint, self.meta["algorithm"],
                self.meta["key_length"], self.meta["creation_time"],
                self.meta["expiration_time"])
            uid = "uid:%s %s:%s:%s:\n" % (
                self.user["name"], self.user["email"], self.meta["creation_time"],
                self.meta["expiration_time"])
        except KeyError:
            print "Missing metadata in key"

        return str(pub + uid)

    def insert_newlines(self, string, every=64):
        """Insert newlines into raw string"""
        lines = []
        for i in xrange(0, len(string), every):
            lines.append(string[i:i+every])
        return '\n'.join(lines)

    def format_crc(self, binary):
        lines = []
        crc = "="
        for i in xrange(0, len(binary), 6):
                lines.append(binary[i:i+6])

        for i in lines:
                i = "0b" + i
                i = int(i, 2)

                if i < 26:
                        i = i + 65
                elif i >= 26 and i <= 51:
                        i = i + 71
                elif i >= 52 and i <= 61:
                        i = i - 4
                elif i == 62:
                        i = 43
                else:
                        i = 47
                crc = crc + chr(i)
        return crc

    def crc(self, every=6):
        # Format the CRC int for base64 encoding (isn't strong typing fun?)
        crc = crc24(bytearray(base64.b64decode(self.base64())))
        crc = bin(crc)[2:]

        # Front-pad zeros
        while len(crc) < 24:
                crc = '0' + crc

        return self.format_crc(crc)

    def base64(self):
        # Take the binary key data and convert it into a printable format
        key_data = base64.b64encode(self.binary)
        key_data = self.insert_newlines(key_data)
        return key_data

    def output_asc(self, server):
        # Return the key formatted as required
        return  "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +\
            "Version: " + application_version + "\n" +\
            "Comment: " + server.server.server_comment + "\n" +\
            "Hostname: " + server.server.hostname + "\n" +\
            "\n" +\
            self.base64() + "\n" +\
            self.crc() + "\n" +\
            "-----END PGP PUBLIC KEY BLOCK-----"

class PGPKeyDatabase:
    def __init__(self, path):
        self.path = path
        self.IDX_KEYS = []

    def initialize(self, path=None):
        path = path or self.path
        if path[-1] != '/': path = path + '/'
        files = os.listdir(path)
        count = 0
        for fn in files:
            count += 1
            print "\rInitializing %d of %d PGP keys..." % (count, len(files)),
            self.add_key_from_file(fn)

    def load_db(self, path=None):
        path = path or self.path
        if path[-1] != '/': path = path + '/'
        try:
            idx = pickle.loads(open(path + "index.keydb").read())
            self.IDX_KEYS = idx["IDX_KEYS"]

            print "Loaded database with %d keys." % len(self.IDX_KEYS)

        except IOError, e:
            print "Could not load database: %s" % e

    def save_db(self, path=None):
        path = path or self.path
        if path[-1] != '/': path = path + '/'
        if not os.path.exists(path):
            try:
                os.mkdir(path)
            except IOError, e: 
                print "Could not create directory: %s" % e
                return False
        fh = open(path+"index.keydb", "w")
        data = {
            "IDX_KEYS": self.list_keys(),
        }
        fh.write(pickle.dumps(data))
        fh.close()

    def get_gpg_key(self, keyid):
        data = open(self.path + "/" + keyid + ".gpg").read()
        return data

    def list_keys(self):
        # FIXME: This should die in a fire. No mechanism should give the entire
        # list like this - there should probably be a cleaner "download all"
        # function though

        return self.IDX_KEYS

    def add_key_from_file(self, keyfile):  # This needs a better name
        # Index the key...
        try:
            with open(self.path + keyfile) as f:
                key_data = f.read()
        except IOError as e:
            print "I/O error({0}): {1}".format(e.errno, e.strerror)

        key = self.add_key(key_data)

        # Make sure keyfile is in ASCII armored format and in the correct data 
        # directory.
        # if datadir is "data/", then "data/keyid.gpg"...
        pass

    def add_key(self, key_data):
        """Takes .asc key data in ASCII format"""
        # The below variables are faked data that need to be calculated later
        mr_output_version = 1  # Machine readable output version number
        key_length = 2048

        # Convert the ASCII Armored PGP data into usable format
        pgp_data = pgpdump.AsciiData(key_data)
        try:
            packets = list(pgp_data.packets())
        except ValueError:
            return None

        key = PGPKey()
        key.meta = {"mr_output_version": mr_output_version, 
                "key_length": 0, 
                "algorithm": "",
                "creation_time": "",
                "expiration_time": "",
               }

        for packet in packets:
            if isinstance(packet, pgpdump.packet.PublicKeyPacket):
                key.meta["algorithm"] = packet.raw_pub_algorithm
                key.meta["creation_time"] = packet.raw_creation_time
                key.meta["key_length"] = packet.length
                key.fingerprint = packet.fingerprint
                key.id = key.fingerprint[-8:]

            elif isinstance(packet, pgpdump.packet.SignaturePacket):
                key.meta["expiration_time"] = packet.raw_expiration_time

            elif isinstance(packet, pgpdump.packet.UserIDPacket):
                key.user["name"]  = packet.user_name
                key.user["email"] = packet.user_email

        # Store the key's binary data
        key.binary = pgp_data.data

        # Only add the key if it's new
        for search in self.list_keys():
            if search.fingerprint == key.fingerprint:
                return key

        self.IDX_KEYS.append(key)
        return key

    def get_index(self, keyid):
        pass

    def search(self, terms):
        pass



class KeyServer:
    def __init__(self, args):
        self.hostname = 'keys.thoughtworks.com'
        self.address = '0.0.0.0'
        self.port = 11371
        self.server_comment = ''
        self.quitting = False
        self.dbdir = os.path.realpath("data/")
        self.pem = "server.pem"
        self.http_worker = None

        self.parse_args(args)
        self.load_database()
        self.start_server()
        try:
            self.interact()
        except KeyboardInterrupt:
            pass
        finally:
            self.quitting = True
            self.stop_server()

    def interact(self):
        import readline
        try:
            while True:
                opt = raw_input('\rkeyserver> ').decode('utf-8').strip()
                if opt:
                    if ' ' in opt:
                        opt, arg = opt.split(' ', 1)
                    else:
                        arg = ''

                    # TODO: Make a Command class and manage command list.
                    if opt == "quit":
                        break
                    elif opt == "http":
                        if arg == "stop":
                            self.stop_server()
                        elif arg == "start":
                            self.start_server()
                        elif arg == "status":
                            self.http_worker.server_status()
                    elif opt == "keys":
                        if arg == "count":
                            cnt = len(self.database.list_keys())
                            print "%d keys in database" % cnt
                        else:
                            print self.database.list_keys()
                    elif opt == "hello":
                        print "Hello!"
                    else:
                        print "Unknown command"

        except EOFError:
            pass


    def load_database(self):
        self.database = PGPKeyDatabase(self.dbdir)
        self.database.load_db()

    def start_server(self):
        if self.http_worker and self.http_worker.httpd:
            print "Can't start server. It's already started."
            return False
        self.http_worker = HttpWorker(self)
        self.http_worker.start()
        return True

    def stop_server(self):
        if not self.http_worker or not self.http_worker.httpd:
            print "Can't stop server. It's not running!"
            return False
        self.http_worker.quit()
        return True

    def parse_args(self, args):
        pass


if __name__ == "__main__":
    s = KeyServer(sys.argv)

# vim: set smartindent tabstop=4 shiftwidth=4 expandtab:
