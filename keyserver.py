#! /usr/bin/env python

from twisted.internet import reactor
from twisted.web.server import Site
from twisted.web.resource import Resource
from twisted.python.log import err
from pgpdump.utils import crc24
import pgpdump, base64, sys, getopt, binascii

# Get key from commandline
input_file = sys.argv[1]

# Server settings
application_version = '0.1'
hostname = 'keys.thoughtworks.com'
server_comment = ''

# The below variables are faked data that need to be calculated later
mr_output_version = 1  # Machine readable output version number
num_keys_returned = 1  # Number of keys returned in a search
key_length = 2048

# Use the file specified on the command line as the output key
try:
	with open(input_file) as f:
		file_contents = f.read()
except IOError as e:
	print "I/O error(%s): %s" % (e.errno, e.strerror)

# Insert newlines into raw string
def insert_newlines(string, every=64):
	lines = []
	for i in xrange(0, len(string), every):
		lines.append(string[i:i+every])
	return '\n'.join(lines)

def format_crc(binary):
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

def generate_crc(pgp_data):
	# Format the CRC int for base64 encoding
	data = pgp_data.strip_magic(pgp_data.original_data)
	data, crc = pgp_data.split_data_crc(data)
	crc = bin(crc)[2:]

	# Front-pad zeros
	while len(crc) < 24:
		crc = '0' + crc

	crc = format_crc(crc)
	return crc

# Functions for machine-readable output
class MachineReadableKey(Resource):
	isLeaf = 1

	def __init__(self, url):
		Resource.__init__(self)
		self.url = url

	# Rendering method
	def render_GET(self, request):
		# Set the HTML header type
		request.setHeader("Content-Type", "text/plain;")

		# Convert the ASCII Armored PGP data into usable format
		pgp_data = pgpdump.AsciiData(file_contents)
		packets = list(pgp_data.packets())

		crc = generate_crc(pgp_data)

		# Check to see if the HTTP POST has was an op=get request. We should return a 
		#	 key to download
		if "get" in request.args["op"]:
			# Take the binary key data and convert it into a printable format
			key_data = pgp_data.data
			key_data = base64.b64encode(key_data)
			key_data = insert_newlines(key_data)

			# Set HTTP headers so the key will be downloaded as a file
			request.responseHeaders.setRawHeaders(
				'Content-Disposition', ['attachment; filename="gpgkey.asc"'])

			# Return the key formatted as required
			return	"-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +\
				"Version: " + application_version + "\n" +\
				"Comment: " + server_comment + "\n" +\
				"Hostname: " + hostname + "\n" +\
				"\n" +\
				key_data + "\n" +\
							crc + "\n" +\
				"-----END PGP PUBLIC KEY BLOCK-----"
		else:
			# Treat the request as an index pull. Return machine-readable output
			info = "info:%s:%s\n" % (mr_output_version, num_keys_returned)
			pub  = "pub:%s:%s:%s:%s:%s::\n" % (packets[0].fingerprint, packets[0].raw_pub_algorithm, key_length, packets[0].raw_creation_time, packets[2].raw_expiration_time)
			uid  = "uid:%s:%s:%s:\n" % (packets[1].user, packets[0].raw_creation_time, packets[2].raw_expiration_time)
			return str(info + pub + uid)

# Handle all of the URL redirections
class URLHandler(Resource):
	isLeaf = 0

	def getChild(self, name, request):
		return MachineReadableKey(name)

root = URLHandler()
factory = Site(root)
reactor.listenTCP(11371, factory)
reactor.run()

# vim: set smartindent tabstop=4 shiftwidth=4 noexpandtab:
