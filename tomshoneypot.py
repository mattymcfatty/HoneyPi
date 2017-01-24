#!/usr/bin/python

import binascii
import sys
import time
import struct
import socket
import random
import thread
import unicodedata

from twisted.internet.protocol import Protocol, Factory, DatagramProtocol
from twisted.internet import reactor

# uncomment these if you want to use the tweeting functionality
#import tweepy
#import GeoIP

# you MUST change these...
interface = ''
myid = 'TEST_CANARY'

SQLPing = binascii.unhexlify('02')
SQLSlammer = binascii.unhexlify('\
04010101010101010101010101010101010101010101010101010101010101010101010101010101\
01010101010101010101010101010101010101010101010101010101010101010101010101010101\
0101010101010101010101010101010101dcc9b042eb0e0101010101010170ae420170ae42909090\
909090909068dcc9b042b80101010131c9b11850e2fd35010101055089e551682e646c6c68656c33\
32686b65726e51686f756e746869636b43684765745466b96c6c516833322e64687773325f66b965\
745168736f636b66b9746f516873656e64be1810ae428d45d450ff16508d45e0508d45f050ff1650\
be1010ae428b1e8b033d558bec517405be1c10ae42ff16ffd031c951515081f10301049b81f10101\
0101518d45cc508b45c050ff166a116a026a02ffd0508d45c4508b45c050ff1689c609db81f33c61\
d9ff8b45b48d0c408d1488c1e20401c2c1e20829c28d049001d88945b46a108d45b05031c9516681\
f17801518d4503508b45ac50ffd6ebca')
RAdmindInit = binascii.unhexlify('01000000010000000808')
RAdmindIHasPW = binascii.unhexlify('01000000010000001B1B')
enctype = ['ENCRYPT_OFF', 'ENCRYPT_ON', 'ENCRYPT_NOT_SUP', 'ENCRYPT_REQ']
marstype = ['ON', 'OFF']
logindata = ['ClientName', 'Username', 'Password', 'AppName', 'Server Name', 'Unused', 'Library Name', 'Locale', 'Database Name']
tds_response_a = '0401002500000100000015000601001b000102001c000103001d0000ff'
vnc_protocol_version = binascii.unhexlify("524642203030332e3030380a")
lastSQLSlammer = ''
lastMSSQL = ''
lastTS = ''
lastSIPPER = ''
lastRAdmind = ''
lastVNC = ''

def logprint(x):
	now = time.time()
	t = time.strftime("%Y-%m-%d %H:%M:%S") + ("%1.4f" % (now - int(now)))[1:] + ": "
	print(t + x)

def twitter_it(x, ip):
	#remove the "return" line and get OAUTH values from Twitter (http://dev.twitter.com) if you want to have this tweet
	return
	global myid
	wait = random.randint(60,600) + random.randint(60,600)
	time.sleep(wait)
	# necessary auth values
	CONSUMER_KEY = '<YOU NEED TO REPLACE THIS>'
	CONSUMER_SECRET = '<YOU NEED TO REPLACE THIS>'
	ACCESS_KEY = '<YOU NEED TO REPLACE THIS>'
	ACCESS_SECRET = '<YOU NEED TO REPLACE THIS>'
	# end auth values
	gir = gi.record_by_addr(ip)
	if gir != None:
		if gir['region_name'] != None:
			region = unicodedata.normalize('NFKD', unicode(gir['region_name'], 'iso-8859-1')).encode('ascii','ignore')
		else:
			region = 'N/A'
		if gir['city'] != None:
			city = unicodedata.normalize('NFKD', unicode(gir['city'], 'iso-8859-1')).encode('ascii','ignore')
		else:
			city = 'N/A'
	else:
		city = 'N/A'
		region = 'N/A'
	auth = tweepy.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)                                                                 
	auth.set_access_token(ACCESS_KEY, ACCESS_SECRET)                                                                          
	api = tweepy.API(auth)
	if(gir != None):
		msg = x % (ip, gir['country_code'], region, city)
	else:
		msg = x % (ip, 'N/A', region, city)
	if myid != '':
		msg = msg + " " + myid
	api.update_status(msg)                                                                                                                                                                                                       
	logprint("Tweeted: " + msg)

class flushfile(object):
	def __init__(self, f):
		self.f = f
	def write(self, x):
		self.f.write(x)
		self.f.flush()

class tFakeMSSQL(Protocol):
	def dataReceived(self, data):
		global lastMSSQL
		tds_type, size = struct.unpack('!BxH', data[:4])
		if(size == len(data)):
			p1 = 8
			nexttoken = 0
			if(tds_type == 0x12):
				tds_response_created = 0
				p2 = p1 + 6;
				logprint("TDS 7/8 Prelogin packet on port %d from: %s (%d/TCP):" % (self.transport.getHost().port, self.transport.getPeer().host, self.transport.getPeer().port))
				while nexttoken != 0xff:
					tokentype, p, l, nexttoken = struct.unpack('!BHHB', data[p1:p2])
					if tokentype == 0:
						maj, minor = struct.unpack('!LH', data[p + 8:p + l + 8])
						tds_response = tds_response_a + binascii.hexlify(data[p + 8:p + l + 8]) + '0200'
						tds_response_created = 1
						print "\tVersion:\n\t\tMaj: %s\n\t\tMin: %s" % (hex(socket.ntohl(maj)), hex(socket.ntohl(minor)))
					if tokentype == 1:
						enc, = struct.unpack('!B', data[p + 8:p + l + 8])
						print "\tEncryption: ", enctype[enc]
					if (tokentype == 2) & (l > 1):
						print "\tInstance: ", data[p + 8:p + l + 8]
					if tokentype == 3:
						threadid, = struct.unpack('!L', data[p + 8:p + l + 8])
						print "\tThread ID: ", threadid
					if tokentype == 4:
						mars, = struct.unpack('!B', data[p + 8:p + l + 8])
						print "\tMARS: ", marstype[mars]
					p1 = p2 - 1
					p2 = p1 + 6
				if tds_response_created == 0:
					tds_response = tds_response_a + '080002fe00000200' 
				self.transport.write(binascii.unhexlify(tds_response))
			elif(tds_type == 0x10):
				p2 = p1 + 36
				logprint("TDS 7/8 Login packet on port %d from: %s (%d/TCP):" % (self.transport.getHost().port, self.transport.getPeer().host, self.transport.getPeer().port))
				if len(data) > p2:
					l, v, ps, cv, pid, cid, o1, o2, o3, r, tz, lc = struct.unpack('=LLLLLLBBBBLL', data[p1:p2])
					print '\tLen: ', l
					print '\tVersion: ', hex(socket.ntohl(v))
					print '\tPacket Size: ', ps
					print '\tClient Version: ', socket.ntohl(cv)
					print '\tClient PID: ', pid
					print '\tConnection ID: ', cid
					print '\tOption Flag 1: ', o1
					print '\tOption Flag 2: ', o2
					print '\tOption Flag 3: ', o3
					print '\tType Flag: ', r
					print '\tClient TZ: ', tz
					print '\tClient Language Code: ', lc
					p1 = p2
					p2 = p1 + 4
					for n in logindata:
						o, l = struct.unpack('=HH', data[p1:p2])
						if l > 0:
							if n == 'Password':
								pw = ''
								p = data[o + 8:o + (2 * l) + 8]
								for byte in p:
									b = ord(byte) ^ 0xa5
									reverse_b = (b & 0xf) << 4 | (b & 0xf0) >> 4
									pw = pw + chr(reverse_b)
								print '\t%s: %s' % (n, pw.encode("utf-8"))
							else:
								s = data[o + 8:o + (2 * l) + 8]
								print '\t%s: %s' % (n, s.encode("utf-8"))
						p1 = p2
						p2 = p1 + 4
					print '\tClient ID: ', binascii.hexlify(data[p1:p1+6])
					self.transport.loseConnection()
					if(lastMSSQL != self.transport.getPeer().host):
						lastMSSQL = self.transport.getPeer().host
						thread.start_new_thread(twitter_it, ("A host at %s (%s, %s - %s) tried to log into my honeypot's fake MSSQL Server... #netmenaces", lastMSSQL))							
			else:
				logprint("TCPData on port %d from: %s (%d/TCP):\n%s" % (self.transport.getHost().port, self.transport.getPeer().host, self.transport.getPeer().port, binascii.hexlify(data)))
				self.transport.loseConnection()

class Dumper(Protocol):
	def dataReceived(self, data):
		logprint("TCPData on port %d from: %s (%d/TCP):\n%s" % (self.transport.getHost().port, self.transport.getPeer().host, self.transport.getPeer().port, binascii.hexlify(data)))
		self.transport.loseConnection()

class tFakeTS(Protocol):
	def dataReceived(self, data):
		global lastTS
		global gi
		tpkt_data = data[:4]
		x224_data = data[4:]
		v, junk, total_len = struct.unpack('!BBH', tpkt_data)		
		logprint("TPKT (v.%d and length %d) on port %d from: %s (%d/TCP):" % (v, total_len, self.transport.getHost().port, self.transport.getPeer().host, self.transport.getPeer().port))
		if(len(data) == total_len):
			l, c = struct.unpack('BB',x224_data[:2])
			if c == 0xe0:
				x224 = struct.unpack('!HHBH', x224_data[2:9])
				print "\tX224 Connection Request. Responding..."
				self.transport.write(struct.pack('!BBHBBHHB', v, 0, 11, 6, 0xd0, x224[1], 0x1234, x224[2]))
				print "\tLogin: %s" % x224_data[6:]
				if(lastTS != self.transport.getPeer().host):
					lastTS = self.transport.getPeer().host
					thread.start_new_thread(twitter_it, ("A host at %s (%s, %s - %s) tried to log into my honeypot's fake Terminal Services server... #netmenaces", lastTS))							
			else:
				print "\tX224 Unrecognized code:"
				print binascii.hexlify(data)
				self.transport.loseConnection()
				if(lastTS != self.transport.getPeer().host):
					lastTS = self.transport.getPeer().host
					thread.start_new_thread(twitter_it, ("A host at %s (%s, %s - %s) connected to my honeypot's fake Terminal Services server... #netmenaces", lastTS))							
		else:
			print "Data inconsistent... dropping connection."
			print binascii.hexlify(data)
			self.transport.loseConnection()
			if(lastTS != self.transport.getPeer().host):
				lastTS = self.transport.getPeer().host
				thread.start_new_thread(twitter_it, ("A host at %s (%s, %s - %s) connected to my honeypot's fake Terminal Services server... #netmenaces", lastTS))							

class tFakeRAdmind(Protocol):
	def dataReceived(self, data):	
		global gi
		global lastRAdmind
		global RAdmindInit
		global RAdmindIHasPW
		if(data == RAdmindInit):
			logprint("RAdmind initiate connection on port %d from: %s (%d/TCP):" % (self.transport.getHost().port, self.transport.getPeer().host, self.transport.getPeer().port))
			self.transport.write(binascii.unhexlify('01000000250800011008010008080000000000000000000000000000000000000000000000000000000000000000'))
			if(lastRAdmind != self.transport.getPeer().host):
				lastRAdmind = self.transport.getPeer().host
				thread.start_new_thread(twitter_it, ("A host at %s (%s, %s - %s) wants to use my honeypot's fake RAdmind... #netmenaces", lastRAdmind))
			self.transport.loseConnection()
		else:
			if(data == RAdmindIHasPW):
				logprint("RAdmind password ready on port %d from: %s (%d/TCP):" % (self.transport.getHost().port, self.transport.getPeer().host, self.transport.getPeer().port))
				self.transport.write(binascii.unhexlify('01000000217BA977521B3BF0F3E2DCC7917B5A41C4FC0A92FF2251B16D3689417060F4170AB02A134A76'))
			else:
				logprint("RAdmind data on port %d from: %s (%d/TCP):\n%s" % (self.transport.getHost().port, self.transport.getPeer().host, self.transport.getPeer().port, binascii.hexlify(data)))
				self.transport.write(binascii.unhexlify('01000000010000000B0B0D0A0D0A'))	
				self.transport.loseConnection()

class tFakeVNC(Protocol):
	def connectionMade(self):
		global vnc_protocol_version
		logprint("Inbound VNC connection from: %s (%d/TCP) - responding..." % (self.transport.getPeer().host, self.transport.getPeer().port))
		# send "RFB 003.008"
		self.transport.write(vnc_protocol_version)
		self.state = 1
	def dataReceived(self, data):
		global lastVNC
		global gir
		if self.state == 1:
			if data == vnc_protocol_version:
				self.transport.write(binascii.unhexlify('0102'))
				logprint("Sending security types: %s (%d/TCP)..." % (self.transport.getPeer().host, self.transport.getPeer().port))
				self.state = 2
			else:
				logprint("Unrecognized TCP data on port %d from: %s (%d/TCP):\n%s" % (self.transport.getHost().port, self.transport.getPeer().host, self.transport.getPeer().port, binascii.hexlify(data)))
		elif self.state == 2:
			if data == binascii.unhexlify('01'):
				self.transport.write(binascii.unhexlify('00000000'))
				self.state = 3
				logprint("Sending authentication results: %s (%d/TCP)..." % (self.transport.getPeer().host, self.transport.getPeer().port))
				if(lastVNC != self.transport.getPeer().host):
					lastVNC = self.transport.getPeer().host
					thread.start_new_thread(twitter_it, ("A host at %s (%s, %s - %s) attempted to bypass authentication for RealVNC... #netmenaces", lastVNC))
			else:
				logprint("Unrecognized TCP data on port %d from: %s (%d/TCP):\n%s" % (self.transport.getHost().port, self.transport.getPeer().host, self.transport.getPeer().port, binascii.hexlify(data)))
		elif self.state == 3:
			self.transport.write(binascii.unhexlify('043a02ff2018000100ff00ff00ff1008000000000000000d4745525449452d445747445747'))
			self.state = 4
			logprint("Sending framebuffer parameters: %s (%d/TCP)..." % (self.transport.getPeer().host, self.transport.getPeer().port))
		else: 
			logprint("State (%d) - TCPData on port %d from: %s (%d/TCP):\n%s" % (self.state, self.transport.getHost().port, self.transport.getPeer().host, self.transport.getPeer().port, binascii.hexlify(data)))
			self.transport.loseConnection()
	def connectionLost(self, reason):
		self.state = 0

class uFakeMSSQL(DatagramProtocol):
	global SQLPing
	global SQLSlammer
	def datagramReceived(self, data, (host, port)):
		global lastSQLSlammer
		global gi
		if data == SQLPing:
			logprint('SQL Ping received from %s (%d/UDP). Responding...' % (host, port))
			self.transport.write('ServerName;REDEMPTION;InstanceName;MSSQLSERVER;IsClustered;No;Version;8.00.194;tcp;1433;np;\\REDEMPTION\pipe\sql\query;;',(host,port))
		elif ((len(data) == len(SQLSlammer)) & (data == SQLSlammer)):
			logprint('The host at %s (%d/UDP) has requested that we join his SQLSlammer Party...' % (host, port))
			if(lastSQLSlammer != host):
				lastSQLSlammer = host
				thread.start_new_thread(twitter_it, ('A host at %s (%s, %s - %s) requested that my honeypot join their SQLSlammer party... #netmenaces', lastSQLSlammer))
		else:
			logprint("UDPData from: %s (%d/UDP):\n%s" % (host, port, binascii.hexlify(data)))

class uFakeSIP(DatagramProtocol):
	def datagramReceived(self, data, (host, port)):
		global lastSIPPER
		global gi
		logprint('The host at %s (%d/UDP) is trying to initiate a SIP connection...' % (host, port))
		if(lastSIPPER != host):
			lastSIPPER = host
			thread.start_new_thread(twitter_it, ('A host at %s (%s, %s - %s) wants to talk SIP to my honeypot... #netmenaces', lastSIPPER))
		logprint("SIP Data from: %s (%d/UDP):\n%s" % (host, port, data))

random.seed()
sys.stdout = flushfile(sys.stdout)
fDump = Factory()
fDump.protocol = Dumper
fMSSQL = Factory()
fMSSQL.protocol = tFakeMSSQL
fTS = Factory()
fTS.protocol = tFakeTS
fVNC = Factory()
fVNC.protocol = tFakeVNC
fRAdmind = Factory()
fRAdmind.protocol = tFakeRAdmind

logprint("Starting up...")
# Uncomment the following and install GeoLiteCity data from MaxMind (http://www.maxmind.com) if you want to use the tweeting functionality.
#gi = GeoIP.open("/usr/share/GeoIP/GeoLiteCity.dat",GeoIP.GEOIP_STANDARD)
reactor.listenTCP(1433, fMSSQL, interface = interface)
reactor.listenTCP(3389, fTS, interface = interface)
reactor.listenTCP(5900, fVNC, interface = interface)
reactor.listenTCP(22292, fDump, interface = interface)
reactor.listenTCP(4899, fRAdmind, interface = interface)
reactor.listenUDP(1434, uFakeMSSQL(), interface = interface)
reactor.listenUDP(5060, uFakeSIP(), interface = interface)
reactor.run()
logprint("Shutting down...")
