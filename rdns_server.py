#!/usr/bin/env python

"""
    DNS proxy/resolver (relies on upstream forwarder): 
    [Work in Progress ..]
    Author: Shumon Huque <shuque@gmail.com>
"""

import getopt, os, os.path, sys
import struct, socket, select, errno, threading
from binascii import hexlify
import dns.message, dns.rdatatype, dns.rcode, dns.flags, dns.query, dns.edns


DEBUG      = True
TIMEOUT    = 3
RETRIES    = 3
FORWARDER  = '127.0.0.1'


class Prefs:
    """Preferences"""
    DEBUG      = False                    # -d: Print debugging output?
    SERVER     = ""                       # -s: server listening address
    PORT       = 53                       # -p: port
    FORWARDER  = '127.0.0.1'              # -f: forwarder DNS server


def dprint(input):
    if Prefs.DEBUG:
        with tlock:
            print("DEBUG: %s" % input)


def usage():
    """Usage string"""
    print("""\
Usage: %s [<options>]

Options:
       -h:        Print usage string
       -d:        Turn on debugging
       -p N:      Listen on port N
       -s A:      Bind to server address A
       -f F:      Use F (IP address) as forwarder
""" % os.path.basename(sys.argv[0]))
    sys.exit(1)


def tcp4socket(host, port):
    """Create IPv4 TCP server socket"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    return sock


def tcp6socket(host, port):
    """Create IPv6 TCP server socket"""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    return sock


def udp4socket(host, port):
    """Create IPv4 UDP server socket"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    return sock


def udp6socket(host, port):
    """Create IPv6 UDP server socket"""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((host, port))
    return sock


def sendSocket(s, message):
    """Send message on a connected socket"""
    try:
        octetsSent = 0
        while (octetsSent < len(message)):
            sentn = s.send(message[octetsSent:])
            if sentn == 0:
                raise(ValueError, "send() returned 0 bytes")
            octetsSent += sentn
    except Exception as diag:
        print("DEBUG: Exception: %s" % diag)
        return False
    else:
        return True


def recvSocket(s, numOctets):
    """Read and return numOctets of data from a connected socket"""
    response = ""
    octetsRead = 0
    while (octetsRead < numOctets):
        chunk = s.recv(numOctets-octetsRead)
        chunklen = len(chunk)
        if chunklen == 0:
            return ""
        octetsRead += chunklen
        response += chunk
    return response


def truncated(msg):
    """Does DNS message have truncated (TC) flag set?"""
    return (msg.flags & dns.flags.TC == dns.flags.TC)


class Resolver:
    """Resolver/forwarder class"""

    def __init__(self, forwarder, timeout=TIMEOUT, retries=RETRIES):
        self.forwarder = forwarder
        self.timeout = timeout
        self.retries = retries
        pass

    def do_query(self, query):
        """Query forwarder using parameters from given DNS 'query' message"""
        qname = query.question[0].name
        qtype = query.question[0].rdtype
        qclass = query.question[0].rdclass
        edns = query.edns
        ednsflags = query.ednsflags
        payload = query.payload
        message = dns.message.make_query(qname, qtype, qclass, use_edns=edns, 
                                         ednsflags=ednsflags, payload=payload)
        message.flags |= dns.flags.RD
        response = None
        count = 0
        while (not response) and (count < self.retries):
            try:
                dprint('> Resolver: Sending UDP query')
                response = dns.query.udp(message, self.forwarder, 
                                         timeout=self.timeout,
                                         ignore_unexpected=True)
            except dns.exception.Timeout:
                count += 1
                pass
        if response and truncated(response):
            dprint("> Resolver: Truncated, retrying with TCP ...")
            try:
                response = dns.query.tcp(message, self.forwarder, 
                                         timeout=self.timeout)
            except dns.exception.Timeout:
                pass
        return response


class DNSquery:
    """DNS query and response object"""
    query = None
    response = None
    wire_response = None
    rcode = dns.rcode.NOERROR
    dontreply = False

    def __init__(self, data, tcp=False):
        self.tcp = tcp
        if self.tcp:
            msg_len, = struct.unpack('!H', data[:2])
            self.msg = data[2:2+msg_len]
        else:
            self.msg = data

    def parse_query(self):
        if len(self.msg) < 12:
            self.rcode = -1
            return
        try:
            self.query = dns.message.from_wire(self.msg)
        except dns.exception.FormError:
            self.rcode = dns.rcode.FORMERR
            pass
        except dns.message.BadEDNS:
            self.rcode = dns.rcode.BADVERS
        else:
            if self.query.flags & dns.flags.RD != dns.flags.RD:
                # Don't respond to RD=0 queries
                self.rcode = -1
            else:
                self.txid = self.query.id
                if self.query.edns != -1:
                    for option in self.query.options:
                        dprint("EDNS option %d: %s" % 
                               (option.otype, hexlify(option.data)))

    def prepend_length(self, msg):
        return struct.pack('!H', len(msg)) + msg

    def msg2wire(self, msg):
        wire = msg.to_wire()
        if self.tcp:
            return self.prepend_length(wire)
        else:
            return wire

    def make_response(self):
        if self.rcode == -1:
            pass
        elif self.rcode == dns.rcode.FORMERR:
            self.response = 'Format Error'
            self.make_formerr()
        else:
            r = Resolver(Prefs.FORWARDER)
            self.response = r.do_query(self.query)
            if self.response:
                self.response.id = self.txid                   # rewrite txid
                self.wire_response = self.msg2wire(self.response)
                if not self.tcp:
                    self.checkudpsize()
            else:
                self.response = 'Server Failure'
                self.make_servfail()

    def checkudpsize(self):
        """Check UDP response size, reduce or truncate if needed"""
        if self.query.edns == -1:
            maxsize = 512
        else:
            maxsize = self.query.payload
        if len(self.wire_response) > maxsize:
            if not self.omit_extra() or len(self.wire_response) > maxsize:
                self.truncate()
                pass

    def truncate(self):
        """Truncate UDP response (this preserves OPT RR if present)"""
        self.response.flags |= dns.flags.TC
        self.response.answer = []
        self.response.authority = []
        self.response.additional = []
        self.wire_response = self.msg2wire(self.response)

    def omit_extra(self):
        """Omit authority/additional sections of response if present"""
        if not (self.response.authority or self.response.additional):
            return False
        else:
            self.response.authority = []
            self.response.additional = []
            self.wire_response = self.msg2wire(self.response)
            return True

    def make_formerr(self):
        """make wire format FORMERR message"""
        wire = self.msg[0:2] + struct.pack('!H', 0x8081) + b'\x00\x00' * 4
        if self.tcp:
            self.wire_response = self.prepend_length(wire)
        else:
            self.wire_response = wire

    def make_servfail(self):
        """make wire format SERVFAIL message"""
        wire = struct.pack('!H', self.txid) + \
               struct.pack('!H', 0x8082) + b'\x00\x00' * 4
        if self.tcp:
            self.wire_response = self.prepend_length(wire)
        else:
            self.wire_response = wire


def handle_connection_tcp(sock, addr, rbufsize=2048):
    cliaddr, cliport = addr[0:2]
    data = sock.recv(rbufsize)
    dprint("TCP connection from (%s, %d) msgsize=%d" %
           (cliaddr, cliport, len(data)))
    d = DNSquery(data, tcp=True)
    d.parse_query()
    dprint("GOT QUERY: \n%s" % d.query)
    d.make_response()
    if d.response:
        dprint("SEND RESPONSE: \n%s" % d.response)
    if d.wire_response:
        dprint(hexlify(d.wire_response))
        sendSocket(sock, d.wire_response)
    sock.close()


def handle_connection_udp(sock, rbufsize=2048):
    data, addr = sock.recvfrom(rbufsize)
    cliaddr, cliport = addr[0:2]
    dprint("UDP connection from (%s, %d) msgsize=%d" % 
           (cliaddr, cliport, len(data)))
    d = DNSquery(data)
    d.parse_query()
    dprint("GOT QUERY: \n%s" % d.query)
    d.make_response()
    if d.response:
        dprint("SEND RESPONSE: \n%s" % d.response)
    if d.wire_response:
        dprint(hexlify(d.wire_response))
        sock.sendto(d.wire_response, addr)


def process_args(arguments):
    """Process all command line arguments"""

    global Prefs

    try:
        (options, args) = getopt.getopt(arguments, 'hds:p:f:')
    except getopt.GetoptError:
        usage()

    for (opt, optval) in options:
        if opt == "-h":
            usage()
        elif opt == "-d":
            Prefs.DEBUG = True
        elif opt == "-s":
            Prefs.SERVER = optval
        elif opt == "-p":
            Prefs.PORT = int(optval)
        elif opt == "-f":
            Prefs.FORWARDER = optval

    return


if __name__ == '__main__':

    process_args(sys.argv[1:])

    s_tcp4 = tcp4socket(Prefs.SERVER, Prefs.PORT)
    s_udp4 = udp4socket(Prefs.SERVER, Prefs.PORT)
    s_tcp6 = tcp6socket(Prefs.SERVER, Prefs.PORT)
    s_udp6 = udp6socket(Prefs.SERVER, Prefs.PORT)
    print("Listening on port %d" % Prefs.PORT)

    fd_read = [ s_tcp4.fileno(), s_udp4.fileno(), s_tcp6.fileno(), \
                s_udp6.fileno()]
    tlock = threading.Lock()

    while True:

        try:
            (ready_r, ready_w, ready_e) = select.select(fd_read, [], [], 5)
        except select.error as e:
            if e[0] == errno.EINTR:
                continue
            else:
                print("Fatal error from select(): %s" % e)
                sys.exit(1)

        if ready_r:
            for fd in ready_r:
                if fd == s_tcp4.fileno():
                    s_conn4, addr = s_tcp4.accept()
                    threading.Thread(target=handle_connection_tcp, 
                                     args=(s_conn4, addr)).start()
                elif fd == s_udp4.fileno():
                    threading.Thread(target=handle_connection_udp, 
                                     args=(s_udp4,)).start()
                if fd == s_tcp6.fileno():
                    s_conn6, addr = s_tcp6.accept()
                    threading.Thread(target=handle_connection_tcp, 
                                     args=(s_conn6, addr)).start()
                elif fd == s_udp6.fileno():
                    threading.Thread(target=handle_connection_udp, 
                                     args=(s_udp6,)).start()

        # Do something in the main thread here if needed
        #dprint("Heartbeat.")
