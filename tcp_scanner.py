import optparse
from socket import *
import socket


def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send('Violent python\r\n')
        results = connSkt.recv(100)
         
        print '[+] %d/tcp open' % tgtPort
        print '\n[+] ' + str(results)

        connSkt.close()
    except:
        print '[-] %d/tcp closed' % tgtPort

def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print "[-] cannot resolve '%s': Unknown host" & tgtHost
        return 
    try:
        tgtName = gethostbyaddr(tgtIP)
        print '\n[+] Scan result for: ' + tgtName[0]
    except:
        print '\n[+] Scan result for: ' + tgtIP
    setdefaulttimeout(1)

    for tgtPort in tgtPorts:
        print 'Scanning port ' + tgtPort
        connScan(tgtHost, tgtPort)

def main():

    parser = optparse.OptionParser('usage %prog -H + <targethost> -p <targetport>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='int', help='specify target port')

    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPort = options.tgtPort
    if tgtHost == None or tgtPort == None:
        print parse.usage
        exit(0)
    portScan(tgtHost, tgtPorts)


if __name__ == '__main__':
    main()

