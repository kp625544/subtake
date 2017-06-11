#----------------------------------------------------------------
#C0ded by Kaushal aka Hydra
#----------------------------------------------------------------


import sublist3r
import sys
import argparse
import dns.resolver
import socket
import requests
from urllib2 import urlopen


is_windows = sys.platform.startswith('win')


if is_windows:
    # Windows deserve coloring too :D
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white
    try:
        import win_unicode_console , colorama
        win_unicode_console.enable()
        colorama.init()
        #Now the unicode will work ^_^
    except:
        print("[!] Error: Coloring libraries not installed ,no coloring will be used [Check the readme]")
        G = Y = B = R = W = G = Y = B = R = W = ''


else:
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white
    S = '\x1b[6;30;42m'
    E = '\x1b[0m'
def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -d google.com")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain name to enumerate it's subdomains", required=True)
    parser.add_argument('-b', '--bruteforce', help='Enable the subbrute bruteforce module', nargs='?', default=False)
    parser.add_argument('-p', '--ports', help='Scan the found subdomains against specified tcp ports')
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime', nargs='?', default=False)
    parser.add_argument('-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)
    parser.add_argument('-e', '--engines', help='Specify a comma-separated list of search engines')
    parser.add_argument('-o', '--output', help='Save the results to text file')
    return parser.parse_args()

def parser_error(errmsg):
    banner()
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit()


def subdomain_check(subdomains):
    # Basic query
    for subd in range(len(subdomains)):
        if subd != 0:
            try:
                #print("inside query")
                for rdata in dns.resolver.query(subdomains[subd], 'CNAME') :
                    print "Checking subdomain takeover on:  "+str(subdomains[subd])
                    try:
                        #response = urlopen("http://"+str(rdata.target))
                        response = urlopen("http://"+str(subdomains[subd]))
                        print(R+str(subdomains[subd])+"  seems Up and running fine")
                    except:
                        print(S+"Success!!! Possible sub-domain takeover on:     "+str(subdomains[subd])+E)
            except:
                print (R+"No CNAME for"+str(subdomains[subd])+"i.e. subdomain takeover not Possible")



try:
    if sys.argv[1] == '-d':
       args = parse_args()
       no_threads = args.threads
       domain = args.domain
       savefile = args.output
       ports = args.ports
       enable_bruteforce = args.bruteforce
       verbose = args.verbose
       engines = args.engines
       if verbose or verbose is None:
           verbose = True
       subdomains = sublist3r.main(domain, no_threads, savefile, ports, silent=False, verbose=verbose, enable_bruteforce=enable_bruteforce, engines=engines)
       print("checking for subdomain takeovers")
       subdomain_check(subdomains)
    else:
       print(R+"Error! usage: python subtake.py -d domain.name")
except:
    print(R+"error: usage python subtake.py -d domain.name")
