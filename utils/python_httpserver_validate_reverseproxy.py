from http.server import BaseHTTPRequestHandler, HTTPServer

import requests
import multiprocessing
import random
import time
import psutil
import os
import signal


def validate(server=None,remote_port=None,vhost=None,local_port=2222):
    headers = {}
    ip = server

    if vhost != None:
        remote_port = 80
        headers = {"Host":vhost}

    randomint = random.randint(1111111111111,9999999999999)
    URL = 'http://{ip}:{port}/{validate}/'.format(ip=ip,port=remote_port, validate=randomint)

    class ValidationHandler(BaseHTTPRequestHandler):
        def __init__(self, request, client_address, server):
            BaseHTTPRequestHandler.__init__(self, request, client_address, server)
            self.valido = False

        def _set_response(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

        def is_valido(self):
            return self.valido

        def do_GET(self):
            #print("pidieron", self.path)

            self._set_response()

            if str(self.path.replace("/", "")) == str(randomint):
                self.wfile.write("OK".encode('utf-8'))
            else:
                self.wfile.write("NOK".encode('utf-8'))



    httpd = HTTPServer(("0.0.0.0", local_port), ValidationHandler)
    #print(dir())
    # httpd = SocketServer.TCPServer(("", PORT), ValidationHandler)
    #print("Serving at port", PORT)
    # start the server as a separate process
    server_process = multiprocessing.Process(target=httpd.serve_forever)
    server_process.daemon = True
    server_process.start()
    print("pid",server_process.pid)
    # Getting HTML from the target page
    try:
        print("server URL",URL)
        r = requests.get(URL,timeout=5, headers=headers)
        print(r.request.url)
        print(r.request.body)
        print(r.request.headers)
    except:
        r = None
    #print(repr(r.text))
    # stop the server

    server_process.terminate()
    server_process.kill()
    #httpd.shutdown()

    #time.sleep(2)
    if "text" in dir(r):
        if r.text== u'OK': return True
    return False

if __name__ == "__main__":
    print(validate(serverport="127.0.0.1:5555",local_port=5555))