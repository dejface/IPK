import sys
import socket
import re

#function which proccesses request and returns it in right format
def getRequest(addr,flag):
    ip = addr.split("&")
    if (len(ip) != 2):
        errorGET(ip[0])
    if (flag):
        try:
            if (ip[0] == ""):
                errorGET(ip[1])
                return "abort"
            dest = socket.gethostbyname(ip[0]) 
            if (dest == ip[0]):
                errorGET(ip[1])
                return "abort"
        except:
            connection.sendall(("HTTP/1.1 404 Not Found\r\n").encode())
            connection.close()
            return "abort"
    else:
        try:
            if (not re.search(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$',ip[0])):
                errorGET(ip[1])
                return "abort"
            dest = socket.gethostbyaddr(ip[0])
        except:
            connection.sendall(("HTTP/1.1 404 Not Found\r\n").encode())
            connection.close()
            return "abort"
    sub = re.sub("&type=",":",addr)
    if (sub == addr):
        errorGET(addr)
    addr = sub.split(" ")
    if (len(addr) != 2):
        errorGET(addr[0])
    if (flag):
        response = addr[0] + "=" + dest + "\r\n"
    else:
        response = addr[0] + "=" + dest[0] + "\r\n"
    return response

def errorGET(ptrn):
    if (re.search("HTTP/1.1",ptrn)):
        connection.sendall(("HTTP/1.1 400 Bad Request\r\n").encode())
        connection.close()
        return
    else:
        connection.sendall(("500 Internal Server Error\r\n").encode())
        connection.close()
        return

def sendAnswer(ptrn,data):
    connection.sendall((ptrn.rstrip() + " 200 OK\r\n\r\n").encode())
    connection.sendall(data.encode())
    connection.close()
    return

if __name__ == "__main__":
    if (len(sys.argv) != 2):
        print("Wrong number of arguments!\n")
        sys.exit(1)
    
    s = sys.argv[1].split('=')
    if ((s[0] != "PORT") or (s[1].isdigit() == False) or (len(s) != 2) or (int(s[1]) < 1024) or (int(s[1]) > 65535)):
        print("Wrong format of PORT\nPort have to be in range from 1024 to 65535\n"
              "Correct usage: PORT=number_in_range\n")
        sys.exit(1)
    else:
        PORT = s[1]             #set PORT of server from argument
        SERVER = '127.0.0.1'    #set server IP on localhost

    sckt = socket.socket(socket.AF_INET,socket.SOCK_STREAM)     #socket initialization
    try:
        sckt.bind((SERVER, int(PORT)))
        sckt.listen(1)
        #whole communication between client and server is in infinite loop
        while 1:
            flag = False
            connection, address = sckt.accept()
            data = connection.recv(1024).decode()
            splitArr = data.split('\n');
            if (len(splitArr) > 0):
                if (re.search(r"^GET\s\/resolve\?", splitArr[0])):
                    addr = re.sub("GET \/resolve\?name=","",splitArr[0])
                    if (addr == splitArr[0]):
                        errorGET(splitArr[0])
                        continue
                    typ = addr.split("=")
                    if (len(typ) != 2):
                        errorGET(typ[0])
                        continue
                    typ = str(typ[1]).split(" ")
                    if (len(typ) != 2):
                        errorGET(typ[0])
                        continue
                    if (str(typ[0]) == "A"):
                        flag = True        
                        data = getRequest(addr,flag)
                        if (data == "abort"): 
                            continue
                        sendAnswer(typ[1],data)
                    elif (str(typ[0]) == "PTR"):
                        data = getRequest(addr,flag)
                        if (data == "abort"): 
                            continue
                        sendAnswer(typ[1],data)
                    else:
                        errorGET(typ[1])
                        continue
                elif (re.search(r"^POST\s\/dns-query\s",splitArr[0])):
                    data = ''
                    wrongRequest = 0
                    protocol = splitArr[0].split(" ")
                    if (len(protocol) <= 1):
                        errorGET(splitArr[0])
                        continue
                    splitArr = splitArr[7:]
                    for i in range (0,len(splitArr)):
                        if (re.search(r'[:\s]A$|[\s*](A\s*)$',splitArr[i])):
                            typ = splitArr[i].split(":")
                            if (len(typ) != 2):
                                wrongRequest += 1
                                continue
                            typ[0] = typ[0].strip()
                            typ[1] = typ[1].strip()
                        elif (re.search(r'[:\s]PTR$|[\s*](PTR\s*)$',splitArr[i])):
                            typ = splitArr[i].split(":")
                            if (len(typ) != 2):
                                wrongRequest += 1
                                continue
                            typ[0] = typ[0].strip()
                            typ[1] = typ[1].strip()
                        else:
                            typ = splitArr[i].split(":")
                            if (len(typ) != 2):
                                wrongRequest += 1
                                continue
                        if (str(typ[1]) == "A"):
                            try:
                                if (typ[0] == ""):
                                    wrongRequest += 1
                                    continue
                                dest = socket.gethostbyname(typ[0])
                                if (dest == typ[0]):
                                    wrongRequest += 1
                                    continue
                            except:
                                wrongRequest += 1
                                continue
                            data += typ[0] + ":" + typ[1] + "=" + dest + "\r\n"
                        elif (str(typ[1]) == "PTR"):
                            try:
                                if (not re.search(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$',typ[0])):
                                    wrongRequest += 1
                                    continue
                                dest = socket.gethostbyaddr(typ[0]) 
                            except:
                                wrongRequest += 1
                                continue
                            data += typ[0] + ":" + typ[1] + "=" + dest[0] + "\r\n"
                        else:
                            wrongRequest += 1
                            flag = True
                            continue
                    if (wrongRequest == len(splitArr)):
                        if not flag:
                            connection.sendall(("HTTP/1.1 404 Not Found\r\n").encode())
                            connection.close()
                            continue 
                        else:
                            connection.sendall(("HTTP/1.1 400 Bad Request\r\n").encode())
                            connection.close()
                            continue
                    else:
                        sendAnswer(protocol[2],data)
                elif ((re.search(r"^POST\s", splitArr[0]) == None) and (re.search(r"^GET\s", splitArr[0]) == None)):
                    data = ''
                    connection.sendall("HTTP/1.1 405 Method Not Allowed\r\n".encode())
                    connection.sendall(data.encode())
                    connection.close()
                    continue
                else: 
                    data = ''
                    errorGET(splitArr[0])
                    continue
            else:
                data = ''
                errorGET("")
                continue

    except KeyboardInterrupt:
        print("\nServer shutting down\n")
        sys.exit(0)

    sckt.close()
    sys.exit(0)
