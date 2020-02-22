import sys
import socket
import re

#function which proccesses request and returns it in right format
def getRequest(addr,flag):
    ip = addr.split("&")
    if (len(ip) != 2):
        errorGET(ip[0])
    if (flag):
        dest = socket.gethostbyname(ip[0])     
    else:
        dest = socket.gethostbyaddr(ip[0])
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
        connection.sendall(("HTTP/1.1 400 Bad Request\r\n\r\n").encode())
        connection.close()
        return
    else:
        connection.sendall(("500 Internal Server Error\r\n\r\n").encode())
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
                        sendAnswer(typ[1],data)
                    elif (str(typ[0]) == "PTR"):
                        data = getRequest(addr,flag)
                        sendAnswer(typ[1],data)
                    else:
                        errorGET(typ[1])
                        continue
                elif (re.search(r"^POST\s\/dns-query\s",splitArr[0])):
                    data = ''
                    protocol = splitArr[0].split(" ")
                    if (len(protocol) <= 1):
                        errorGET(splitArr[0])
                        continue
                    splitArr = splitArr[7:]
                    for i in range (0,len(splitArr)):
                        typ = splitArr[i].split(":")
                        if (len(typ) != 2):
                            errorGET(typ[0])
                            continue
                        if (str(typ[1]) == "A"):
                            dest = socket.gethostbyname(typ[0]) 
                            data += splitArr[i] + "=" + dest + "\r\n"
                        elif (str(typ[1]) == "PTR"):
                            dest = socket.gethostbyaddr(typ[0]) 
                            data += splitArr[i] + "=" + dest[0] + "\r\n"
                        
                    sendAnswer(protocol[2],data)
                elif ((re.search(r"^POST\s", splitArr[0]) and re.search(r"^GET\s", splitArr[0])) == None):
                    data = ''
                    connection.sendall("HTTP/1.1 405 Method Not Allowed\r\n\r\n".encode())
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

    except Exception as exc:
        print(exc)
    sckt.close()
    sys.exit(0)
