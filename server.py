import sys
import socket
import re

def getRequest(addr,flag):
    ip = addr.split("&")
    if (flag):
        dest = socket.gethostbyname(ip[0])     
    else:
        dest = socket.gethostbyaddr(ip[0])
    addr = re.sub("&type=",":",addr)
    addr = addr.split(" ")
    if (flag):
        response = addr[0] + "=" + dest + "\r\n"
    else:
        response = addr[0] + "=" + dest[0] + "\r\n"
    return response

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
        PORT = s[1]
        SERVER = '127.0.0.1'

    sckt = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        sckt.bind((SERVER, int(PORT)))
        sckt.listen(1)
        while 1:
            flag = False
            connection, address = sckt.accept()
            data = connection.recv(1024).decode()
            splitArr = data.split('\n');
            if (len(splitArr) > 0):
                if (re.search("GET \/resolve", splitArr[0])):
                    addr = re.sub("GET \/resolve\?name=","",splitArr[0])
                    typ = addr.split("=")
                    typ = str(typ[1]).split(" ")
                    if (str(typ[0]) == "A"):
                        flag = True        
                        data = getRequest(addr,flag)
                        connection.sendall(("HTTP/1.1 200 OK\r\n\r\n").encode())
                        connection.sendall(data.encode())
                    elif (str(typ[0]) == "PTR"):
                        data = getRequest(addr,flag)
                        connection.sendall(("HTTP/1.1 200 OK\r\n\r\n").encode())
                        connection.sendall(data.encode())
                    else:
                        data = "HTTP/1.1 400 Bad Request\r\n\r\n"
                        connection.sendall(data.encode())
                elif (re.search("POST \/dns-query",splitArr[0])):
                    data = ''
                    protocol = splitArr[0].split(" ")
                    splitArr = splitArr[7:]
                    for i in range (0,len(splitArr)):
                        typ = splitArr[i].split(":") 
                        if (str(typ[1]) == "A"):
                            dest = socket.gethostbyname(typ[0]) 
                            data += splitArr[i] + "=" + dest + "\r\n"
                        elif (str(typ[1]) == "PTR"):
                            dest = socket.gethostbyaddr(typ[0]) 
                            data += splitArr[i] + "=" + dest[0] + "\r\n"
                        
                    connection.sendall((protocol[2].rstrip() + ' 200 OK\r\n\r\n').encode())
                    connection.sendall(data.encode())
                elif (not (re.search("GET /resolve",splitArr[0]) and re.search("POST /dns-query",splitArr[0]))):
                    data = ''
                    connection.sendall("HTTP/1.1 400 Bad Request\r\n\r\n".encode())
                    connection.sendall(data.encode())
                elif (not (re.search("POST", splitArr[0]) and re.search("GET", splitArr[0]))):
                    data = ''
                    connection.sendall("HTTP/1.1 405 Method Not Allowed\r\n\r\n".encode())
                    connection.sendall(data.encode())


                #elif ()
            #connection.shutdown(connection.SHUT_WR)        
    except KeyboardInterrupt:
        print("\nServer shutting down\n")

    except Exception as exc:
        print("\n404 Not Found\n")
        print(exc)
    sckt.close()