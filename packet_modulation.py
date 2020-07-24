import socket, sys
from _thread import *

try:
   listening_port = int(input("[*] Enter Listening Port Number : "))
except KeyboardInterrupt:
   print("\n[*] User Requested An Interrupt")
   print("[*] Application Exiting...")
   sys.exit()

max_conn = 5
buffer_size = 8192

def start():
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   s.bind(('', listening_port))
   s.listen(max_conn)
   print("[*] Initializing Sockets ... Done")
   print("[*] Sockets Binded Successfully ...")
   print("[*] Server Started Successfully [ %d ]\n" % (listening_port))

   while 1:
      try:
         conn, addr = s.accept()
         data = conn.recv(buffer_size)
         start_new_thread(conn_string, (conn, data, addr))
      except KeyboardInterrupt:
         s.close()
         print("\n[*] Proxy Server Shutting Down ...")
         print("[*] Have A Nice Day ... Sergeant !!!")
         sys.exit(1)
   s.close()


def conn_string(conn, data, addr):
   first_line = data.split(b'\n')[0]
   url = first_line.split(b' ')[1]
   http_pos = url.find(b"://")
   if (http_pos==-1):
      temp = url
   else:
      temp = url[(http_pos+3):]
   port_pos = temp.find(b":")
   webserver_pos = temp.find(b"/")
   if webserver_pos == -1:
      webserver_pos = len(temp)
   webserver = ""
   port = -1
   if (port_pos == -1 or webserver_pos < port_pos):
      port = 80
      webserver = temp[:webserver_pos]
   else:
      port = int((temp[(port_pos+1):])[:webserver_pos-port_pos-1])
      webserver = temp[:port_pos]
   print()
   print("===========Host Request===========")
   print(data)
   aorc = input("Accept or Change (a/c) : ")
   if aorc == "c":
      data = bytes(input("====change data====\n"))
   proxy_server(webserver, port, conn, addr, data)


def proxy_server(host, port, conn, addr, data):
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   s.connect((host, port))
   s.send(data)

   while True:
      reply = s.recv(buffer_size)
      print()
      print("===========Host Reply===========")
      print(reply)
      if(len(reply) > 0):
         conn.send(reply)
         dar = float(len(reply))
         dar = float(dar / 1024)
         dar = "%.3s" % (str(dar))
         dar = "%s KB" % (dar)
         #print("[*] Request Done : %s => %s <=" % (str(addr[0]), str(dar)))
      else:
         break

   s.close()
   conn.close()

start()
