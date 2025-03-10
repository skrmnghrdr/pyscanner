#!/usr/bin/python3

import socket
import argparse
import threading #nitrous oxide :)
import http.client
#we might need a http.client so we can wget -r
#make a whole network range scanner as well.#ez to implement
#from asian_heritiage, import rice and fish
#import Dainty_Wilder.withclothes(True)
#import coffee
#import nicotine. (not really)
#add
"""
quick and dirty script frankenstiened from stackoverflow,
github, googleai, chatgpt, my braincells
modded to use argparse, acts like a netcat client so we do not have to 9050 
tf out of the machines.

python3 runs native on these machines, they forgot to "permission deny" us
on it. 
then again, use this script at your own risk, I tested this and finished archer
with it.

SOCKS5 does not allow any protocols aside from TCP and UDP, means you cannot
proxychains and ping hosts, hency why I made this.

lines on code not cut to 75 characters for easy vim pasting.
"""
SCANNED_HOSTS = {}

def tcp_client(host: str, port: int, verb):
    if verb == "t":
        print("[*] Scanning {} on port {}".format(host,port))


    
    
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
        print(f"[/] Connected to {host}:{port}")


        if port == 80:
                #if http, we need to grab the head lmao
            print("[!] Trying PORT 80, sending HTTP GET")
            http_reqest = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(host).encode('utf-8')
            client.sendall(http_reqest)
                
        else:
            message = "wake tf up"
            client.sendall(message.encode('utf-8'))
            #print(f"Sent: {message}")
            

            # Receive data
        response = client.recv(1024)
            #print(f"[%] Received:\n{response.decode("utf-8", errors="ignore")}")
        print("[%] HTTP HOST: {} Received:\n{}".format(host, response.decode('utf-8', errors='ignore')))
            
        SCANNED_HOSTS[host].append(port)

    except Exception as e:
        if verb == "t":
            print("[X] Error: HOST:{} PORT:{} Err:{}".format(host, port, e))
    finally:
            # Close the connection
        client.close()
            #print("Connection closed")

def udp_client(host: str, port: int):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        message = "WAKE THE FUCK UP SERVER"

        #we need to poke it on udp since we do not have the handshake
        client.sendto(message.encode('utf-8'), (host, port))
        print(f"Sent: {message}")
        
        # Receive response
        response, server_address = client.recvfrom(1024)
        print(f"Received: {response.decode('utf-8')} from {server_address}")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the socket
        client.close()
        #print("Connection closed")


def main():

    parser = argparse.ArgumentParser(description="zxxxx")
    parser.add_argument("--host", type=str, help="the host in STR: eg: 192.168.0, default would be 127.0.0.1")
    parser.add_argument("--hstart", type=str, help="start where? xxx.xxx.xxx.0", default=0)
    parser.add_argument("--hend", type=str, help="end where? xxx.xxx.xxx.0", default=254)
    parser.add_argument("--proto", type=str, help="protcol to use, tcp or udp. default is tcp", default="tcp")
    parser.add_argument("--verbose", type=str, default="f")

    ports = [21,22,23,80,134]
    #we might just ditch the port on this since we only have 3 std ports to scan, once we get in, we just do recon on the machine to locate the port of our ssh.
    args = parser.parse_args()

    threads = []

    #if args.proto == "tcp":
        #bro wants tcp then
    hstart = int(args.hstart)
    hend = (int(args.hend)+1)


    for ip in range(hstart, hend):
        curr_host = "{}.{}".format(args.host, str(ip))

        SCANNED_HOSTS.update({curr_host:[]})

        for port in ports:
            if args.proto == "tcp":
                #cvhat gpt came clutchy on this 
                thread = threading.Thread(target=tcp_client, args=(curr_host, port, args.verbose))
            if args.proto == "udp":
                thread = threading.Thread(target=udp_client, args=(curr_host, port))

            threads.append(thread)
            thread.start()


    for thread in threads:
        #we wait for threads to finsih.
        #DO NOT DELETE PLS
        thread.join()


    
    for key, value in SCANNED_HOSTS.items():
        if value:
            print("[*] Host:{}, ports:{}".format(key, sorted(SCANNED_HOSTS[key])))    

    print("\n[!] Finished Host: {}".format(args.host))


    #print("[!] OPEN_PORTS {}".format(sorted(OPEN_PORTS)))
    #parser.add_argument("--port", type=str, help="the target port in INT: eg 21 22 23 80")
    #python3 tcpbannergrabber.py --host 10.50.24 --hstart 90 --hend 120

main()
