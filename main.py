#!/usr/bin/python3

import socket
import argparse
import threading #nitrous oxide :)

#from asian_heritiage, import rice and fish
#import Dainty_Wilder.withclothes(True)
#import coffee
#import nicotine. (not really)

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
OPEN_PORTS = []

def tcp_client(host: str, port: int):
    print("[*] Scanning {} on port {}".format(host, port))
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
        print(f"[/] Connected to {host}:{port}")

        #delete incase the server does not respond 
        #here is a generic http get to
        #message = "Hello, Server!"
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
        print("[%] Received:\n{}".format(response.decode('utf-8', errors='ignore')))

        OPEN_PORTS.append(port)

    except Exception as e:
        print("[X] Error: PORT:{} {}".format(port, e))
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
    parser.add_argument("--host", type=str, help="the host in STR: eg: 192.168.1.1, default would be 127.0.0.1", default="127.0.0.1")
    parser.add_argument("--proto", type=str, help="protcol to use, tcp or udp. default is tcp", default="tcp")

    ports = [21,22,23,80,100,123,134,3333]
    #we might just ditch the port on this since we only have 3 std ports to scan, once we get in, we just do recon on the machine to locate the port of our ssh.
    args = parser.parse_args()

    threads = []

    #if args.proto == "tcp":
        #bro wants tcp then
    for port in ports:
        if args.proto == "tcp":
            #cvhat gpt came clutchy on this 
            thread = threading.Thread(target=tcp_client, args=(args.host, port))
        if args.proto == "udp":
            thread = threading.Thread(target=udp_client, args=(args.host, port))

        threads.append(thread)
        thread.start()

    for thread in threads:
        #we wait for threads to finsih.
        thread.join()


    
    print("\n[!] Finished Host: {}".format(args.host))
    print("[!] OPEN_PORTS {}".format(sorted(OPEN_PORTS)))
    #parser.add_argument("--port", type=str, help="the target port in INT: eg 21 22 23 80")

    #change here
    #runs at localhost,
    """
    print("Banner grabs the TCP port by the nutsack")
    porty = int(input("Enter port:"))
    tcp_client("127.0.0.1", porty)
    """

main()
