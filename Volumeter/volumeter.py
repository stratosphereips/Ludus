#!/usr/bin/env python3
#  Copyright (C) 2017  Sebastian Garcia, Ondrej Lukas
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Author:
# Ondrej Lukas, ondrej.lukas95@gmail.com    

# Description
# A program that analyzes output of conntrack and counts pkts and bytes transfered in each port in each protocol
import subprocess
import re
import datetime
import select
import argparse
import sys
import socket
import os
import multiprocessing
from multiprocessing import Queue
import pickle
import time
from threading  import Thread



class Port(object):
    """Container for volumes counting. For unfinished conections, buffers (1 pkts/event) are used as an estimation. THIS ESTIMATE IS ONLY USED IF ASKED FOR THE VOLUME BEFORE THE CONNNECTION ENDS. Upon
    recieving [DESTORY] event for the connection, value in buffer is reseted (we don't need it anymore because we ahave the real value)"""
    def __init__(self,port_number):
        self.id = port_number
        self.bytes = 0
        self.packets = 0
        self.buffer = 0
    
    def add_values(self,new_packets, new_bytes, timestamp):
        """Process destroyed connection, clear buffers"""
        #update values
        self.packets += new_packets
        self.bytes += new_bytes
        #print("[{}] New connection destroyed in port {} \tPKTS: {}, BYTES: {}".format(timestamp, self.id, self.packets,self.bytes))
        #erase buffer
        #print("UPDATED", self)
        self.tcp_buffer = 0

    def get_values(self):
        return {"bytes": self.bytes, "packets":(self.packets + self.buffer)}

    def increase_buffer(self, timestamp):
        """Connection  is still active, estimate it with 1 pkt in buffer"""
        #print("[{}] Active connection in port {} - buffer incremented".format(timestamp, self.id))
        self.buffer +=1

    def __str__(self):
        return f"<ID: {self.id}, bytes: {self.bytes}, packets: {self.packets}, buffer: {self.buffer}>"

class Counter(multiprocessing.Process):
    """Counts pkts/bytes in each port"""
    def __init__(self, queue, router_ip, port,end_flag):
        multiprocessing.Process.__init__(self)
        self.queue = queue
        self.tcp = {}
        self.icmp = Port("icmp")
        self.udp = {}

        self.router_ip = router_ip.rstrip('\n')
        self.end_flag = end_flag
        self.socket =socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setblocking(0)
        self.socket.bind(("localhost", port))
        self.socket.listen(5)
        print("Router IP:",self.router_ip)

    def process_event(self,string):
        """Parses the events from conntrack and stores the volumes (pkts, bytes). Port class is used as a container"""
        parts = []
        #get the timestamp
        split = string.split("\t")
        timestamp = split[0].strip("[]")
        #parse the rest of the line
        for part in split[1].split(' '):
            if len(part) > 0:
                parts.append(part.strip())
        #get the basic information about the connection
        event = parts[0].strip("[]")
        protocol = parts[1].lower()

        #is it a protocol with ports?
        if protocol == "udp" or protocol == "tcp":
            #has the connection finished yet?
            if event.lower() == 'destroy':
                src_ip = parts[3].strip("src=").rstrip('\n')
                dst_ip = parts[4].strip("dst=").rstrip('\n')
                sport = int(parts[5].strip("sport="))
                dport = int(parts[6].strip("dport="))
                #store the vlaues in the dict
                if dst_ip == self.router_ip:
                    #[UNREPLIED] event
                    if parts[9].strip("[]").lower() == "unreplied":
                        pkts = int(parts[7].strip("packets="))
                        data_bytes = int(parts[8].strip("bytes="))
                    else:
                        pkts = int(parts[7].strip("packets=")) +  int(parts[13].strip("packets="))
                        data_bytes = int(parts[8].strip("bytes=")) + int(parts[14].strip("bytes="))
                    if protocol == "tcp":
                        try:
                            self.tcp[dport].add_values(pkts, data_bytes,timestamp)
                        except KeyError:
                            #first time we see it
                            self.tcp[dport] = Port(dport)
                            self.tcp[dport].add_values(pkts, data_bytes,timestamp)
                    else:
                        try:
                            self.udp[dport].add_values(pkts, data_bytes,timestamp)
                        except KeyError:
                            #first time we see it
                            self.udp[dport] = Port(dport)
                            self.udp[dport].add_values(pkts, data_bytes,timestamp)
            else: #Active connection - at least estimate the number of pkts
                if protocol == 'tcp':
                    #print(parts)
                    dst_ip = parts[6].strip("dst=").strip()
                    dport = int(parts[8].strip("dport="))
                    #store values
                    if dst_ip == self.router_ip:
                        try:
                            self.tcp[dport].increase_buffer(timestamp)
                        except KeyError:
                            #first time we see it
                            self.tcp[dport] = Port(dport)
                            self.tcp[dport].increase_buffer(timestamp)
                else:
                    dst_ip = parts[5].strip("dst=").strip()
                    dport = int(parts[7].strip("dport="))
                    #store values
                    if dst_ip == self.router_ip:
                        #print(parts)
                        try:
                            self.udp[dport].increase_buffer(timestamp)
                        except KeyError:
                            #first time we see it
                            self.udp[dport] = Port(dport)
                            self.udp[dport].increase_buffer(timestamp)
        #ICMP
        
        elif protocol == "icmp":
            dst_ip = parts[4].strip("dst=")
            if dst_ip == self.router_ip:           
                if event.lower() == 'destroy':
                    self.icmp.add_values(int(parts[8].strip("packets=")) +  int(parts[15].strip("packets=")), int(parts[8].strip("packets=")) +  int(parts[15].strip("packets=")),timestamp)
                else:
                    self.icmp.increase_buffer(timestamp)
        else:
            #we are not interested in anyhting else for now, just continue
            pass

    def build_dict(self):
        d = {}
        #d['icmp'] = self.icmp.get_values()
        tmp = {}
        for port in self.tcp.keys():
            tmp[port] = self.tcp[port].get_values()
        d['tcp'] = tmp
        tmp = {}
        for port in self.udp.keys():
            tmp[port] = self.udp[port].get_values()
        d['udp'] = tmp
        return d

    def reset_counters(self):
        self.udp = {}
        self.tcp = {}
        self.icmp = Port('icmp')

    def process_msg(self, msg):
        #print(msg)
        """Processes the message recieved from the control program and if it contains known commnad, generates the respons"""
        if msg.lower() == 'get_data':
            response = pickle.dumps(self.build_dict())
            #reset counters
            return response
        elif msg.lower() == 'get_data_and_reset':
            #get data first
            response = pickle.dumps(self.build_dict())
            #reset counters
            self.reset_counters()
            return response
        elif msg.lower() == 'reset':
            #reset counters
            self.icmp = Port('icmp')
            self.udp = {}
            self.tcp = {}
            #confirm
            return "reset_done"
        else: #we dont recognize the command
            return "unknown_command"

    def run(self):
        try:
            while not self.end_flag.is_set():
                #do we have a connection?
                try:
                    c, addr = self.socket.accept()
                    msg = c.recv(1024).decode()
                    if msg:
                        response = self.process_msg(msg)
                        #print("MSG: '{}'".format(msg))
                        if(response.lower() == "terminating"):
                            self.end_flag.set()
                            c.send(response.encode())
                            c.close()
                        else:
                            c.send(response)
                            c.close()
                except socket.error:
                    #no, just wait
                    pass
                #read from the queue
                if not self.queue.empty():
                    line = self.queue.get_nowait().decode("utf-8")
                    if len(line) > 0:
                        #print(line)
                        self.process_event(line)
                else:
                    pass
                    time.sleep(.1)
            self.socket.close()
        except KeyboardInterrupt:
            self.socket.close()
            sys.exit()
        finally:
            self.socket.close()

class Volumeter(multiprocessing.Process):


    def __init__(self,address, port):
        multiprocessing.Process.__init__(self)
        self.address = address
        self.port = port
   
    def run(self):
        #create flag to exit gracefully
        exit_flag = multiprocessing.Event()
        #create queue for comunication between processes
        queue = Queue()
        #create new process
        counter = Counter(queue, self.address, self.port,exit_flag)
        #start it
        print("Staring counter:{}".format(datetime.datetime.now()))
        counter.start()
        try:
            process=subprocess.Popen(['conntrack','-E','-o','timestamp'],stdout=subprocess.PIPE)
            for line in iter(process.stdout.readline, b''):
                 queue.put(line)
            process.stdout.close()
        except KeyboardInterrupt:
            print("\nInterrupting volumeter")
            process.terminate()
            counter.join()

if __name__ == '__main__':
    #get parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--address', help='public address of the router', action='store', required=False, type=str, default='147.32.83.175')
    parser.add_argument('-p', '--port', help='Port used for communication with Ludus.py', action='store', required=False, type=int, default=53333)
    args = parser.parse_args()
    #create the process
    v = Volumeter(args.address, args.port)
    #start it
    v.run()
