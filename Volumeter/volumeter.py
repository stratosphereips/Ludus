#!/usr/bin/env python
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
import json
import argparse
import sys
import socket
import os
import multiprocessing
from multiprocessing import Queue

def default(o):
    return o._asdict()

class MyEncoder(json.JSONEncoder):
    """Simple JSON encoder for storing Port objects"""
    def default(self, obj):
        if not isinstance(obj, Port):
            return super(MyEncoder, self).default(obj)
        return obj.__dict__

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
        print "[{}] New connection destroyed in port {} \tPKTS: {}, BYTES: {}".format(timestamp, self.id, self.packets,self.bytes)
        #erase buffer
        self.tcp_buffer = 0


    def values_for_json(self):
        return {'bytes': self.bytes, 'packets':(self.packets + self.buffer)}

    def increase_buffer(self, timestamp):
        """Connection  is still active, estimate it with 1 pkt in buffer"""
        print "[{}] Active connection in port {} - buffer incremented".format(timestamp, self.id)
        self.buffer +=1

    def __str__(self):
        return "<ID: {}, bytes: {}, packets: {}, buffer: {}>".format(self.id, self.bytes, self.packets, self.buffer)

class Counter(multiprocessing.Process):
    """Counts pkts/bytes in each port"""
    def __init__(self, queue, router_ip, port,end_flag):
        multiprocessing.Process.__init__(self)
        self.queue = queue
        self.tcp = {}
        self.icmp = Port('icmp')
        self.udp = {}

        self.router_ip = router_ip
        self.end_flag = end_flag
        self.socket =socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setblocking(0)
        self.socket.bind(('localhost', port))
        self.socket.listen(5)

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
        protocol = parts[1]

        #is it a protocol with ports?
        if protocol == "udp" or protocol == "tcp":
            #has the connection finished yet?
            if event.lower() == 'destroy':
                src_ip = parts[3].strip("src=")
                dst_ip = parts[4].strip("dst=")
                sport = parts[5].strip("sport=")
                dport = parts[6].strip("dport=")
                #[UNREPLIED] event
                if parts[9].strip("[]").lower() == "unreplied":
                    pkts = int(parts[7].strip("packtets="))
                    data_bytes = int(parts[8].strip("bytes="))
                else:
                    pkts = int(parts[7].strip("packtets=")) +  int(parts[13].strip("packtets="))
                    data_bytes = int(parts[8].strip("bytes=")) + int(parts[14].strip("bytes="))
                #store the vlaues in the dict
                if dst_ip == self.router_ip:
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
                    dst_ip = parts[6].strip("dst=")
                    dport = parts[8].strip("dport=")
                    #store values
                    if dst_ip == self.router_ip:
                        try:
                            self.tcp[dport].increase_buffer(timestamp)
                        except KeyError:
                            #first time we see it
                            self.tcp[dport] = Port(dport)
                            self.tcp[dport].increase_buffer(timestamp)
                else:
                    dst_ip = parts[5].strip("dst=")
                    dport = parts[8].strip("dport=")
                    #store values
                    if dst_ip == self.router_ip:
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
                    self.icmp.add_values(int(parts[8].strip("packtets=")) +  int(parts[15].strip("packtets=")), int(parts[8].strip("packtets=")) +  int(parts[15].strip("packtets=")),timestamp)
                else:
                    self.icmp.increase_buffer(timestamp)
        else:
            #we are not interested in anyhting else for now, just continue
            pass
    def create_JSON(self):
        d = {}
        d['icmp'] = self.icmp.values_for_json()
        tmp = {}
        for port in self.tcp.keys():
            tmp[port] = self.tcp[port].values_for_json()
        d['tcp'] = tmp
        tmp = {}
        for port in self.udp.keys():
            tmp[port] = self.udp[port].values_for_json()
        d['udp'] = tmp
        return d
    def reset_counters(self):
        self.udp = {}
        self.tcp = {}
        self.icmp = Port('icmp')

    def process_msg(self, msg):
        """Processes the message recieved from the control program and if it contains known commnad, generates the respons"""
        if msg.lower() == 'get_data':
            values = {'icmp':self.icmp, 'tmp':self.tcp, 'udp':self.udp}
            data = json.dumps(values, default=lambda x: x.__dict__)
            return data
        elif msg.lower() == 'get_data_and_reset':
            #get data first
            response = json.dumps(self.create_JSON())
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
        elif msg.lower() == "terminate":
            return "terminating"
        else: #we dont recognize the command
            return "unknown_command"

    def run(self):
        try:
            while not self.end_flag.is_set():
                #do we have a connection?
                try:
                    c, addr = self.socket.accept()
                    msg = c.recv(1024)
                    if msg:
                        response = self.process_msg(msg)
                        print "MSG: '{}'".format(msg)
                        c.send(response)
                        c.close()
                        if(response.lower() == "terminating"):
                            self.end_flag.set()
                except socket.error:
                    #no, just wait
                    pass
                #read from the queue
                if not self.queue.empty():
                    line = self.queue.get()
                    if len(line) > 0:
                        self.process_event(line)
            self.socket.close()
        except KeyboardInterrupt:
            self.socket.close()
            sys.exit()
        finally:
            self.socket.close()

class Volumeter(object):


    def __init__(self,address, port):
        self.address = address
        self.port = port
   
    def main(self):
        #create flag to exit gracefully
        exit_flag = multiprocessing.Event()
        #create queue for comunication between processes
        queue = Queue()
        #create new process
        counter = Counter(queue, self.address, self.port,exit_flag)
        #start it
        print("Staring counter:{}", datetime.datetime.now())
        counter.start()

        #yet another process
        process = subprocess.Popen('conntrack -E -o timestamp', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        #***MAIN LOOP***
        while not exit_flag.is_set():
            try:
                for line in process.stdout.readline().split('\n'):
                    queue.put(line)
            except KeyboardInterrupt:
                print "\nInterrupting volumeter"
                exit_flag.set()
                process.terminate()
                counter.join()
        print("Leaving Volumeter")

if __name__ == '__main__':
    #get parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--address', help='public address of the router', action='store', required=False, type=str, default='147.32.83.179')
    parser.add_argument('-p', '--port', help='Port used for communication with Ludus.py', action='store', required=False, type=int, default=53333)
    args = parser.parse_args()
    main(args.address,args.port)