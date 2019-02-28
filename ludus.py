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
# This file is part of the Stratosphere Linux IPS project. https://stratosphereips.org

# Author:
# Ondrej Lukas, ondrej.lukas95@gmail.com    

import time, threading, datetime
import sys
import subprocess
import argparse
import Strategizer.strategy_generator as generator
import IPTablesAnalyzer.iptables_analyzer
import Suricata_Extractor.suricata_extractor_for_ludus as s_extractor
from Volumeter.volumeter_client import Volumeter_client
import configparser
from configparser import NoOptionError
import Volumeter.volumeter as vol
from multiprocessing import Process
import zmq
import msgpack
import time
import multiprocessing
import sched

VERSION = "0.6"

known_honeypots=['22', '23', '8080', '2323', '80', '3128', '8123']


class Sendline():
    TOPIC=b"sentinel/collect/ludus"

    def __init__(self, target="ipc:///tmp/sentinel_pull.sock"):
        self.zmqcontext = zmq.Context.instance()
        self.zmqsocket = self.zmqcontext.socket(zmq.PUSH)
        self.zmqsocket.connect(target)
    def sendline(self,data):
        packed = msgpack.dumps(data)
        self.zmqsocket.send_multipart([self.TOPIC, packed])
    def close(self):
        self.zmqcontext.destroy()






def open_honeypot(port, known_honeypots, protocol='tcp'):
    if port in known_honeypots:
        #ssh HP
        if port == '22':
            command = '/etc/init.d/haas-proxy start'
        #minipot
        else:
            command = 'uci del_list ucollect.fakes.enable='+port+protocol
    #no, use TARPIT
    else:
        command = 'iptables -I zone_wan_input 6 -p tcp --dport %s -j TARPIT' % port
    subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()

def close_honeypot(port,known_honeypots, protocol='tcp'):
    #is the port among the known honeypots
    if port in known_honeypots:
        #is it ssh
        if port == '22':
            subprocess.Popen('iptables -t nat -D zone_wan_prerouting 1', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()
            command = '/etc/init.d/haas-proxy stop'
        #no, its one of the minipot
        else:
            command = 'uci del_list ucollect.fakes.disable='+port+protocol
    #no, it is TARPIT
    else:
        command = 'iptables -D zone_wan_input 6'
    subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()

def get_strategy(ports, active_honeypots, path_to_strategy):
    """Prepares the string in the format required in strategy generator and return the strategy"""
    #build the string
    if(len(path_to_strategy) > 0):
        ports_s = ''
        for item in ports:
            ports_s += (str(item)+',')
        #get rid of the last comma
        ports_s = ports_s[0:-1]
        
        #get strategy
        suggested_honeypots = generator.get_strategy(ports_s,path_to_strategy)
        return suggested_honeypots
    else: #no strategy file, do nothing
        return []

def get_ports_information():
    data = IPTablesAnalyzer.iptables_analyzer.get_output()
    production_ports = []
    honeypots = []
    for key in data:
        #get active ports
        if data[key] == 'accepted' or data[key] == 'production':
            production_ports.append(key)
        #get honeypots
        if data[key] == 'honeypot-turris':
            honeypots.append(key)
    return (production_ports, honeypots)

class Ludus(object):
    """Main program for LUDUS project"""
    def __init__(self, volumeter_port,flag, config_file='/etc/ludus/ludus.config'):
        self.volumeter_client = Volumeter_client(volumeter_port)
        self.config_parser = parser = configparser.ConfigParser()
        self.config_file = config_file
        self.flag = flag
        self.suricat_extractor = s_extractor.Extractor("/var/log/suricata/eve.json")
        self.tw_start = None
        self.read_configuration()
        self.next_call = 0
        self.s = Sendline() #na zacatku zavolas tohle

    def read_configuration(self):
        """Reads values in ludus.conf and updates the settings accordily"""
        self.config_parser.read(self.config_file)
        self.strategy_file = self.config_parser.get('strategy', 'filename')

        #self.json_file = self.config_parser.get('output', 'filename')
        try:
            self.tw_length = self.config_parser.getint('settings', 'timeout')
            print("TW LEN", self.tw_length)
        except NoOptionError:
            print("Option 'timeout' not found! Using DEFAULT value 60 insted.")
            self.tw_length = 60
        except ValueError:
            print("Unsupported value in field 'timeout' (expected int)! Using DEFAULT value 60 insted.")
            self.tw_length = 60
        try:
            self.use_suricata = self.config_parser.getboolean('suricata', 'allow')
        except ValueError:
            print("Unsupported value in field 'allow' (expected boolean)! Using DEFAULT value 'False' instead.")
            self.use_suricata = False
        try:
            self.router_ip = self.config_parser.get('settings', 'router_ip')
        except ValueError:
            print("Unknown value in field 'router_ip'!")
            self.router_ip="unknown"

    def apply_strategy(self, suggested_honeypots,known_honeypots=['22', '23', '8080', '2323', '80', '3128', '8123']):
        #close previously opened HP which we do not want anymore               
        try:
            for port in suggested_honeypots:
                if port not in self.active_honeypots:
                    close_honeypot(port, known_honeypots)
        except TypeError:
            #no action required
            pass
        #open new HP ports
        try:
            #open the Honeypots on suggested ports
            for port in suggested_honeypots:
                if port not in self.active_honeypots:
                    open_honeypot(port,known_honeypots)   
        except TypeError:
            #no action required
            pass

    def generate_output(self,suricata_data, volumeter_data):
        output = {}
        output["tw_start"] = datetime.datetime.fromtimestamp(self.tw_start).isoformat(' ')
        output["tw_end"] = datetime.datetime.fromtimestamp(self.tw_end).isoformat(' ')
        #STORE PORT INFORMATION
        portInfo = {}
        #TCP
        tcp_ports = {}
        ports = set()
        #get all ports we saw in the TW
        ports.update(int(x) for x in volumeter_data['tcp'].keys())
        ports.update(suricata_data["Alerts/DstPort"].keys())
        ports.update(self.active_honeypots)
        ports.update(self.production_ports)
        #determine type of each port and prepare structure
        for p in ports:
            if p in self.active_honeypots:
                tcp_ports[p] = {"type":"Honeypot", "bytes":0, "packets":0, "flows":-1, "#Alerts":0}
            elif p in self.production_ports:
                tcp_ports[p] = {"type":"Production","bytes":0, "packets":0, "flows":-1, "#Alerts":0}
            else:
                tcp_ports[p] = {"type":"Unknown","bytes":0, "packets":0, "flows":-1, "#Alerts":0}
        #update volumes
        for p in volumeter_data['tcp'].keys():
            tcp_ports[p]["bytes"] = volumeter_data["tcp"][p]["bytes"]
            tcp_ports[p]["packets"] = volumeter_data["tcp"][p]["packets"]
        #update alerts
        for p in suricata_data["Alerts/DstPort"].keys():
            tcp_ports[p]["#Alerts"] = suricata_data["Alerts/DstPort"][p]
        udp_ports = {}
        portInfo["UDP"] = udp_ports
        portInfo["TCP"] = tcp_ports
        output["PortInfo"] = portInfo

        ## STORE ALERTS FROM SURICATA
        #store information about alerts from suricata
        output["honeypots"] = self.active_honeypots
        output["production_ports"] = self.production_ports
        output["GameStrategyFileName"] = self.strategy_file
        output["alerts"] = suricata_data
        output["volumeter_data"] = volumeter_data
        output["suricata_data"] = suricata_data
        output["alerts"] = suricata_data
        return output

    def run(self):
        print(f"-------start: {datetime.datetime.fromtimestamp(self.tw_start)}-------")
        self.tw_end = time.time()
        next_start = self.tw_end
        #get data from Volumeter
        volumeter_data = self.volumeter_client.get_data_and_reset()
        self.next_call += self.tw_length #this helps to avoid drifting in time windows
        next_start = self.tw_end
        #get data from Suricata-Extractor
        suricata_data = self.suricat_extractor.get_data(self.tw_start,self.tw_end)    
        old_strategy = self.strategy_file
        #check if there is any change configuration
        self.read_configuration()

        #get the information about ports in use
        (production_ports, active_hp) = get_ports_information()  
        #do we need to change the defence_strategy?
        if set(production_ports) != set(self.production_ports) or self.strategy_file != old_strategy:
            #update the settings
            self.active_honeypots = active_hp
            self.production_ports = production_ports
            #get strategy
            suggested_honeypots = get_strategy(self.production_ports,active_hp,self.strategy_file)
            self.apply_strategy(suggested_honeypots)
        
        #store the information in the file
        output = self.generate_output(suricata_data, volumeter_data)

        #-------------------------
        #REMOVE BEFORE PUBLISHING
        print(output)
        #-------------------------

        self.s.sendline(output) #potom takhle odesilas data

        self.tw_start = self.tw_end
        print(f"------end: {datetime.datetime.fromtimestamp(self.tw_end)}--------")
        self.scheduler.enter((self.next_call +self.tw_length) - time.time(),1,self.run)

    
    def start(self):
        """Main loop"""
        
        #analyze the production ports
        (self.production_ports, self.active_honeypots)=get_ports_information()
        #get strategy
        suggested_honeypots = get_strategy(self.production_ports,self.active_honeypots,self.strategy_file)
        print("{} is suggested strategy for port combination {}".format(self.production_ports, suggested_honeypots))
        #apply strategy
        self.apply_strategy(suggested_honeypots)
        
        self.tw_start = time.time()
        


        self.scheduler = sched.scheduler()
        self.next_call = self.tw_start
        self.scheduler.enter(self.tw_length, 1, self.run)
        self.scheduler.run()
        """


        self.next_call = time.time()
        while not self.flag.wait(timeout=(self.next_call +self.tw_length) - time.time()):
            print(f"-------start: {self.tw_start}-------")
            self.next_call+= self.tw_length #this helps to avoid drifting in time windows
            self.tw_end = datetime.datetime.now()
        
            #get data from Volumeter
            volumeter_data = {}
            volumeter_data = self.volumeter_client.get_data_and_reset()
            #print("VOLUMETER DATA:", volumeter_data)
            #get data from Suricata-Extractor
            suricata_data = self.suricat_extractor.get_data(self.tw_start,self.tw_end)
            
            old_strategy = self.strategy_file
            #check if there is any change configuration
            self.read_configuration()

            #get the information about ports in use
            (production_ports, active_hp) = get_ports_information()
            
            #do we need to change the defence_strategy?
            if set(production_ports) != set(self.production_ports) or self.strategy_file != old_strategy:
                #update the settings
                self.active_honeypots = active_hp
                self.production_ports = production_ports
                #get strategy
                suggested_honeypots = get_strategy(self.production_ports,active_hp,self.strategy_file)
                self.apply_strategy(suggested_honeypots)
            
            #store the information in the file
            output = self.generate_output(suricata_data, volumeter_data)

            #-------------------------
            #REMOVE BEFORE PUBLISHING
            print(output)
            #-------------------------

            self.s.sendline(output) #potom takhle odesilas data

            self.tw_start = self.tw_end
            print(f"TW------end: {datetime.datetime.now()}--------")            
        """
        
        #terminate the connection to DB
        self.s.close() #na konci zavolas tohle.

if __name__ == '__main__':

    # Parse the parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='Path to config file', action='store', required=False, type=str, default='/etc/ludus/ludus.config')
    parser.add_argument('-p', '--volumeter_port', help='Port to listen on to get data from Volumeter', action='store', default=53333, required=False, type=int)
    args = parser.parse_args()
    
    #start the tool
    print(".-.   .-..-..--. .-..-..---.\n| |__ | || || \ \| || | \ \ \n`----'`----'`-'-'`----'`---'\n")
    print(f"\nVersion {VERSION}\n")



    #check if suricata is running
    process = subprocess.Popen('pidof suricata', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    end_flag = threading.Event()
    ludus = Ludus(args.volumeter_port,end_flag,args.config)
    if(len(err) > 0): #something wrong with the suricata running test
        print("Error while testing if suricata is running.")
    else:
        try:
            if(len(out) == 0): #no running suricata
                print("Suricata is required for running Ludus. Starting suricata with interface {} and default configuration.")
                suricata_process =  subprocess.Popen('suricata -i eth1', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            #start Volumeter
            volumeter_process = vol.Volumeter('147.32.83.175',53333) 
            volumeter_process.start()

            print("Volumeter started")
            #everything is set, start ludus
            print("Started on {}\n".format(datetime.datetime.now()))
            ludus.start()

        except KeyboardInterrupt:
            end_flag.set()
            ludus.s.close()
            volumeter_process.join()
            print("\nLeaving Ludus")