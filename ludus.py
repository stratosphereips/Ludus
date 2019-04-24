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
# This file is part of the Stratosphere Linux IPS project. https://stratosphereips.org

# Author:
# Ondrej Lukas - ondrej.lukas95@gmail.com , lukasond@fel.cvut.cz 


#TODO:
#   log
#   sample config file
#   changes in suricata.yaml
#   check if sentinel is running
import time,datetime
import sys
import subprocess
import argparse
import Strategizer.generator as generator
import IPTablesAnalyzer.iptables_analyzer
import zmq
import msgpack
import multiprocessing
import sched
import os
import signal
import Suricata_Extractor.suricata_extractor_for_ludus as s_extractor
import configparser
from multiprocessing import Process
VERSION = "0.7"


#known_honeypots = ['22', '23', '8080', '2323', '80', '3128', '8123']
known_honeypots = [22, 23, 8080, 2323, 80, 3128, 8123]

def colored(text,color):
    CRED = '\033[91m'
    CEND = '\033[0m'
    CGREEN = '\033[92m'
    CYELLOW = '\033[93m'
    CBLUE = '\033[94m'

    if color == "green":
        return CGREEN + text + CEND
    elif color == "red":
        return CRED + text + CEND
    elif color == "yellow":
        return CYELLOW + text + CEND
    elif color == "blue":
        return CBLUE + text + CEND
    else:
        return text

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
        if port == 22:
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
        if port == 22:
            #subprocess.Popen('iptables -t nat -D zone_wan_prerouting 1', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()
            command = '/etc/init.d/haas-proxy stop'
        #no, its one of the minipot
        else:
            #TODO BETTER HANDELING THE RULE NUMBERS
            command = 'uci del_list ucollect.fakes.disable='+port+protocol
    #no, it is TARPIT
    else:
        command = 'iptables -D zone_wan_input 6'
    subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()

def get_strategy(ports, active_honeypots, path_to_strategy):
    """Prepares the string in the format required in strategy generator and return the strategy"""
    #build the string
    if(len(path_to_strategy) > 0):
        #get strategy
        defender = generator.Defender(path_to_strategy)
        suggested_honeypots = defender.get_strategy(ports)
        return suggested_honeypots
    else: #no strategy file, do nothing
        return []

def get_ports_information():
    data = IPTablesAnalyzer.iptables_analyzer.get_output()
    production_ports = []
    honeypots = []
    for protocol,key in data:
        #get active ports
        if data[protocol, key] == 'accepted' or data[protocol,key] == 'production':
            production_ports.append((protocol,key))
        #get honeypots
        if data[protocol, key] == 'honeypot-turris':
            honeypots.append((protocol,key))
    return (production_ports, honeypots)

class Ludus(object):
    """Main program for LUDUS project"""
    def __init__(self, config_file='/etc/ludus/ludus.config'):
        self.config_parser = configparser.ConfigParser()
        self.config_file = config_file
        self.suricata_log = "/root/log/suricata/eve.json"
        self.suricata_tmp_log = "/root/log/suricata/suricata_log.json"
        self.suricat_extractor = s_extractor.Extractor(self.suricata_tmp_log)
        self.tw_start = None
        self.read_configuration()
        self.next_call = 0
        self.s = Sendline()
        self.suricata_pid = None

    def read_configuration(self):
        """Reads values in ludus.conf and updates the settings accordily"""
        self.config_parser.read(self.config_file)
        self.strategy_file = self.config_parser.get('strategy', 'filename')

        #self.json_file = self.config_parser.get('output', 'filename')
        try:
            self.tw_length = self.config_parser.getint('settings', 'timeout')
        except configparser.NoOptionError:
            self.tw_length = 60
            print(colored(f"Option 'timeout' not found! Using DEFAULT value {self.tw_length} insted.", "red"))
        except ValueError:
            self.tw_length = 60
            print(colored(f"Unsupported value in field 'timeout' (expected int)! Using DEFAULT value {self.tw_length} insted.", "red"))
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

    def generate_output(self,suricata_data):
        port_info = []
        used = set()
        for (protocol, dport),(pkts_toserver, pkts_toclient) in suricata_data["packets_per_port"].items():
            tmp = {"port": dport, "protocol":protocol, "pkts_to_server":pkts_toserver, "pkts_to_client": pkts_toclient}
            if (protocol,dport) in self.production_ports:
                tmp["status"] = "production"
            elif (protocol,dport) in self.active_honeypots:
                tmp["status"] = "honeypot"
            else:
                tmp["status"] = "closed"
            #add bytes volumes
            tmp["bytes_to_server"] = suricata_data["bytes_per_port"][protocol, dport][0]
            tmp["bytes_to_client"] = suricata_data["bytes_per_port"][protocol, dport][1]
            used.add((protocol, dport))
            port_info.append(tmp)
        for x in self.active_honeypots:
            if x not in used:
                port_info.append({"status":"honeypot", "pkts_toserver":0, "pkts_toclient":0, "bytes_to_server":0, "bytes_to_client":0})
        for x in self.production_ports:
            if x not in used:
                port_info.append({"status":"production", "pkts_toserver":0, "pkts_toclient":0, "bytes_to_server":0, "bytes_to_client":0})

        flows = []
        for flow_id, data in suricata_data["flows"].items():
            if flow_id in suricata_data["alerts"].keys():
                tmp = {"severity": suricata_data["alerts"][flow_id]["severity"], "category":suricata_data["alerts"][flow_id]["category"], "signature":suricata_data["alerts"][flow_id]["signature"]}
                data["alert"] = tmp
            else:
                data["alert"] = False
                #print(data)
            flows.append(data)

        output = {}
        output["tw_start"] = datetime.datetime.fromtimestamp(self.tw_start).isoformat(' ')
        output["tw_end"] = datetime.datetime.fromtimestamp(self.tw_end).isoformat(' ')
        output["port_info"] = port_info
        #output["honeypots"] = self.active_honeypots
        #output["production_ports"] = self.production_ports
        output["flows"] = flows
        output["GameStrategyFileName"] = self.strategy_file
        #output["suricata_data"] = suricata_data
        return output

    def run(self):
        self.tw_end = time.time()
        next_start = self.tw_end
        try:
            #rotate suricata log file
            os.rename(self.suricata_log, self.suricata_tmp_log)
            os.kill(self.suricata_pid, signal.SIGHUP)
            #get data from Suricata-Extractor
            suricata_data = self.suricat_extractor.get_data(self.tw_start,self.tw_end,self.router_ip)
            os.remove(self.suricata_tmp_log)
        except FileNotFoundError:
            print(colored("Unable to locate the suricata log!","red"))
            self.terminate(status=-1)
        self.next_call += self.tw_length #this helps to avoid drifting in time windows
        next_start = self.tw_end
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
        output = self.generate_output(suricata_data)

        ###########################
        #-------------------------#
        #REMOVE BEFORE PUBLISHING #
        print(output)             #
        #-------------------------#
        ###########################

        #send data with Sentinel
        self.s.sendline(output)

        self.tw_start = self.tw_end
        print(f"------end: {datetime.datetime.fromtimestamp(self.tw_end)}--------")
        self.scheduler.enter((self.next_call +self.tw_length) - time.time(),1,self.run)

    
    def start(self):
        # check if suricata event file exist
        subprocess.call(["touch",self.suricata_log])
        # check if suricata is up and running
        process = subprocess.Popen('pidof suricata', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        if(len(err) > 0): #something wrong with the suricata running test
            print(colored("Error while testing if suricata is running.","red"))
            self.terminate(-1)
            sys.exit(-1)
        else:
            if(len(out) == 0): #no running suricata
                #TODO CHECK IF suricata.yaml is set up correctly
                print(colored("Suricata is required for running Ludus. Starting suricata with default configuration.", "red"))
                suricata_process =  subprocess.Popen('suricata -i eth1', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.suricata_pid = int(subprocess.check_output(["pidof","suricata"]))
                if ludus.suricata_pid:
                    print(colored("Suricata started", "green"))
                else:
                    print(colored("Error while starting suricata","red"))
                    self.terminate(-1)                    
                    sys.exit(-1)
        #start            
        print(colored(f"Ludus started on {datetime.datetime.now()}\n", "green"))
        # read configuration file
        self.read_configuration()
        #analyze the production ports
        (self.production_ports, self.active_honeypots)=get_ports_information()
        #get strategy
        suggested_honeypots = get_strategy(self.production_ports,self.active_honeypots,self.strategy_file)
        #apply strategy
        self.apply_strategy(suggested_honeypots)
        self.tw_start = time.time()
        self.scheduler = sched.scheduler()
        self.next_call = self.tw_start
        self.scheduler.enter(self.tw_length, 1, self.run)
        self.scheduler.run()
        
        #terminate the connection to DB
        self.terminate()

    def terminate(self,status=0):
        #close sentinel connection
        self.s.close()
        #kill suricata
        if self.suricata_pid:
            subprocess.check_output(["kill", str(ludus.suricata_pid)])
        if status == 0:
            print(colored("\nLeaving Ludus", "blue"))
        else:
            print(colored("\nError, terminating Ludus", "red"))

if __name__ == '__main__':

    # Parse the parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='Path to config file', action='store', required=False, type=str, default='/etc/ludus/ludus.config')
    parser.add_argument('-p', '--volumeter_port', help='Port to listen on to get data from Volumeter', action='store', default=53333, required=False, type=int)
    args = parser.parse_args()
    
    #start the tool
    print(colored(".-.   .-..-..--. .-..-..---.\n| |__ | || || \ \| || | \ \ \n`----'`----'`-'-'`----'`---'\n", "blue"))
    print(colored(f"\nVersion {VERSION}\n", "blue"))



    #check if suricata is running
    #process = subprocess.Popen('pidof suricata', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #out, err = process.communicate()
    
    #create ludus object
    ludus = Ludus(args.config)
    #
    #if(len(err) > 0): #something wrong with the suricata running test
    #   print("Error while testing if suricata is running.")
    try:
        """
        if(len(out) == 0): #no running suricata
            print(colored("Suricata is required for running Ludus. Starting suricata with default configuration.", "red"))
            suricata_process =  subprocess.Popen('suricata -i eth1', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ludus.suricata_pid = int(subprocess.check_output(["pidof","suricata"]))
        if ludus.suricata_pid:
            print(colored("Suricata is running", "green"))
        """
        # start ludus
        ludus.start()
    except KeyboardInterrupt:
        """
        ludus.s.close()
        subprocess.check_output(["kill", str(ludus.suricata_pid)])
        print(colored("\nLeaving Ludus", "blue"))
        """
        ludus.terminate(-1)