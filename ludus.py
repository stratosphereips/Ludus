#!/usr/bin/python3
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

# Author:
# Ondrej Lukas - ondrej.lukas95@gmail.com , lukasond@fel.cvut.cz
# Project webpage: https://www.stratosphereips.org/ludus


#TODO:
#   check if sentinel is running !
import time,datetime
import sys
import subprocess
import Strategizer.generator as generator
import IPTablesAnalyzer.iptables_analyzer
import zmq
import msgpack
import sched
import os
import signal
import pickle
import json
import requests
import Suricata_Extractor.suricata_extractor_for_ludus as s_extractor
from multiprocessing import Process
from argparse import ArgumentParser
from configparser import ConfigParser,NoOptionError



VERSION = "0.9"

known_honeypots = [("tcp",22), ("tcp",23)]

def write_pid_file(pid_file):
    with open(pid_file, "w+") as fp:
        pid = str(os.getpid())
        fp.write(pid)

def store_to_tmp(data, last_tw_start, tmp_file):
    data_list = []
    def is_in_24h_tw(t1,t2):
        td = t2-t1
        return td.days < 1
    try:
        with open(tmp_file,"rb") as f:
            data_list = pickle.load(f)
    except FileNotFoundError:
        data_list = []
    data_list = [x for x in data_list if is_in_24h_tw(datetime.datetime.strptime(x["tw_start"], "%Y-%m-%d %H:%M:%S.%f"),last_tw_start)]
    data_list.append(data)
    with open(tmp_file, "wb") as f:
        pickle.dump(data_list, f)

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

class Logger():
    def __init__(self, logfile):
        self._target_file = logfile

    def log_event(self, msg):
        with open(self._target_file, "a") as out_file:
            print(f"[{datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')}]\t{msg}", file=out_file)
    
    def update_target_file(self, filename):
        self._target_file = filename

def open_honeypot(port, protocol, known_honeypots):
    if port == 22 and protocol == "tcp":
        subprocess.Popen("/etc/init.d/haas-proxy start", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()
    elif port == 23 and protocol == "tcp":
        subprocess.Popen("/etc/init.d/sentinel-minipot start", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()
    else:
        subprocess.Popen(f"iptables -I zone_wan_input 1 -p tcp --dport {port} -j TARPIT", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()

def close_honeypot(port, protocol, known_honeypots):
    if port == 22 and protocol == "tcp":
        subprocess.Popen("/etc/init.d/haas-proxy stop", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()
    elif port == 23 and protocol == "tcp":
        subprocess.Popen("/etc/init.d/sentinel-minipot stop", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()
    else:
        subprocess.Popen(f"iptables -D zone_wan_input -p tcp --dport {port} -j TARPIT", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()

def get_strategy(ports, active_honeypots, path_to_strategy):
    """Prepares the string in the format required in strategy generator and return the strategy"""
    #build the string
    if len(path_to_strategy) > 0:
        #get strategy
        defender = generator.Defender(path_to_strategy)
        suggested_honeypots = defender.get_strategy(ports)
        return suggested_honeypots
    else: #no strategy file, do nothing
        return []

def valid_ip4(string):
    try:
        l = [int(x) for x in string.split(".")]
        if len(l) != 4:
            return False
        for part in l:
            if part not in range(0,256,1):
                return False
        return True
    except (TypeError,ValueError):
        return False

def get_ports_information():
    data = IPTablesAnalyzer.iptables_analyzer.get_output()
    production_ports = []
    honeypots = []
    for protocol,key in data:
        #get active ports
        if data[protocol, key] == "accepted" or data[protocol,key] == "production":
            production_ports.append((protocol,key))
        #get honeypots
        if data[protocol, key] == "honeypot-turris":
            honeypots.append((protocol,key))
    return (production_ports, honeypots)

class Ludus(object):
    """Main program for LUDUS project"""
    def __init__(self, config_file="/etc/ludus/ludus.config", log_file = "/var/log/ludus/ludus.log"):
        self.config_parser = ConfigParser()
        self.logger = Logger(log_file)
        self.ludus_local_stats = None
        self.config_file = config_file
        self.suricata_log = None
        self.suricata_extractor = s_extractor.Extractor(logdir="/var/log/ludus")
        self.tw_start = None
        self.s = Sendline()
        self.next_call = 0
        self.suricata_pid = None
        self.read_configuration()
        self.strategy_timestamp = 0

    def check_strategy_update(self, verify=True):
        try:
            #get the information about the strategy
            r = requests.head(self.strategy_url, verify=verify)
            if r.status_code == 200:
                last_modified_url = r.headers["Last-Modified"].strip('\"')
                last_modified_url_dt = datetime.datetime.utcfromtimestamp(datetime.datetime.strptime(last_modified_url, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=datetime.timezone.utc).timestamp())
                
                current_strategy_dt = datetime.datetime.utcfromtimestamp(self.strategy_timestamp.replace(tzinfo=datetime.timezone.utc).timestamp())
                #compare the timestamps
                if current_strategy_dt < last_modified_url_dt:
                    tmp_file = "/tmp/tmp.gpg"
                    self.logger.log_event(f"New strategy available! Initializing update.")
                    r = requests.get(self.strategy_url, verify=verify)
                    open(tmp_file, 'wb').write(r.content)
                    #import the key
                    if subprocess.run(["gpg", "--import", "/etc/ludus/ludus-public-key.asc"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0:
                        #check signature
                        if subprocess.run(["gpg", "--verify", tmp_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0:
                            # decrypt it and store
                            r = subprocess.run(["gpg", "--decrypt", tmp_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            if r.returncode == 0:
                                filename = None
                                #check if the format is correct
                                for line in r.stdout.decode("utf-8").split("\n"):
                                    if "# name:" in line:
                                        filename = line.lstrip("# name:")
                                if filename:
                                    with open(os.path.join(self.strategy_dir, filename), "wb") as f:
                                        f.write(r.stdout)
                                    #remove the tmp_file
                                    os.remove(tmp_file)
                                    self.strategy_timestamp = last_modified_url_dt
                                    self.update_strategy_name(filename)
                                    self.logger.log_event(f"Strategy updated! New strategy: '{filename}'")
                                else:
                                    self.logger.log_event(f"Error - Invalid format of the strategy file! Strategy update skipped.")
                            else:
                                self.logger.log_event(f"Error - Could not decrypt the file using the Ludus key! Strategy update skipped.")
                        else:
                            self.logger.log_event(f"Error - File not signed by Ludus! Strategy update skipped.")
                    else:
                        self.logger.log_event(f"Error - Problem with the gpg key: '/etc/ludus/ludus-public-key.asc'")
            else:
                self.logger.log_event(f"Error while accesing the strategy URL - Status code:{r.status_code}")
        except requests.exceptions.RequestException as e:
            #log it
            self.logger.log_event(f"HTTPError while accesing the strategy webpage:'{strategy_url}'! Strategy update skipped.")
            self.logger.log_event(f"Excetion detail: {e}")
            pass
    def update_strategy_name(self, new_name):
        self.strategy_file = os.path.join(self.strategy_dir, new_name)
        self.config_parser.set("strategy","filename", str(new_name))
        with open(self.config_file, 'w') as configfile:
            self.config_parser.write(configfile)

    def read_configuration(self):
        """Reads values in ludus.conf and updates the settings accordily"""
        self.config_parser.read(self.config_file)
        #get strategy file and modified timestamp
        self.strategy_file = os.path.join(self.config_parser.get("strategy", "strategy_dir"),self.config_parser.get("strategy", "filename"))
        self.strategy_timestamp = datetime.datetime.utcfromtimestamp(os.path.getmtime(self.strategy_file))
        self.strategy_dir = self.config_parser.get("strategy", "strategy_dir")

        try:
            self.tw_length = self.config_parser.getint("settings", "timeout")*60
        except configparser.NoOptionError:
            self.tw_length = 600
        except ValueError:
            self.tw_length = 600
        #get router ip    
        try:
            self.router_ip = self.config_parser.get('settings', 'router_ip')
            if not valid_ip4(self.router_ip):
                self.logger.log_event(f"Error - Unsupported value in field 'router_ip'!, please check '{self.config_file}' and enter valid ipv4 address.")
                self.terminate(status=-1)
        except ValueError:
            self.logger.log_event("Error - Unknown value in field 'router_ip'!")
            self.terminate(status=-1)
        #get ludus logfile path
        try:
            self.logger.update_target_file(self.config_parser.get('settings', 'logfile'))
        except (ValueError, NoOptionError) as e:
            self.logger.update_target_file("/var/log/ludus/ludus.log")
        try:
            self.suricata_interface = self.config_parser.get('suricata', 'interface')
        except ValueError:
            self.suricata_interface = "eth1"

        try:
            self.suricata_logdir = self.config_parser.get('suricata', 'logdir')
            self.suricata_log = os.path.join(self.config_parser.get('suricata', 'logdir'), "eve.json")
        except ValueError:
            self.suricata_logdir = "/var/log/ludus/"
            self.suricata_log = "/var/log/ludus/eve.json"

        try:
            self.suricata_config = self.config_parser.get('suricata', 'config')
        except ValueError:
            self.suricata_interface = "/etc/ludus/suricata_for_ludus.yaml"

        try:
            self.ludus_local_stats = self.config_parser.get("settings", "local_stats")
        except ValueError:
            self.ludus_local_stats = "/tmp/ludus_local_data.pkl"
        try:
            self.instance_hash = self.config_parser.get("settings","installation_hash")
        except ValueError:
            self.instance_hash = "Unknown"
        try:
            self.strategy_url = self.config_parser.get("strategy","strategy_url")
        except (ValueError, NoOptionError) as e:
            self.strategy_url = "http://ludus.aic.fel.cvut.cz:443/newest.gpg"
        
    def apply_strategy(self, suggested_honeypots,known_honeypots=['22', '23', '8080', '2323', '80', '3128', '8123']):
        #close previously opened HP which we do not want anymore
        try:
            self.logger.log_event(f"ACTIVE:{self.active_honeypots}, SUGGESTED:{suggested_honeypots}")
            for port in self.active_honeypots:
                if not suggested_honeypots or port not in suggested_honeypots:
                    close_honeypot(port[1],port[0], known_honeypots)
        except TypeError:
            #no action required
            pass
        #open new HP ports
        try:
            #open the Honeypots on suggested ports
            for port in suggested_honeypots:
                if not self.active_honeypots or port not in self.active_honeypots:
                    open_honeypot(port[1],port[0],known_honeypots)
        except TypeError:
            #no action required
            pass
        self.logger.log_event(f"Opening honeypots in ports: {suggested_honeypots}")

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
        for protocol, dport in self.active_honeypots:
            if (protocol, dport) not in used:
                port_info.append({"port": dport, "protocol":protocol,"status":"honeypot", "pkts_toserver":0, "pkts_toclient":0, "bytes_to_server":0, "bytes_to_client":0})
        for protocol, dport in self.production_ports:
            if (protocol, dport) not in used:
                port_info.append({"port": dport, "protocol":protocol,"status":"production", "pkts_toserver":0, "pkts_toclient":0, "bytes_to_server":0, "bytes_to_client":0})
        flows = []
        for flow_id, data in suricata_data["flows"].items():
            data["alert"] = []
            if flow_id in suricata_data["alerts"].keys():
                for alert in suricata_data["alerts"][flow_id]:
                    tmp = {"severity": alert["severity"], "category":alert["category"], "signature":alert["signature"]}
                    data["alert"].append(tmp)
            flows.append(data)

        output = {}
        output["tw_start"] = datetime.datetime.fromtimestamp(self.tw_start).isoformat(' ')
        output["tw_end"] = datetime.datetime.fromtimestamp(self.tw_end).isoformat(' ')
        output["port_info"] = port_info
        output["flows"] = flows
        output["instance_hash"] = self.instance_hash
        output["GameStrategyFileName"] = self.strategy_file.split("/")[-1]
        output["timezone"] = time.tzname[0]
        return output

    def run(self):
        self.tw_end = time.time()
        next_start = self.tw_end
        try:
            #rotate suricata log file
            tmp_file = os.path.join(self.suricata_logdir,"tmp.json")
            os.rename(self.suricata_log, tmp_file)
            #create the file again
            open(os.path.join(self.suricata_logdir,"eve.json"), 'a').close()
            #tell suricata to reopen the eve.json file
            os.kill(self.suricata_pid, signal.SIGHUP)
            #get data from Suricata-Extractor
            suricata_data = self.suricata_extractor.get_data(tmp_file, self.tw_start, self.tw_end, self.router_ip)
            os.remove(tmp_file)

        except FileNotFoundError:
            self.logger.log_event("Unable to locate the suricata log - Leaving Ludus.")
            self.terminate(status=-1)
        self.next_call += self.tw_length #this helps to avoid drifting in time windows
        next_start = self.tw_end
        old_strategy = self.strategy_file
        #check if there is strategy update
        self.check_strategy_update()
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
        store_to_tmp(output, datetime.datetime.fromtimestamp(self.tw_start), self.ludus_local_stats)
        #send data with Sentinel
        self.s.sendline(output)

        self.tw_start = self.tw_end
        self.scheduler.enter((self.next_call +self.tw_length) - time.time(),1,self.run)

    def start(self):
        # read configuration file
        self.read_configuration()
        self.check_strategy_update()
        #create dir for logs
        try:
            os.makedirs(self.suricata_logdir)
        except FileExistsError:
            pass
        # check if suricata event file exist
        subprocess.call(["touch",self.suricata_log])
        #start suricata
        suricata_process =  subprocess.Popen(f'suricata -i {self.suricata_interface} -c {self.suricata_config} -l {self.suricata_logdir}', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.suricata_pid = suricata_process.pid
        if not self.suricata_pid:
            self.logger.log_event(f"Error while starting suricata: {proc.stderr.read()}")
            self.terminate(-1)                    
        
        #start
        self.logger.log_event("Ludus system started.")
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
        self.terminate(0)

    def terminate(self,status=0):
        #close sentinel connection
        if self.s:
            self.s.close()
        #kill suricata
        if self.suricata_pid:
            subprocess.check_output(["kill", str(ludus.suricata_pid)])
        if status == 0:
            self.logger.log_event("Stopping Ludus.")
        else:
            self.logger.log_event("Terminating Ludus.")
        sys.exit(status)
            
if __name__ == '__main__':
    # Parse the parameters
    parser = ArgumentParser()
    parser.add_argument('-c', '--config', help='Path to config file', action='store', required=False, type=str, default="/etc/ludus/ludus.config")
    parser.add_argument('--pidfile', help='Path to create pid file', action='store', required=False, type=str)
    args = parser.parse_args()
    
    if args.pidfile:
        write_pid_file(args.pidfile)
    #start the tool
    ludus = Ludus(args.config)
    try:
        ludus.start()
    except KeyboardInterrupt:
        ludus.terminate(0)