import time, threading, datetime
import sys
import json
import subprocess
import argparse

import Strategizer.strategy_generator as generator
import IPTablesAnalyzer.iptables_analyzer
import Suricata_Extractor.suricata_extractor_for_ludus as s_extractor
from Volumeter.volumeter_client import Volumeter_client
from ConfigParser import SafeConfigParser
import Volumeter.volumeter as vol
from multiprocessing import Process

VERSION = 0.5

known_honeypots=['22', '23', '8080', '2323', '80', '3128', '8123']

def open_honeypot(port, known_honeypots, protocol='tcp'):
    if port in known_honeypots:
        #ssh HP
        if port == '22':
            command = '/etc/init.d/mitmproxy_wrapper start'
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
            command = '/etc/init.d/mitmproxy_wrapper stop'
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
    ports_s = ''
    for item in ports:
        ports_s += (str(item)+',')
    #get rid of the last comma
    ports_s = ports_s[0:-1]
    
    #get strategy
    suggested_honeypots = generator.get_strategy(ports_s,path_to_strategy)
    return suggested_honeypots

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
    def __init__(self, volumeter_port,config_file='/etc/ludus/ludus.config'):
        
        self.volumeter_client = Volumeter_client(volumeter_port)
        self.config_parser = parser = SafeConfigParser()
        self.config_file = config_file
        self.flag = threading.Event()
        self.suricat_extractor = s_extractor.Extractor("/root/var/log/suricata/eve.json")
        self.tw_start = None
        self.read_configuration()
        self.next_call = 0
        self.production_ports =[]
        self.active_honeypots = []

    def read_configuration(self):
        """Reads values in ludus.conf and updates the settings accordily"""
        self.config_parser.read(self.config_file)
        self.strategy_file = self.config_parser.get('strategy', 'filename')

        self.json_file = self.config_parser.get('output', 'filename')
        try:
            self.tw_length = self.config_parser.getint('settings', 'timeout')
        except ValueError:
            print("Unsupported value in field 'timeout' (expected int)! Using DEFAULT value 60 insted.")
            self.tw_length = 60
        try:
            self.use_suricata = self.config_parser.getboolean('suricata', 'allow')
        except ValueError:
            print("Unsupported value in field 'allow' (expected boolean)! Using DEFAULT value 'False' instead.")
            self.use_suricata = False

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


    def run(self):
        """Main loop"""
        
        #analyze the production ports
        (self.production_ports, self.active_honeypots)=get_ports_information()
        print "production_ports"
        print self.production_ports
        print "*************"
        #get strategy
        suggested_honeypots = get_strategy(self.production_ports,self.active_honeypots,self.strategy_file)
        #apply strategy
        self.apply_strategy(suggested_honeypots)
        self.tw_start = datetime.datetime.now()
        self.next_call = time.time()
        try:
            while not self.flag.wait(timeout=(self.next_call +self.tw_length) - time.time()):
                print "-------start: {}-------".format(datetime.datetime.now())
                self.next_call+= self.tw_length #this helps to avoid drifting in time windows
                self.tw_end = datetime.datetime.now()
            
                #get data from Volumeter
                volumeter_data = self.volumeter_client.get_data_and_reset()
                print "## volumeter data ##"
                print volumeter_data
                print "#################"
                #get data from Suricata-Extractor
                suricata_data = self.suricat_extractor.get_data(self.tw_start,self.tw_end)
                
                old_strategy = self.strategy_file
                #check if there is any change configuration
                self.read_configuration()

                #get the information about ports in use
                (production_ports, active_hp) = get_ports_information()
                print "production_ports"
                print self.production_ports
                print "*************"
                
                #do we need to change the defence_strategy?
                if set(production_ports) != set(self.production_ports) or self.strategy_file != old_strategy:
                    #update the settings
                    self.active_honeypots = active_hp
                    self.production_ports = production_ports
                    #get strategy
                    suggested_honeypots = get_strategy(self.production_ports,active_hp,self.strategy_file)
                    apply_strategy(suggested_honeypots)
                
                #store the information in the file
                output = {}
                output["tw_start"] = self.tw_start.isoformat(' ')
                output["tw_end"] = self.tw_end.isoformat(' ')
                output["honeypots"] = self.active_honeypots
                output["production_ports"] = self.production_ports
                output["strategy_file"] = self.strategy_file
                output["suricata_data"] = suricata_data
                output["volumeter_data"] = volumeter_data

                #-------------------------
                #REMOVE BEFORE PUBLISHING
                print(output)
                #-------------------------
                
                #write values in the file
                with open(self.json_file, 'a+') as fp:
                    s = json.dumps(output)
                    fp.write(s+'\n')
                #move TW
                self.tw_start = self.tw_end
                print("TW------end: {}--------".format(datetime.datetime.now()))            
        
        #Asynchronous interruption
        except KeyboardInterrupt:
            #terminate Volumeter
            self.volumeter_client.terminate()
            print("\nInterrupted")

if __name__ == '__main__':

    # Parse the parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='Path to config file', action='store', required=False, type=str, default='/etc/ludus/ludus.conf')
    parser.add_argument('-p', '--volumeter_port', help='Port to listen on to get data from Volumeter', action='store', default=53333, required=False, type=int)
    args = parser.parse_args()
    
    #start the tool
    print ".-.   .-..-..--. .-..-..---.\n| |__ | || || \ \| || | \ \ \n`----'`----'`-'-'`----'`---'"
    print "\nVersion %s\n" % VERSION
    print "Started on {}\n".format(datetime.datetime.now())


    #check if suricata is running
    process = subprocess.Popen('pidof suricata', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    ludus = Ludus(args.volumeter_port, args.config)
    if(len(err) > 0): #something wrong with the suricata running test
        print("Error while testing if suricata is running.")
    else:
        if(len(out) == 0): #no running suricata
            print("Suricata is required for running Ludus. Please start suricata and restart ludus.py")
        else: #its ok, proceed
            #start Volumeter
            v = vol.Volumeter('localhost', args.volumeter_port)
            p = Process(target=v.main, args=())
            p.start()
            #everything is set, start ludu
            ludus.run()
            p.join()
