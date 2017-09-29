
import time, threading, datetime
import sys
import json
import subprocess

import Strategizer.strategizer
import IPTablesAnalyzer.iptables_analyzer
from Volumeter.volumeter_client import Volumeter_client

VERSION = 0.3

DEFAULT_TW_LENGHT=60
VOLUMETER_PORT = 53333
CLIENT = Volumeter_client('localhost', 53333)
known_honeypots=['22', '23', '8080', '2323', '80', '3128', '8123']
strategy_file = 'Strategizer/strategies/2017-07-21-defenseStrategyWith2HP-zerosum-v1'


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
    #print "\tOpening HP in port: {}".format(port)

def close_honeypot(port,known_honeypots, protocol='tcp'):
    if port in known_honeypots:
            #ssh HP
            if port == '22':
                command = '/etc/init.d/mitmproxy_wrapper stop'
            #minipot
            else:
                command = 'uci del_list ucollect.fakes.disable='+port+protocol
        #no, use TARPIT
    else:
        command = 'iptables -D zone_wan_input 6'
    subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()
    #print "\tClosing HP in port: {}".format(port)

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
    def __init__(self, tw_length, volumeter_port, strategy_file, output_file):
        self.tw_length = tw_length
        self.volumeter_client = Volumeter_client('localhost', volumeter_port)
        self.hp_ports = []
        self.strategy_file = strategy_file
        self.ports_data = {}
        self.json_file = output_file

    def run(self):
        """Main loop"""
        self.tw_start = datetime.datetime.now()
        self.tw_end = self.tw_start + datetime.timedelta(seconds=DEFAULT_TW_LENGHT)
        
        try:    
            while True:
                #check if we are still in the TW
                if datetime.datetime.now() > self.tw_end:
                    #move the timewindow
                    old_tw_start = self.tw_start
                    self.tw_start = self.tw_end
                    self.tw_end = self.tw_start + datetime.timedelta(seconds=DEFAULT_TW_LENGHT)

                    #get data from Volumeter
                    volumeter_data = self.volumeter_client.get_data_and_reset()
                    #get data from Suricata-Extractor
                    suricata_data = []

                    #get the information about ports in use
                    (production_ports, active_hp) = get_ports_information()

                    #update honeypot distribution following the GT strategy        
                    self.hp_ports = Strategizer.strategizer.get_strategy(production_ports,active_hp,self.strategy_file)
                    #close previously opened HP which we do not want anymore
                    #are there any active_hp
                    
                    try:
                    	for port in active_hp:
	                        if port not in self.hp_ports:
	                            close_honeypot(port, known_honeypots)
                    except TypeError:
                    	pass
                    try:
                    	#open the Honeypots on suggested ports
	                    for port in self.hp_ports:
	                        if port not in active_hp:
	                            open_honeypot(port,known_honeypots)   
                    except TypeError:
                    	pass      
           	
                    #store the information in the file
                    output = {}
                    output['tw_start'] = old_tw_start.isoformat(' ')
                    output['tw_end'] = self.tw_start.isoformat(' ')
                    output['honeypots'] = active_hp
                    output['production_ports'] = production_ports

                    with open(self.json_file, 'a+') as fp:
                        s = json.dumps(output)
                        fp.write(s+'\n')
                    print "Timewindow started: {}, ended: {}".format(old_tw_start, self.tw_start)
                    print "\tProduction ports: {}".format(production_ports)
                    print "\tHoneyPots: {}".format(active_hp)
                    print "\tData from Volumeter:"
                    for item in volumeter_data:
                        #for key in item.keys():
                        port_number = int(item['id'])
                        if self.ports_data.has_key(port_number):
                            self.ports_data[port_number][0] += (item['tcp_pkts'] + item['tcp_buffer'])
                            self.ports_data[port_number][1] += item['tcp_bytes']
                            self.ports_data[port_number][2] += (item['udp_pkts'] + item['udp_buffer'])
                            self.ports_data[port_number][3] += item['udp_bytes']
                        else:
                            #create the tuple
                            self.ports_data[port_number] = [(item['tcp_pkts'] + item['tcp_buffer']), item['tcp_bytes'], (item['udp_pkts'] + item['udp_buffer']), item['udp_bytes']]
                    print "\t\tPORT\t[tcp pkts, tpc bytes, udp pkts, udp bytes]"
                    for key in self.ports_data.keys():
                        print "\t\t{}:\t{}".format(key, self.ports_data[key])
                    print
                #w8 for the next time window
                #time.sleep(DEFAULT_TW_LENGHT)
        #Asynchronous interruption
        except KeyboardInterrupt:
            print "\nInterrupted"


if __name__ == '__main__':       
    print ".-.   .-..-..--. .-..-..---.\n| |__ | || || \ \| || | \ \ \n`----'`----'`-'-'`----'`---'"
    print "\nVersion %s\n" % VERSION
    thread = Ludus(DEFAULT_TW_LENGHT, VOLUMETER_PORT, strategy_file,'test.json')
    thread.run()