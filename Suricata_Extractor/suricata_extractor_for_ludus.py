#!/usr/bin/python -u
# See the file 'LICENSE' for copying permission.
# Authors:  Sebastian Garcia. eldraco@gmail.com , sebastian.garcia@agents.fel.cvut.cz
#           Ondrej Lukas. ondrej.lukas95@gmail.com, lukasond@fel.cvut.cz

#TODO:
# add srcport in flows
import sys
import time
import os
import json
import math
from datetime import datetime
from datetime import timedelta
#from os.path import isfile, join
version = '0.3.2'


timewindows = {}
timeStampFormat = '%Y-%m-%dT%H:%M:%S.%f'
categories = {
    "Not Suspicious Traffic":[],
    "Unknown Traffic":[],
    "Potentially Bad Traffic":[],
    "Attempted Information Leak":[],
    "Information Leak":[],
    "Large Scale Information Leak":[],
    "Attempted Denial of Service":[],
    "Denial of Service":[],
    "Attempted User Privilege Gain":[],
    "Unsuccessful User Privilege Gain":[],
    "Successful User Privilege Gain":[],
    "Attempted Administrator Privilege Gain":[],
    "Successful Administrator Privilege Gain":[],
    "Decode of an RPC Query":[],
    "Executable Code was Detected":[],
    "A Suspicious String was Detected":[],
    "A Suspicious Filename was Detected":[],
    "An Attempted Login Using a Suspicious Username was Detected":[],
    "A System Call was Detected":[],
    "A TCP Connection was Detected":[],
    "A Network Trojan was Detected":[],
    "A Client was Using an Unusual Port":[],
    "Detection of a Network Scan":[],
    "Detection of a Denial of Service Attack":[],
    "Detection of a Non-Standard Protocol or Event":[],
    "Generic Protocol Command Decode":[],
    "Access to a Potentially Vulnerable Web Application":[],
    "Web Application Attack":[],
    "Misc activity":[],
    "Misc Attack":[],
    "Generic ICMP event":[],
    "Inappropriate Content was Detected":[],
    "Potential Corporate Privacy Violation":[],
    "Attempt to Login By a Default Username and Password":[]}

###################
# TimeWindow
class TimeWindow(object):
    """ Store info about the time window """
    def __init__(self, tw_start,tw_end):
        self.start = datetime.fromtimestamp(tw_start)
        self.end = datetime.fromtimestamp(tw_end)

        #self.categories = {}
        #self.severities = {}
        #self.severities[1] = 0
        #self.severities[2] = 0
        #self.severities[3] = 0
        #self.severities[4] = 0

        #self.signatures = {}
        #self.src_ips = {}
        #self.dst_ips = {}
        #self.src_ports = {}
        #self.dst_ports = {}
        # port_combinations will be: {dstip: {srcip: [1st port, 2nd port]}}
        #self.port_combinations = {}
        #self.final_count_per_dst_ip = {}
        # bandwidth = {dstport: [mbits]}
        #self.bandwidth = {}
        self.flows = {}
        self.alerts = {}
        self.packets_per_port = {}
        self.bytes_per_port = {}

    def add_flow(self, src_ip, dst_ip, srcport, dstport, proto, bytes_toserver, bytes_toclient, pkts_toserver, pkts_toclient, target_destination_ip, flow_id):
        """
        Receive a flow and use it
        """
        #print(src_ip, dst_ip, srcport, dstport, proto, bytes_toserver, bytes_toclient, pkts_toserver, pkts_toclient, target_destination_ip)
        if proto in ["tcp", "udp"]:
            if dst_ip in target_destination_ip:
                #save flow
                """
                try:
                    self.flows[src_ip,proto,dstport][0] += bytes_toserver
                    self.flows[src_ip,proto,dstport][1] += bytes_toclient
                    self.flows[src_ip,proto,dstport][2] += pkts_toserver
                    self.flows[src_ip,proto,dstport][3] += pkts_toclient
                except KeyError:
                    self.flows[src_ip,proto,dstport] = [bytes_toserver, bytes_toclient, pkts_toserver, pkts_toclient]
                """
                self.flows[flow_id] = {"src_ip":src_ip, "sport": srcport, "dport": dstport, "protcol": proto, "bytes_toclient":bytes_toclient, "bytes_toserver":bytes_toserver, "pkts_toserver":pkts_toserver, "pkts_toclient":pkts_toclient}
                #save port volumes
                try:
                    self.packets_per_port[proto, dstport][0] += pkts_toserver
                    self.packets_per_port[proto, dstport][1] += pkts_toclient
                    self.bytes_per_port[proto, dstport][0] += bytes_toserver
                    self.bytes_per_port[proto, dstport][1] += bytes_toclient
                except KeyError:
                    self.packets_per_port[proto, dstport] = [pkts_toserver, pkts_toclient]
                    self.bytes_per_port[proto, dstport] = [bytes_toserver, bytes_toclient]
        """
        if 'tcp' in proto:
            try:
                data = self.bandwidth[dstport]
                self.bandwidth[dstport] += bytes_toserver + bytes_toclient
            except KeyError:
                self.bandwidth[dstport] = bytes_toserver + bytes_toclient
        """
    def add_alert(self, category, severity, signature, src_ip,src_port, dst_ip, srcport, destport,flow_id):
        """
        Receive an alert and it adds it to the TW
        TODO:Check if there are any new fields in eve.json
        """
        #print("ALERT!!!!!!!!!!!")
        #print(category, severity, signature, src_ip, dst_ip, srcport, destport)
        self.alerts[flow_id] = {"src_ip":src_ip, "dst_ip": dst_ip, "sport":src_port, "dport": destport, "signature":signature, "severity":severity,"category":category}
        """
        def get_B_class_network(ip):
            splitted = ip.split(".")
            return "{}.{}".format(splitted[0], splitted[1]) 
        # Categories
        if category == '':
            try:
                self.categories["Unknown Traffic"] += 1
            except KeyError:
                self.categories["Unknown Traffic"] = 1
        else:
            try:
                self.categories[category] += 1
            except KeyError:
                self.categories[category] = 1
        # Severities
        try:
            self.severities[int(severity)] += 1
        except KeyError:
            self.severities[int(severity)] = 1
        # Signatures
        try:
            self.signatures[signature] += 1
        except KeyError:
            self.signatures[signature] = 1
        # Srcip
        #extract B class network (mask 255.255.0.0)

        try:
            self.src_ips[get_B_class_network(src_ip)] += 1
        except KeyError:
            self.src_ips[get_B_class_network(src_ip)] = 1
        # Dstip
        try:
            self.dst_ips[get_B_class_network(dst_ip)] += 1
        except KeyError:
            self.dst_ips[get_B_class_network(dst_ip)] = 1
        # Srcport
        try:
            self.src_ports[srcport] += 1
        except KeyError:
            self.src_ports[srcport] = 1
        # dstport
        try:
            self.dst_ports[destport] += 1
        except KeyError:
            self.dst_ports[destport] = 1

        #port combination
        if destport != '':
            try:
                srcdict = self.port_combinations[dst_ip]
                try:
                    # the dstip is there, the srcip is also there, just add the port
                    ports = srcdict[src_ip]
                    # We have this dstip, srcip, just add the port
                    try:
                        ports.index(destport)
                    except ValueError:
                        ports.append(destport)
                    srcdict[src_ip] = ports
                    self.port_combinations[dst_ip] = srcdict
                    #print 'Added port {}, to srcip {} attacking dstip {}'.format(destport, src_ip, dst_ip)
                except KeyError:
                    # first time for this src_ip attacking this dst_ip
                    ports = []
                    ports.append(destport)
                    srcdict[src_ip] = ports
                    self.port_combinations[dst_ip] = srcdict
                    #print 'New srcip {} attacking dstip {} on port {}'.format(src_ip, dst_ip, destport)
            except KeyError:
                # First time for this dst ip
                ports = []
                ports.append(destport)
                srcdict = {}
                srcdict[src_ip] = ports
                self.port_combinations[dst_ip] = srcdict
                #print 'New dst IP {}, attacked from srcip {} on port {}'.format(dst_ip, src_ip, destport)
    """
    def get_data_as_dict(self):
        data = {}
        #data["Alerts Categories"] = self.categories
        #data["# Uniq Signatures"] = len(self.signatures)
        #data["# Severity 1"] = self.severities[list(self.severities)[0]]
        #data["# Severity 2"] = self.severities[list(self.severities)[1]]
        #data["# Severity 3"] = self.severities[list(self.severities)[2]]
        #data["# Severity 4"] = self.severities[list(self.severities)[3]]
        #data["Alerts/DstPort"] = self.dst_ports
        #data["Alerts/SrcPort"] = self.src_ports
        #data["Alerts/SrcBClassNet"] = self.src_ips
        #data["Alerts/DstBClassNet"] = self.dst_ips
        #data["Per SrcPort"] = self.src_ports
        data["alerts"] = self.alerts
        data["flows"] = self.flows
        data["packets_per_port"] = self.packets_per_port
        data["bytes_per_port"] = self.bytes_per_port
        return data
    def __repr__(self):
        return 'TW: {}. #Categories: {}. #Signatures: {}. #SrcIp: {}. #DstIP: {}. #Severities: 1:{}, 2:{}, 3:{}, 4:{}'.format(str(self.start), len(self.categories), len(self.signatures), len(self.src_ips), len(self.dst_ips), self.severities[list(self.severities)[0]], self.severities[list(self.severities)[1]], self.severities[list(self.severities)[2]], self.severities[list(self.severities)[3]])

    def printit(self):
        pass    
        #print('TW: {}. #Categories: {}. #Signatures: {}. #SrcIp: {}. #DstIP: {}. #Severities: 1:{}, 2:{}, 3:{}, 4:{}'.format(str(self.start), len(self.categories), len(self.signatures), len(self.src_ips), len(self.dst_ips), self.severities[list(self.severities)[0]], self.severities[list(self.severities)[1]], self.severities[list(self.severities)[2]], self.severities[list(self.severities)[3]]))

def roundTime(dt=None, date_delta=timedelta(minutes=1), to='average'):
    """
    Round a datetime object to a multiple of a timedelta
    dt : datetime.datetime object, default now.
    dateDelta : timedelta object, we round to a multiple of this, default 1 minute.
    from:  http://stackoverflow.com/questions/3463930/how-to-round-the-minute-of-a-datetime-object-python
    """
    round_to = date_delta.total_seconds()
    if dt is None:
        dt = datetime.now()
    seconds = (dt - dt.min).seconds
    if to == 'up':
        # // is a floor division, not a comment on following line (like in javascript):
        rounding = (seconds + round_to) // round_to * round_to
    elif to == 'down':
        rounding = seconds // round_to * round_to
    else:
        rounding = (seconds + round_to / 2) // round_to * round_to
    return dt + timedelta(0, rounding - seconds, -dt.microsecond)

class Extractor(object):
    """Class for extracting information and alerts from suricata outptu file eve.json"""

    def __init__(self, filename=None):
        self.tw_archive = {}
        self.timewindow = None
        self.last_timestamp = None
        self.file = filename

    def process_line(self, line, timewindow, target_destination_ip):
        """
        Process each line, extract the columns, get the correct TW and store each alert on the TW object
        """
        json_line = json.loads(line)
        #check if we are in the timewindow
        line_timestamp = datetime.strptime(json_line["timestamp"].split('+')[0], timeStampFormat)
        if line_timestamp > timewindow.start or True:
            if line_timestamp <= timewindow.end or True:
                if "alert" not in json_line["event_type"] and "flow" not in json_line["event_type"]:
                    return False
                # forget the timezone for now with split
                try:
                    col_flow_id = json_line["flow_id"]
                except KeyError:
                    col_flow_id = ''
                try:
                    col_time = json_line["timestamp"].split('+')[0]
                except KeyError:
                    col_time = ''
                try:
                    col_category = json_line["alert"]["category"]
                except KeyError:
                    col_category = ''
                try:
                    col_severity = json_line["alert"]["severity"]
                except KeyError:
                    col_severity = ''
                try:
                    col_signature = json_line["alert"]['signature']
                except KeyError:
                    col_signature = ''
                try:
                    col_srcip = json_line['src_ip']
                except KeyError:
                    col_srcip = ''
                try:
                    col_dstip = json_line['dest_ip']
                except KeyError:
                    col_dstip = ''
                try:
                    col_srcport = json_line['src_port']
                except KeyError:
                    col_srcport = ''
                try:
                    col_dstport = json_line['dest_port']
                except KeyError:
                    col_dstport = ''

                # Get the time window object
                if 'alert' in json_line["event_type"]:
                    timewindow.add_alert(col_category, col_severity, col_signature, col_srcip,col_srcport, col_dstip, col_srcport, col_dstport, col_flow_id)
                elif 'flow' in json_line["event_type"]:
                    #print("FLOW PROCESSING")
                    try:
                        col_proto = json_line["proto"].lower()
                    except KeyError:
                        col_proto = ''
                    try:
                        col_bytes_toserver = json_line["flow"]["bytes_toserver"]
                    except KeyError:
                        col_bytes_toserver = ''
                    try:
                        col_bytes_toclient = json_line["flow"]["bytes_toclient"]
                    except KeyError:
                        col_bytes_toclient = ''
                    try:
                        col_pkts_toserver = json_line["flow"]["pkts_toserver"]
                    except KeyError:
                        col_pkts_toserver = ''
                    try:
                        col_pkts_toclient = json_line["flow"]["pkts_toclient"]
                    except KeyError:
                        col_pkts_toclient = ''
                    try:
                        flow_id = json_line["flow_id"]
                    except KeyError:
                        flow_id = ''
                    timewindow.add_flow(col_srcip, col_dstip, col_srcport, col_dstport, col_proto, col_bytes_toserver, col_bytes_toclient, col_pkts_toserver, col_pkts_toclient,target_destination_ip, col_flow_id)
            else: #we are out of TimeWindow
                self.last_timestamp = line_timestamp
                print("Out of TW")
                
    def get_data(self, tw_start, tw_end, target_destination_ip):
        self.timewindow = TimeWindow(tw_start,tw_end)
        #Check if there is a better way of iterate through file
        counter = 0;
        print(f"Starting reading of the suricata file :{self.file}")
        with open(self.file) as lines:
            for line in lines: #skip the lines we already inspected
                self.process_line(line,self.timewindow,target_destination_ip)
                counter+=1
        print("################### Number of processed lines:{} , size:{}##########################".format(counter, os.path.getsize(self.file)))
        return self.timewindow.get_data_as_dict()