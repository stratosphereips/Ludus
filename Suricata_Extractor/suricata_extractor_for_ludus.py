#!/usr/bin/python3 -u
# See the file 'LICENSE' for copying permission.
# Authors:  Sebastian Garcia. eldraco@gmail.com , sebastian.garcia@agents.fel.cvut.cz
#           Ondrej Lukas. ondrej.lukas95@gmail.com, lukasond@fel.cvut.cz

import sys
import json
import os
from datetime import datetime
from datetime import timedelta
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
        self.flows = {}
        self.alerts = {}
        self.packets_per_port = {}
        self.bytes_per_port = {}

    def add_flow(self, src_ip, dst_ip, srcport, dstport, proto, bytes_toserver, bytes_toclient, pkts_toserver, pkts_toclient, target_destination_ip, flow_id, state): 
        #Receive a flow and use it
        if proto in ["tcp", "udp"]:
            if dst_ip in target_destination_ip:
                #save flow
                self.flows[flow_id] = {"src_ip":src_ip, "sport": srcport, "dport": dstport, "protcol": proto, "bytes_toclient":bytes_toclient, "bytes_toserver":bytes_toserver, "pkts_toserver":pkts_toserver, "pkts_toclient":pkts_toclient, "state":state}
                #save port volumes
                try:
                    self.packets_per_port[proto, dstport][0] += pkts_toserver
                    self.packets_per_port[proto, dstport][1] += pkts_toclient
                    self.bytes_per_port[proto, dstport][0] += bytes_toserver
                    self.bytes_per_port[proto, dstport][1] += bytes_toclient
                except KeyError:
                    self.packets_per_port[proto, dstport] = [pkts_toserver, pkts_toclient]
                    self.bytes_per_port[proto, dstport] = [bytes_toserver, bytes_toclient]

    def add_alert(self, category, severity, signature, src_ip,src_port, dst_ip, srcport, destport, flow_id):
        """
        Receive an alert and it adds it to the TW
        TODO:Check if there are any new fields in eve.json
        """
        #self.alerts[flow_id] = {"src_ip":src_ip, "dst_ip": dst_ip, "sport":src_port, "dport": destport, "signature":signature, "severity":severity,"category":category}
        try:
            self.alerts[flow_id].append({"src_ip":src_ip, "dst_ip": dst_ip, "sport":src_port, "dport": destport, "signature":signature, "severity":severity,"category":category})
        except KeyError:
            self.alerts[flow_id] = [{"src_ip":src_ip, "dst_ip": dst_ip, "sport":src_port, "dport": destport, "signature":signature, "severity":severity,"category":category}]

    def get_data_as_dict(self):
        data = {}
        data["alerts"] = self.alerts
        data["flows"] = self.flows
        data["packets_per_port"] = self.packets_per_port
        data["bytes_per_port"] = self.bytes_per_port
        return data

    def __repr__(self):
        return 'TW: {}. #Categories: {}. #Signatures: {}. #SrcIp: {}. #DstIP: {}. #Severities: 1:{}, 2:{}, 3:{}, 4:{}'.format(str(self.start), len(self.categories), len(self.signatures), len(self.src_ips), len(self.dst_ips), self.severities[list(self.severities)[0]], self.severities[list(self.severities)[1]], self.severities[list(self.severities)[2]], self.severities[list(self.severities)[3]])

def round_time(dt=None, date_delta=timedelta(minutes=1), to='average'):
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

    def __init__(self, logdir, json_file="eve.json", alert_file="fast.log"):
        self.tw_archive = {}
        self.timewindow = None
        self.last_timestamp = None
        self.json_file = os.path.join(logdir, json_file)
        self.alert_file = os.path.join(logdir, alert_file)

    def process_line(self, line, timewindow, target_destination_ip):
        """
        Process each line, extract the columns, get the correct TW and store each alert on the TW object
        """
        try:
            json_line = json.loads(line)
        except json.decoder.JSONDecodeError:
            print(json_line)
            sys.exit()
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
            try:
                state = json_line["flow"]["state"]
            except KeyError:
                state = ""
            timewindow.add_flow(col_srcip, col_dstip, col_srcport, col_dstport, col_proto, col_bytes_toserver, col_bytes_toclient, col_pkts_toserver, col_pkts_toclient,target_destination_ip, col_flow_id, state)
    

                
    def get_data(self, tmp_file, tw_start, tw_end, target_destination_ip):

        self.timewindow = TimeWindow(tw_start,tw_end)
        #Check if there is a better way of iterate through file
        counter = 0
        with open(tmp_file) as lines:
            for line in lines: #skip the lines we already inspected
                self.process_line(line,self.timewindow,target_destination_ip)
                counter+=1
        
        #Check that the alert count is ok
        return self.timewindow.get_data_as_dict()
