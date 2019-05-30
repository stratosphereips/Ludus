import zmq
import msgpack
import json

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

if __name__ == '__main__':

	data = {"tw_start": "2019-05-06 14:14:11.715331", "tw_end": "2019-05-06 14:24:11.717495", "port_info": [{"port": 3389, "protocol": "tcp", "pkts_to_server": 1, "pkts_to_client": 1, "status": "closed", "bytes_to_server": 60, "bytes_to_client": 54}, {"port": 22, "protocol": "tcp", "pkts_to_server": 9, "pkts_to_client": 12, "status": "honeypot", "bytes_to_server": 707, "bytes_to_client": 1321}, {"port": 902, "protocol": "tcp", "status": "production", "pkts_toserver": 0, "pkts_toclient": 0, "bytes_to_server": 0, "bytes_to_client": 0}], "flows": [{"src_ip": "216.218.206.117", "sport": 59104, "dport": 3389, "protcol": "tcp", "bytes_toclient": 54, "bytes_toserver": 60, "pkts_toserver": 1, "pkts_toclient": 1, "alert": False}, {"src_ip": "162.243.136.225", "sport": 57966, "dport": 22, "protcol": "tcp", "bytes_toclient": 915, "bytes_toserver": 527, "pkts_toserver": 6, "pkts_toclient": 5, "alert": False}, {"src_ip": "162.243.136.225", "sport": 35164, "dport": 22, "protcol": "tcp", "bytes_toclient": 348, "bytes_toserver": 60, "pkts_toserver": 1, "pkts_toclient": 6, "alert": False}, {"src_ip": "80.211.41.196", "sport": 43444, "dport": 22, "protcol": "tcp", "bytes_toclient": 58, "bytes_toserver": 120, "pkts_toserver": 2, "pkts_toclient": 1, "alert": {"severity": 2, "category": "Misc Attack", "signature": "ET CINS Active Threat Intelligence Poor Reputation IP group 76"}}], "GameStrategyFileName": "/etc/ludus/strategies/secConfDefAtt_1516886661989_-1HPsalgzerosum-bayes-relevant-NE-partial-att-strategy_Ports25"}
	data = json.dumps(data)
	#print(type(data))
	print(data)
	s=Sendline() #na zacatku zavolas tohle

	s.sendline(data) #potom takhle odesilas data

	s.close() #na konci zavolas tohle.