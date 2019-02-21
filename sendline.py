import zmq
import msgpack

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

	data={
		"timestamp": "2011/12/22 13:14:15.654321+0230",
		"GameStrategyFileName": "strategy",
		"alerts":{
			"Alerts/DstBClassNet": {"123.456.789.101": 31, "8.8.8.8":15},
			"Alerts/SrcBClassNet": {"1.1.1.1":3},
			"# Severity 1": 9999,
			"# Severity 2": 7123,
			"# Severity 3": 8712,
			"# Severity 4": 651468,
			"# Uniq Signatures": 6584994,
			"Alerts Categories":{
					"Attempted Administrator Privilege Gain":11,
					"Executable Code was Detected": 7,
					"A TCP Connection was Detected": 9,
					"Potential Corporate Privacy Violation": 6,
					"Attempt to Login By a Default Username and Password": 3
			}
		},
		"PortInfo":{
			"TCP":{
				"22": {"type": "Honeypot", "bytes": 31, "Packets": 392, "Flows": 7896, "#Alerts": 78945},
				"80": {"type": "Production", "bytes": 33, "Packets": 777, "Flows": 1889, "#Alerts": 56432}
			},
			"UDP":{
				"32": {"type": "Honeypot", "bytes": 1203, "Packets": 64312, "Flows": 16854, "#Alerts": 87964},
				"80": {"type": "Production", "bytes": 999, "Packets": 83613, "Flows": 7861, "#Alerts": 45623}
			}
		}
	}
	print(type(data))

	s=Sendline() #na zacatku zavolas tohle

	s.sendline(data) #potom takhle odesilas data

	s.close() #na konci zavolas tohle.