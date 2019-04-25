import os
import configparser
import urllib.request
from text_colors import colored

#update router
if os.system("opkg update") == 0:
	print(colored("Router up to date", "green"))

#CHECK DEPENDENCIES
#sentinel
os.system("opkg install sentinel-proxy")
os.system("opkg install python3-zmq")
os.system("opkg install python3-msgpack")
#start sentinel
os.system("/etc/init.d/sentinel-proxy start")

#suricata
os.system("opkg install suricata-bin")

#tarpit
os.system("opkg install iptables-mod-tarpit")
os.system("opkg install kmod-ipt-tarpit")

#create config file
config_path = "/etc/ludus"
logdir = "/var/log/ludus"
strategy_dir = "/etc/ludus/strategies"
os.makedirs(config_path)
os.makedirs(logdir)

#get external IP
router_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
config = ConfigParser.ConfigParser()
with (os.path.join(config_path,"ludus.config"), "w") as config_file:
	
	#settings
	config.add_section("settings")
	config.set("settings","router_ip", router_ip)
	config.set("settings","timeout", 600)
	config.set("settings", "logfile", os.path.join(logdir, "stats.log"))
	
	#strategy
	config.add_section("strategy")
	config.set("strategy", "	", strategy_dir)
	confgi.set("strategy", "filename", "secConfDefAtt_1516886661989_-1HPsalgzerosum-bayes-relevant-NE-partial-att-strategy_Ports25")
	
	#suricata
	config.add_section("suricata")
	config.set("suricata", "interface", "eth1")
	config.set("suricata", "config", os.path.join(config_path, 'suricata_for_ludus.yaml'))
	config.set("suricata", "logdir", logdir)
	config.write(config_path)

# copy suricata.yaml and update it
os.system(f"cp /etc/suricata/suricata.yaml {os.path.join(config_path, 'suricata_for_ludus.yaml')}")

#copy strategy files to strategy_dir
os.system(f"cp -a ./Strategizer/strategies {strategy_dir}")

# register ludus as process
print(colored("Instalation finished! See README for more information about Ludus", "green"))
print("For more information read README file")
#print("For starting the tool, type 'COMMAND TODO'.")