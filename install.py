import os
import configparser
import urllib.request
from text_colors import colored

#update router
if os.system("opkg update") == 0:
	print(colored("Router up to date", "green"))

#CHECK DEPENDENCIES
#sentinel
os.system("opkg install python3-msgpack")
os.system("opkg install python3-zmq")
os.system("opkg install sentinel-proxy")
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
try:
	os.makedirs(config_path)
except:
	pass
try:
	os.makedirs(logdir)
except:
	pass
#get external IP using https://ipecho.net/plain service by Google
router_ip = urllib.request.urlopen('https://ipecho.net/plain').read().decode('utf8')
config_file= open(os.path.join(config_path,"ludus.config"), "w")
config = configparser.ConfigParser()
#settings
config.add_section("settings")
config.set("settings","router_ip", router_ip)
config.set("settings","timeout", "10")
config.set("settings", "logfile", os.path.join(logdir, "stats.log"))

#strategy
config.add_section("strategy")
config.set("strategy", "strategy_dir", strategy_dir)
config.set("strategy", "filename", "secConfDefAtt_1516886661989_-1HPsalgzerosum-bayes-relevant-NE-partial-att-strategy_Ports25")

#suricata
config.add_section("suricata")
config.set("suricata", "interface", "eth1")
config.set("suricata", "config", os.path.join(config_path, 'suricata_for_ludus.yaml'))
config.set("suricata", "logdir", logdir)
config.write(config_file)

# copy suricata.yaml and update it
#copy strategy files to strategy_dir
os.system(f"cat /etc/suricata/suricata.yaml | sed -e 's&[^$+#]HOME_NET:.*& HOME_NET: \"{router_ip}\"&' | sed -e 's&default-rule-path: .*&default-rule-path: /etc/ludus/rules&' > /etc/ludus/suricata_for_ludus.yaml")
os.system(f"cp -a ./Strategizer/strategies {strategy_dir}")

#donwload rules for suricata
os.system("wget https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz")
os.system(f"tar -C {config_path} -xvf emerging.rules.tar.gz")
os.system("rm emerging.rules.tar.gz")

# register ludus as process
print(colored("Instalation finished! See README for more information about Ludus", "green"))
print("For more information read README file")
#print("For starting the tool, type 'COMMAND TODO'.")
