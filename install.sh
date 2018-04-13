#check if all dependencies are installed

#suricata
package_list=$(opkg list-installed)
if [[ ! $package_list = *"suricatax"* ]]; then
    echo "Suricata is required. Do you want to install it now?(Y/N)"
    read confirmatinon
    if [[ $confirmatinon == "Y" ]]; then
    	#install it
    	echo "Installing suricata package"
    	opkg install suricata
    else
    	exit 1
    fi
fi

#place ludus configuration file in correct place
cp ./src/ludus.conf /etc/ludus/

#
