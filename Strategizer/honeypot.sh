#!/bin/bash
#SSH HP: uci del_list updater.pkglists.lists='i_agree_honeypot'
#MINIPOTS: uci del_list ucollect.fakes.disable='80tcp'

ACTION=
PORT=
PROTOCOL="tcp"
MINIPOTS=
#get action
if [ $1 == '-e' ] || [ $1 == '--enable' ] 
then
	ACTION='enable'
fi

if [ $1 == '-d' ] || [ $1 == '--disable' ] 
then
	ACTION='disable'
fi
#get port number
if [ $2 == '-p' ] || [ $2 == '--port' ] 
then
	PORT=$3
fi

#action with SSH HP?
if [[ condition ]]; then

	if [ $PORT == '22' ]
	then
		if [ $ACTION == 'enable' ]
		then
			/etc/init.d/mitmproxy_wrapper start
		else
			/etc/init.d/mitmproxy_wrapper stop
		fi
	else
		X=$PORT$PROTOCOL
		if [ $ACTION == 'enable' ]
		then
			uci del_list ucollect.fakes.disable=$X
		else
			uci add_list ucollect.fakes.disable=$X
		fi
		uci commit ucollect
	fi
else
	echo "TARPIT in port $PORT"
fi
echo "$ACTION HP on port $PORT"