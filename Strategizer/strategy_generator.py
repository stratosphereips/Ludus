#!/usr/bin/env python
#  Copyright (C) 2016  Sebastian Garcia
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Authors:
# Sebastian Garcia eldraco@gmail.com

# Description
# A program that reads the game-theoretic strategy to open honeypot ports and tell you which port to use as a honeypot based on your real production ports

import sys
import argparse
import operator
import random
import re

class defender():
    """
    Class to hold all the info about the ports of the defender 
    """
    def __init__(self):
        # The key is the ordered list of production ports separated by comma, and the value is a dictionary that holds the honeypot ports and its probabilities
        # defenders_actions = ['22,80':{443:0.2,23:0.8}, '443,53,119':{87:0.33, 88:0.33, 89:0.33}]
        self.defenders_actions = {}

    def store(self, production_ports, honeypot_ports, defender_action_probability):
        """
        Receive the production and honeyport ports and store them in a dict
        """
        try:
            current_honeypot_dict = self.defenders_actions[production_ports]
            # We have it
            # If we already have a honeypot_ports in this dict, it doesn't matter. The info is the same
            current_honeypot_dict[honeypot_ports] = defender_action_probability
        except KeyError:
            # First time
            honeypot_dict = {}
            honeypot_dict[honeypot_ports] = defender_action_probability
            self.defenders_actions[production_ports] = honeypot_dict

    def print_info(self):
        print 'Amount of diff prod ports: {}'.format(len(self.defenders_actions))
        #print 'Production ports: {}'.format(self.defenders_actions.keys())
        #print 'Honeypot ports: {}'.format(self.defenders_actions.values())

    def get_honeypot_ports(self, production_ports,debug=0):
        """
        Get the production ports and return the honeyport port according to the probabilities 
        """
        try:
            current_honeypot_dict = self.defenders_actions[production_ports]
            # We have it
            sorted_current_honeypot_dict = sorted(current_honeypot_dict.items(), key=operator.itemgetter(1))
            # The format of this last dict is something like this [('443', ' 0.08561247571157425'), ('21', ' 0.27429543264914535'), ('8080', ' 0.287672382290513'), ('80', ' 0.35241970934876826')]
            #print sorted_current_honeypot_dict
            probability = random.uniform(0, 1)
            if debug > 3:
                print 'Random Number: {}'.format(probability)
            for honeypot_tuple in sorted_current_honeypot_dict:
                if debug > 3:
                    print 'Trying with port {}, which has prob {}'.format(honeypot_tuple[0], honeypot_tuple[1])
                if probability < float(honeypot_tuple[1]):
                    if debug > 3:
                        print 'Match the random number {} with the port {}'.format(probability, honeypot_tuple)
                    return honeypot_tuple[0]
            # If there is no match, is the last one
            return sorted_current_honeypot_dict[-1][0]
        except KeyError:
            print production_ports
            print 'We never saw that combination of production ports {}. Sorry we can not help you now.'.format(production_ports)

def read_data(file, NewDefender, debug=0):
    f = open(file)
    line = f.readline()
    while line:
        # We read the lines with while to avoid reding issues of the file
        if '#' in line or 'defen' in line:
            line = f.readline()
            continue
        #prepare 
        nature_pattern = re.compile("(?<=N\[)(.*?)(?=\])")
        defender_pattern = re.compile("(?<=D\[)(.*?)(?=\])")


        production_ports =  nature_pattern.findall(line)[0]
        honeypot_ports =  defender_pattern.findall(line)[0]
        probability =  line.split("], ")[1].split(',')[0]

        # Store them in the dict
        NewDefender.store(production_ports, honeypot_ports, probability)

        #read next line
        line = f.readline()

def get_strategy(production_ports, strategy_file):
    NewDefender = defender()
    read_data(strategy_file, NewDefender,0)
    ret = NewDefender.get_honeypot_ports(production_ports)
    if ret:
        return ret.split(', ')
    else:
        return ret

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Tells you which honeypot port to open given your production ports.')
    parser.add_argument('-f', '--file', type=str, help='Strategy file')
    parser.add_argument('-d', '--debug', type=int, help='Debug. From 0 to 10', default=0)
    parser.add_argument('-p', '--ports', type=str, help='Comma separated list of production ports to test.')
    args = parser.parse_args()

    if not args.file:
        print 'Error. You should provide a strategy file with -f'
        sys.exit()
    # Create the defender object
    NewDefender = defender()

    # Read and load the data
    read_data(args.file, NewDefender,args.debug)

    # Read the production port
    if not args.ports:
        temp_production_ports = raw_input('Input the production ports (comma separated): ')
    else:
        temp_production_ports = args.ports
    try:
        production_ports = ','.join(map(str, sorted(map(int, temp_production_ports.split(',')), reverse=False)))
    except ValueError:
        print 'Sorry, only integers for the ports'
        sys.exit()

    # Get the honeyport port
    honeypot_port = NewDefender.get_honeypot_ports(production_ports,args.debug)
    print 'The honeypot port selected for you is: {}'.format(honeypot_port)




