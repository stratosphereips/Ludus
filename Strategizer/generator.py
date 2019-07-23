import sys
import re
import random

class Defender():
    def __init__(self, strategy_file):
        self.read_strategy(strategy_file)

    def read_strategy(self,strategy_file):
        self.strategies = {}
        with open(strategy_file, "r") as f:
            for line in f:
                if line.startswith("#") or line.startswith("defender-action"): #skip the comments
                    continue
                else:
                    #prepare 
                    nature_pattern = re.compile("(?<=N\[)(.*?)(?=\])")
                    defender_pattern = re.compile("(?<=D\[)(.*?)(?=\])")
                    probability =  float(line.split("], ")[1].split(',')[0])

                    production = []
                    for x in nature_pattern.findall(line)[0].split(","):
                        try:
                            production.append(int(x))
                        except ValueError:
                            production.append(None)
                    honeypots = []
                    for x in defender_pattern.findall(line)[0].split(','):
                        try:
                            honeypots.append(int(x))
                        except ValueError:
                            honeypots.append(None)
                    try:
                        self.strategies[frozenset(production)].append((frozenset(honeypots), probability))
                    except KeyError:
                        self.strategies[frozenset(production)] = [(frozenset(honeypots), probability)]
        #sort it by probabilities
        for k,v in self.strategies.items():
            self.strategies[k] = sorted(v,key=lambda x:x[1], reverse=True)

    def get_strategy(self, production_ports):
        production = frozenset(production_ports)
        if production in self.strategies.keys():
            return self.choose_strategy(self.strategies[production])
        else: #find the nearest neighbour candidates
            candidates = []
            size = float("inf")
            for x in self.strategies.keys():
                if x.issubset(production):
                    if len(x) < size:
                        candidates = [x]
                        size = len(x)
                    elif len(x) == size:
                        candidates.append(x)
            if len(candidates) > 0: #randomly choose winner from candidates with same distance
                random.shuffle(candidates)
                return self.choose_strategy(self.strategies[candidates[0]], production_ports)
            else:
                #No strategy can be aplied
                return None

    def choose_strategy(self, strategy_list, production_ports=None):
        if production_ports: #finding nearest neighbour strategy
            #filter the possible honeypots which collide with our production ports
            hp_list = [(hp_set,prob) for (hp_set,prob) in strategy_list if len(hp_set.intersection(production_ports))==0]
            if len(hp_list) == 0: #no honeypots letf after pruning
                return None
            if len(hp_list) < len(strategy_list):
                #recompute the probablities of filtered list so we have a valid distribution
                filtered_probabilities = sum([prob for (hp_set,prob) in strategy_list if (hp_set,prob) not in hp_list])
                diff = filtered_probabilities/(1 - filtered_probabilities)
                hp_list = [(hp_set,prob+prob*diff) for (hp_set,prob) in hp_list]
        else:
            hp_list = strategy_list
        roll = random.uniform(0,1)
        sum_p = 0
        for i in range(len(hp_list)):
            sum_p += hp_list[i][1]
            if roll <= sum_p:
                return hp_list[i][0]
        return None 


    def prune_candidates(self, candidates, production_ports):
        hp_list = [(hp_set,prob) for (hp_set,prob) in strategy_list if len(hp_set.intersection(production_ports))==0]
        if len(hp_list) == 0: #no honeypots letf after pruning
            return None
        if len(hp_list) < len(strategy_list):
            #recompute the probablities of filtered list so we have a valid distribution
            filtered_probabilities = sum([prob for (hp_set,prob) in strategy_list if (hp_set,prob) not in hp_list])
            diff = filtered_probabilities/(1 - filtered_probabilities)
            hp_list = [(hp_set,prob+prob*diff) for (hp_set,prob) in hp_list]