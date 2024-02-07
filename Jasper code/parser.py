import time
from yaml.loader import FullLoader
from model import *
from yaml import load, dump, load_all
import os
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

def formatlabel(label, value):
    return str.format(label +  ":" + value)

class ConfigParser:
    def __init__(self, filepath=None):
        self.filepath = filepath
        self.containers = []
        self.policies = []
        self.watched=[]

    def create_object(self, data):
        if data is not None:
            if data['kind'] == 'NetworkPolicy':
                try:
                    select = data['spec']['podSelector']['matchLabels']
                    polselect = PolicySelect(select, [])
                    for lab in polselect.labels:
                        polselect.concat_labels.append(formatlabel(lab, polselect.labels[lab]))
                            
                except KeyError:
                    select = {}
                if 'ingress' in data['spec']:
                    for ing in data['spec']['ingress']:
                        allow = []
                        ports = None
                        cidr = None

                        for f in ing['from']:
                            if 'podSelector' in f:
                                allow_labels=(f['podSelector']['matchLabels'])
                                concat_labels = []
                                for lab in allow_labels:
                                    concat_labels.append(formatlabel(lab, allow_labels[lab]))
                                allow_labels= PolicyAllow(allow_labels, concat_labels)
                                allow.append(allow_labels)
                            if 'ipBlock' in f:
                                cidr = (f['ipBlock']['cidr'])

                        if ing['ports']:
                            for p in ing['ports']:
                                if 'protocol' in p:
                                    if 'port' in p:
                                        ports = [p['protocol'], p['port']]

                        new_policy = Policy(data['metadata']['name'], polselect, allow, PolicyIngress, ports, cidr, len(self.policies))

                        self.policies.append(new_policy)
                        return(new_policy)

                if 'egress' in data['spec']:
                    for eg in data['spec']['egress']:
                        allow = []
                        ports = None
                        cidr = None
                        for t in eg['to']:

                            if 'podSelector' in t:
                                allow_labels=(t['podSelector']['matchLabels'])
                                concat_labels = []
                                for lab in allow_labels:
                                    concat_labels.append(formatlabel(lab, allow_labels[lab]))
                                allow_labels= PolicyAllow(allow_labels, concat_labels)
                                allow.append(allow_labels)
                            if 'ipBlock' in t:
                                cidr = (t['ipBlock']['cidr'])

                        if 'ports' in t:
                            for p in eg['ports']:
                                if 'protocol' in p:
                                    if 'port' in p:
                                        ports = [p['protocol'], p['port']]

                        new_policy = Policy(data['metadata']['name'], polselect, allow, PolicyEgress, ports, cidr, len(self.policies))
                        self.policies.append(new_policy)
                        return(new_policy)


            elif data['kind'] == 'Pod':
                labels = data['metadata']['labels']
                concat_labels = []
                for lab in labels:
                    concat_labels.append(formatlabel(lab, labels[lab]))
                new_container = Container(len(self.containers), data['metadata']['name'], labels, concat_labels, data['spec']['nodeName'], len(self.containers))
                self.containers.append(new_container)
                return(new_container)

    # Different because of differences in formatting of To  identifiers
    def create_object_from_event(self, data):
        if data is not None:
            if data['kind'] == 'NetworkPolicy':
                try:
                    select = data['spec']['pod_selector']['match_labels']
                    polselect = PolicySelect(select, [])
                    for lab in polselect.labels:
                        polselect.concat_labels.append(formatlabel(lab, polselect.labels[lab]))
                            
                except KeyError:
                    select = {}
                if 'ingress' in data['spec'] and data['spec']['ingress'] is not None:
                    for ing in data['spec']['ingress']:
                        allow = []
                        ports = None
                        cidr = None

                        for f in ing['_from']:
                            if 'pod_selector' in f:
                                allow_labels=(f['pod_selector']['match_labels'])
                                concat_labels = []
                                for lab in allow_labels:
                                    concat_labels.append(formatlabel(lab, allow_labels[lab]))
                                allow_labels= PolicyAllow(allow_labels, concat_labels)
                                allow.append(allow_labels)
                            if 'ip_block' in f:
                                if f['ip_block'] is not None:
                                    cidr = (f['ip_block']['cidr'])
                                else: cidr = None         
                            else: 
                                cidr = None                   

                        if ing['ports']:
                            for p in ing['ports']:
                                if 'protocol' in p:
                                    if 'port' in p:
                                        ports = [p['protocol'], p['port']]

                        new_policy = Policy(data['metadata']['name'], polselect, allow, PolicyIngress, ports, cidr)
                        self.policies.append(new_policy)
                        return(new_policy)

                if 'egress' in data['spec'] and data['spec']['egress'] is not None:
                    for eg in data['spec']['egress']:
                        allow = []
                        ports = None
                        cidr = None
                        for t in eg['to']:

                            if 'pod_selector' in t:
                                allow_labels=(t['pod_selector']['match_labels'])
                                concat_labels = []
                                for lab in allow_labels:
                                    concat_labels.append(formatlabel(lab, allow_labels[lab]))
                                allow_labels= PolicyAllow(allow_labels, concat_labels)
                                allow.append(allow_labels)
                            if 'ip_block' in t:
                                if t['ip_block'] is not None:
                                    cidr = (t['ip_block']['cidr'])
                                else: cidr = None         
                            else: 
                                cidr = None      
                        if 'ports' in t:
                            for p in eg['ports']:
                                if 'protocol' in p:
                                    if 'port' in p:
                                        ports = [p['protocol'], p['port']]  
                    
                        new_policy = Policy(data['metadata']['name'], polselect, allow, PolicyEgress, ports, cidr)
                        self.policies.append(new_policy)
                        return(new_policy)


            elif data['kind'] == 'Pod':
                labels = data['metadata']['labels']
                concat_labels = []
                for lab in labels:
                    concat_labels.append(formatlabel(lab, labels[lab]))
                new_container = Container(len(self.containers), data['metadata']['name'], labels, concat_labels, data['spec']['nodeName'])
                return(new_container)


    def print_all(self):
        for c in self.containers:
            print(c)
        for p in self.policies:
            print(p)
