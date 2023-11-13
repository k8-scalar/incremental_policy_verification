import time
from yaml.loader import FullLoader
from original.omodel import *
from yaml import load, dump, load_all
import os
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

class ConfigParser:
    def __init__(self, filepath=None):
        self.filepath = filepath
        self.containers = []
        self.policies = []
        self.watched=[]

    def parse(self, filepath=None):
        if filepath == None:
            filepath = self.filepath

        if filepath == None:
            print('no filepath specified')
            return

        if os.path.isfile(filepath):
            try:
                with open(filepath) as f:
                    data = load(f, Loader=Loader)
                    self.create_object(data)

            except:
                print("Error opening or reading file " + filepath)

        else:

            try:
                time.sleep(0.001)#Time to write yaml to data evaluated to be 0.0008
                for subdir, dirs, files in os.walk(filepath):
                    for file in files:
                        filename = os.path.join(subdir, file)

                        with open(filename) as f:
                            data = load(f, Loader=Loader)
                            self.create_object(data)
            except:
                print("Error opening or reading directory")
                raise

        return self.containers, self.policies

    def create_object(self, data):

        if data['kind'] == 'NetworkPolicy':
            try:
                select = data['spec']['podSelector']['matchLabels']
            except KeyError:
                select = {}
            if 'Ingress' in data['spec']['policyTypes']:
                
                for ing in data['spec']['ingress']:
                    allow = []
                    ports = None
                    cidr = None

                    for f in ing['from']:
                        if 'podSelector' in f:
                            allow_labels=(f['podSelector']['matchLabels'])
                            allow_labels= PolicyAllow(allow_labels)
                            allow.append(allow_labels)
                        if 'ipBlock' in f:
                            cidr = (f['ipBlock']['cidr'])

                    if ing['ports']:
                        for p in ing['ports']:
                            if 'protocol' in p:
                                if 'port' in p:
                                    ports = [p['protocol'], p['port']]

                    new_policy = Policy(data['metadata']['name'], PolicySelect(select), allow, PolicyIngress, ports, cidr)
                    self.policies.append(new_policy)


            if 'Egress' in data['spec']['policyTypes']:
                for eg in data['spec']['egress']:
                    allow = []
                    ports = None
                    cidr = None
                    for t in eg['to']:

                        if 'podSelector' in t:
                            allow_labels=(t['podSelector']['matchLabels'])
                            allow_labels= PolicyAllow(allow_labels)
                            allow.append(allow_labels)
                        if 'ipBlock' in t:
                            cidr = (t['ipBlock']['cidr'])

                    if 'ports' in t:
                        for p in eg['ports']:
                            if 'protocol' in p:
                                if 'port' in p:
                                    ports = [p['protocol'], p['port']]

                    new_policy = Policy(data['metadata']['name'], PolicySelect(select), allow, PolicyEgress, ports,cidr)
                    self.policies.append(new_policy)


        elif data['kind'] == 'Pod':
            labels = data['metadata']['labels']
            new_container = Container(data['metadata']['name'], labels, data['spec']['nodeName'])
            self.containers.append(new_container)


    def print_all(self):
        for c in self.containers:
            print(c)
        for p in self.policies:
            print(p)

def main():
   cp = ConfigParser()
   cp.parse('data')
   cp.print_all()

if __name__ == '__main__':
    main()

