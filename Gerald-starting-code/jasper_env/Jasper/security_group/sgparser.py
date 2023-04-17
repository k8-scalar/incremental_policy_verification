from neutronclient.v2_0 import client as neutclient
from novaclient import client as novaclient
from credentials import get_nova_creds
from security_group.sg_model import *

creds = get_nova_creds()
nova = novaclient.Client(**creds)
neutron = neutclient.Client(**creds)

def exception_handler(func):
    def inner_function(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except Exception as e:
            print(type(e).__name__ + ": " + str(e))
    return inner_function

class ConfigParser:
    def __init__(self):
        self.sgs = []
        self.nodes=[]
        self.sgs_on_node=[]


    def build_vm_matrix(self):
        for instance in nova.servers.list():
            if instance.name == "master" or instance.name == "client":
                continue
            self.nodes.append(instance.name)   

        for _, items in enumerate(self.nodes):
            att_sg=[]
            instance = nova.servers.find(name=items)
            for sg in instance.list_security_group():
                #att_sg.append(sg.name)
                att_sg.append(sg.id)# use sg_id instead of sg_name
            sgstonode=sgspernode(instance.name, att_sg)
            #self.sgs_on_node.append({instance.name:att_sg})
            self.sgs_on_node.append(sgstonode)
        


        for sg_items in neutron.list_security_groups()['security_groups']:
            sg_list=[]
            sg_rules=[]
            name=sg_items['name']
            for items in sg_items['security_group_rules']:
                direction=items['direction']
                protocol=items['protocol']
                maxport=items['port_range_max']
                minport=items['port_range_min']
                sg_id=items['security_group_id']
                rem_sg_id= items['remote_group_id']
                remote_cidr=items['remote_ip_prefix']
                rule=Rules(direction, protocol, [minport,maxport], remote_cidr, rem_sg_id)
                sg_rules.append(rule)
            for entry in self.sgs_on_node:
                if sg_id in entry.attachedsgs:
                    sg_list.append(entry.nodename)

            
            new_sg = OpSG(sg_id, name, sg_rules, sg_list)
            self.sgs.append(new_sg)
        return self.sgs, self.sgs_on_node

    def print_all(self):
        for sg in self.sgs:
            print(sg)
        for item in self.sgs_on_node:
            print(item)

def main():
   cp = ConfigParser()
   cp.print_all()
   
if __name__ == '__main__':
    main()

         


