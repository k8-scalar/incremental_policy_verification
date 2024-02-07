import random
from model import *
import networkx as nx
from kubernetes import client, config
from kubernetes.config import ConfigException
import ipaddress


# We only generate single IPs within 172.23.1.1 till 172.23.1.10 to increase chance of overlap
def generate_random_ip():
    return f"172.23.1.{random.randint(1, 10)}"

# We only generate IP ranges within 172.23.1.0 to 172.23.1.255 with subnetmask /24 or higher to increase chance of overlap
def generate_random_ip_network():
    fourth = random.randint(0, 255)
    base_ip = f"172.23.1.{fourth}" 
    subnet_mask = random.randint(24, 32)
    ip_network = f"{base_ip}/{subnet_mask}"
    return ip_network


def compare_overlap(original_ip1, original_ip2):
    parts_slash1 = original_ip1.split("/")
    parts_slash2 = original_ip2.split("/")

    if len(parts_slash1) == 2:
        ip1 =  ipaddress.IPv4Network(original_ip1, strict=False)

        if len(parts_slash2) == 2:
            ip2 = ipaddress.IPv4Network(original_ip2, strict=False)
            # 2 subnetmasks 
            return ip1.overlaps(ip2)
        else:
            ip2 = ipaddress.IPv4Address(original_ip2)
            return ip2 in ip1
    else:
        ip1 =  ipaddress.IPv4Address(original_ip1)
        if len(parts_slash2) == 2:
            ip2 = ipaddress.IPv4Network(original_ip2, strict=False)
            # 2 subnetmasks 
            return ip1 in ip2
        else:
            ip2 = ipaddress.IPv4Address(original_ip2)
            return ip1 == ip2
    
class Security_Groups_Information_Cluster:
    ingress_node_Graph: nx.DiGraph
    egress_node_Graph: nx.DiGraph

    sg_to_nodes: set  # Security Group ids -> Set of Nodes
    node_to_sgs: set  # Node ID -> Set of Security Groups ids

    nodeName_to_nodeId: set # Node Name -> Node Id
    nodeId_to_nodeName: set # Node Name -> Node Id

    nodeId_to_nodeIP: set # Node Id -> Node Ip
    nodeIp_to_nodeId: set # Node Ip -> Node Id

    sgName_to_sgId: set # SG Name -> SG Id
    sgId_to_sgName: set # SG Id -> SG Name

    vmMatrix: []
    security_groups: set # SG Id -> Sg information

    def __init__(self):
        self.ingress_node_Graph = nx.DiGraph()
        self.egress_node_Graph = nx.DiGraph()

        self.sg_to_nodes = {}  # Security Group ids -> Set of Nodes
        self.node_to_sgs = {}  # Node ID -> Set of Security ids

        self.nodeName_to_nodeId = {} # Node Name -> Node Id
        self.nodeId_to_nodeName = {} # Node Name -> Node Id

        self.sgName_to_sgId = {} # SG Name -> SG Id
        self.sgId_to_sgName = {} # SG Id -> SG Name

        self.nodeId_to_nodeIP = {} # Node Id -> Node Ip
        self.nodeIp_to_nodeId = {} # Node Ip -> Node Id
        self.vmMatrix = []
        self.security_groups = {}

    def generate_sg_information(self):
        
        try:
            config.load_incluster_config()
        except ConfigException:
            config.load_kube_config()

        api_instance = client.CoreV1Api()
        nodes = api_instance.list_node()
        nr_of_nodes = len(nodes.items)
        #STEP 1: Generate Random Security Groups
        if nr_of_nodes > 2:
            low = random.randint(1, nr_of_nodes - 2)
        else: 
            low = 1
        # CONSTANT Random number of security groups. 
        # min = between 1 and nr_of_nodes -2
        # max = nr_of_nodes + 8
        nr_of_sg = random.randint(low, nr_of_nodes + 8)
        # For testing purposes we use a low range of Ips.
        port_max = 10
        project_id = random.randint(0,999)

        # Generate random security groups and their rules.
        security_groups = {}

        for sg_id in range(nr_of_sg):
            security_group_name = f'SecurityGroup-{sg_id}'
            num_rules = random.randint(3, 5)  # CONSTANT Random number of rules per group
            rules = []
            for ruleId in range(num_rules):
                port_nr = random.randint(0, port_max)
                # We use only rules for one port for ease of testing. 
                ports = (port_nr, port_nr)
                direction = random.choice(list(SGDirection))
                protocol = random.choice(['tcp', 'udp', 'icmp'])
                ethertype = random.choice(list(Ethertype))
                # Generate a random ip rule
                random_nr = random.randint(1,5)
                if(random_nr == 1):
                    remote_ip = generate_random_ip()
                    remote_sg = None
                elif(random_nr == 2):
                    remote_ip = generate_random_ip_network()
                    remote_sg = None
                else:
                    if len(security_groups) > 0:
                        temp_id = random.randint(0, len(security_groups) - 1)
                        remote_sg = security_groups[temp_id].name
                        remote_ip = None
                    else:
                        remote_ip = generate_random_ip()
                        remote_sg = None

                rule = SGRule(ruleId, sg_id, direction, remote_ip, remote_sg, protocol, ports, ethertype, project_id, f"Security rule {ruleId} for Security group {security_group_name}")
                rules.append(rule)

            sg = Security_Group(sg_id, security_group_name, f"Security group {sg_id} with name {security_group_name}", project_id, rules)
            # self.node_Graph.add_node(sg_id)
            security_groups[sg_id] = sg
            self.link_sgName_to_sgId(sg.name, sg.id)
        self.security_groups = security_groups

        #STEP 2: Couple Nodes to Security groups and to their names and add nodes to graph
        for node in range(nr_of_nodes):
            self.link_nodeName_and_NodeId(nodes.items[node].metadata.name, node)
            node_address = nodes.items[node].status.addresses
            for address in node_address:
                    if address.type == 'InternalIP':
                        self.link_nodeId_and_nodeIp(node, address.address)
                    break
            self.ingress_node_Graph.add_node(node)
            self.egress_node_Graph.add_node(node)

            nr_of_sg_to_link = random.randint(3,5) # Constant nr of sg to link to a node 
            while nr_of_sg_to_link > 0:
                sg_to_link = random.randint(0, nr_of_sg - 1)
                security_groups[sg_to_link]
                self.link_node_and_sg(node, security_groups[sg_to_link])
                nr_of_sg_to_link -= 1

        #STEP 3: Create the graph edges
        for node in range(nr_of_nodes):
            for sg in self.node_to_sgs[node]:
                sgid = self.sgName_to_sgId[sg]
                for rule in security_groups[sgid].rules:
                    if isinstance(rule, SGRule):
                        if rule.direction == SGDirection.EGRESS:
                            if rule.remote_ip_prefix is not None:
                                for ip in self.nodeIp_to_nodeId.keys():
                                    if compare_overlap(rule.remote_ip_prefix, ip):
                                        self.egress_node_Graph.add_edge(node, self.nodeIp_to_nodeId[ip], rule=(sgid, rule.id))
                            if rule.remote_sg is not None:
                                if rule.remote_sg in self.sg_to_nodes:
                                    for n in self.sg_to_nodes[rule.remote_sg]:
                                        self.egress_node_Graph.add_edge(node, n, rule=(sgid, rule.id))
                        else:
                            if rule.remote_ip_prefix is not None:
                                for ip in self.nodeIp_to_nodeId.keys():
                                    if compare_overlap(rule.remote_ip_prefix, ip):
                                        self.ingress_node_Graph.add_edge(node, self.nodeIp_to_nodeId[ip], rule=(sgid, rule.id))
                            if rule.remote_sg is not None:
                                if rule.remote_sg in self.sg_to_nodes:
                                    for n in self.sg_to_nodes[rule.remote_sg]:
                                        self.ingress_node_Graph.add_edge(node, n, rule=(sgid, rule.id))
        self.create_VM_matrix(nr_of_nodes)

    def create_VM_matrix(self, nr_of_nodes):
        tempMatrix = [[0] * nr_of_nodes for _ in range(nr_of_nodes)]

        for n in range(nr_of_nodes):
            for m in range(nr_of_nodes):
                if self.egress_node_Graph.has_edge(n, m) and self.ingress_node_Graph.has_edge(n, m):
                    tempMatrix[n][m] = 1

        self.vmMatrix = tempMatrix

    def print_info(self, debug, verbose):
        if debug:
            print("# Security Groups and rules:\n#")
            for i in self.security_groups:
                print(f"# {self.security_groups[i]}\n#")

            # Print remote ip information
            print("#\n#remote ip:")
            for sg in self.security_groups.values():
                for rule in sg.rules:
                    print(f"# remote_ip: {rule.remote_ip_prefix}")


            # Print egress edge information
            print("#\n#egress Edges:")
            for edge in self.egress_node_Graph.edges():
                print(f"# Edge: {edge}")

             # Print ingress edge information
            print("#\n#ingress Edges:")
            for edge in self.ingress_node_Graph.edges():
                print(f"# Edge: {edge}")

            # Print out information about sg->nodes links
            print("#\n# Security groups to nodes:")
            for sg in self.sg_to_nodes:
                print(f"# Security group {sg}'s nodes: {self.get_nodes_for_security_group(sg)}")

            # Print out information about nodes->sg links
            print("#\n# Nodes to Security groups:")
            for node in self.node_to_sgs:
                print(f"# node {node}'s sgs: {self.get_security_groups_for_node(node)}")

             # Print out information about node Ids -> node names
            print("#\n# NodeIds to Node names:")
            for id in self.nodeId_to_nodeName:
                print(f"# node {id}'s name: {self.nodeId_to_nodeName[id]}")

            # Print out information about node names -> node Ids
            print("#\n# NodeIds to Node names:")
            for name in self.nodeName_to_nodeId:
                print(f"# node {name}'s id: {self.nodeName_to_nodeId[name]}")
        if verbose:
            print("#\n# VM matrix:")
            for i in range(len(self.vmMatrix)):
                print(f"# {self.vmMatrix[i]}")
            print("#")
            
    def check_sg_connectivity(self, nodeName1, nodeName2, connection_wanted):
        node1 = self.nodeName_to_nodeId[nodeName1]
        node2 = self.nodeName_to_nodeId[nodeName2]
        sg1Set = self.node_to_sgs[node1]
        sg2Set = self.node_to_sgs[node2]
        print (f"\n    Node {nodeName1} is part of the following security groups:")
        for sg1 in sg1Set:
            print(f"     -{sg1}")
        print (f"\n    Node {nodeName2} is part of the following security groups:")
        for sg2 in sg2Set:
            print(f"     -{sg2}")

        connection = False
        if self.vmMatrix[node1][node2] == 1:
            connection = True
            print("\n    There is a connection between the nodes in the correct direction due to the following Security group rules:\n")
            (sgid1, ruleid1) = self.ingress_node_Graph.get_edge_data(node1, node2)['rule']
            (sgid2, ruleid2) = self.egress_node_Graph.get_edge_data(node1, node2)['rule']
            rule1 = self.security_groups[sgid1].rules[ruleid1]
            rule2 = self.security_groups[sgid2].rules[ruleid2]

            print(f"        {rule1.description}")
            if rule1.remote_ip_prefix is not None:
                print(f"        This rule is a {rule1.protocol} {rule1.direction.value} rule wich focusses the following ip range: {rule1.remote_ip_prefix}\n")
            else:
                print(f"        This rule is a {rule1.protocol} {rule1.direction.value} rule wich focusses the following Security Groups: {rule1.remote_sg}\n")

            print(f"        {rule2.description}")
            if rule2.remote_ip_prefix is not None:
                print(f"        This rule is a {rule2.protocol} {rule2.direction.value} rule wich focusses the following ip range: {rule2.remote_ip_prefix}\n")
            else:
                print(f"        This rule is a {rule2.protocol} {rule2.direction.value} rule wich focusses the following Security Groups: {rule2.remote_sg}\n")
        if connection:
            if connection_wanted:
                print(f'\n  {colorize(f"=>", 32)} CONCLUSION: NO SG CONFLICTS\n')
            else:
                print("\n  Thus there is no communication possible between these nodes according to the Network Policies but their Security Groups still allow communication between their nodes")
                print(f'\n  {colorize(f"=>", 31)} CONCLUSION: SG CONFLICT NEEDS REVIEWING\n')
        else:
            if connection_wanted:
                print("\n  There is however no communication possible in the right direction between these nodes since their Security Groups do not allow it")
                print(f'\n  {colorize(f"=>", 31)} CONCLUSION: SG CONFLICT NEEDS REVIEWING\n')
            else:
                print("\n  None of the Security Groups of the respective nodes are able to communicate to each other.")
                print("  Thus there is no communication possible between these nodes on the NetworkPolicy level and their security groups also block their communication")
                print(f'\n  {colorize(f"=>", 32)} CONCLUSION: NO SG CONFLICTS\n')


    def link_node_and_sg(self, node, sg):
        if node not in self.node_to_sgs:
            self.node_to_sgs[node] = set()

        self.node_to_sgs[node].add(sg.name)

        if sg.name not in self.sg_to_nodes:
            self.sg_to_nodes[sg.name] = set()

        self.sg_to_nodes[sg.name].add(node)

    def link_nodeId_and_nodeIp(self, id, ip):
        self.nodeId_to_nodeIP[id] = ip
        self.nodeIp_to_nodeId[ip] = id

    def link_sgName_to_sgId(self, name, id):
        self.sgId_to_sgName[id] = name
        self.sgName_to_sgId[name] = id

    def link_nodeName_and_NodeId(self, name, id):
        self.nodeName_to_nodeId[name] = id
        self.nodeId_to_nodeName[id] = name


    # Given a security group, get all its nodes
    def get_nodes_for_security_group(self, security_group):
        return self.sg_to_nodes.get(security_group, set())

    # Given a node, get all its security groups
    def get_security_groups_for_node(self, node):
        return self.node_to_sgs.get(node, set())

if __name__ == "__main__":
    sgic = Security_Groups_Information_Cluster()
    sgic.generate_sg_information()