import random
from model import *
import networkx as nx
from ipTrie import IpTrie
from kubernetes import client, config
from kubernetes.config import ConfigException

# We only generate single IPs within 192.168.0.1 till 192.168.0.10 to increase chance of overlap
def generate_random_ip():
    return f"192.168.0.{random.randint(1, 10)}"

# We only generate IP ranges wihin 192.168.0.1 till 192.168.0.100 to increase chance of overlap
# Ranges can be a max of 10 ips difference
def generate_random_ip_range():
    random_nr =  random.randint(1, 100)
    start_ip = "192.168.0." + str(random_nr)
    end_ip = "192.168.0." + str(random.randint(random_nr + 1, random_nr + 9))
    return f"{start_ip}-{end_ip}"

# We only generate IP ranges within 192.168.0.0 with subnetmask /24 or higher to increase chance of overlap
def generate_random_ip_range_by_subnet():
    base_ip = "192.168.0.0"
    subnet_mask = random.randint(24, 32)  # Random subnet mask length between 24 and 32
    ip_network = f"{base_ip}/{subnet_mask}"
    return ip_network

    
class Security_Groups_Information_Cluster:
    ingressTrie: IpTrie
    egressTrie: IpTrie
    sg_Graph: nx.DiGraph
    sg_to_nodes: set  # Security Group ID -> Set of Nodes
    node_to_sgs: set  # Node ID -> Set of Security Groups
    nodeName_to_nodeId: set # Node Name -> Node Id
    nodeId_to_nodeName: set # Node Name -> Node Id
    vmMatrix: []
    security_groups: set # SG Id -> Sg information

    def __init__(self):
        self.ingressTrie = IpTrie()
        self.egressTrie = IpTrie()
        self.sg_Graph = nx.DiGraph()
        self.sg_to_nodes = {}  # Security Group ID -> Set of Nodes
        self.node_to_sgs = {}  # Node ID -> Set of Security Groups
        self.nodeName_to_nodeId = {} # Node Name -> Node Id
        self.nodeId_to_nodeName = {} # Node Name -> Node Id
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
        if nr_of_nodes > 1:
            low = random.randint(0, nr_of_nodes - 2)
        else: 
            low = 1
        nr_of_sg = random.randint(low, nr_of_nodes + 8)
        # For testing purposes we use a low range of Ips.
        port_max = 10
        project_id = random.randint(0,999)

        # Generate random security groups and their rules.
        security_groups = {}

        for sg_id in range(nr_of_sg):
            security_group_name = f'SecurityGroup-{sg_id}'
            num_rules = random.randint(1, 3)  # Random number of rules per group
            rules = []
            for ruleId in range(num_rules):
                port_nr = random.randint(0, port_max)
                # We use only rules for one port for ease of testing. 
                ports = (port_nr, port_nr)
                direction = random.choice(list(SGDirection))
                protocol = random.choice(['tcp', 'udp', 'icmp'])
                ethertype = random.choice(list(Ethertype))
                # Generate a random ip rule
                random_nr = random.randint(1,3)
                if(random_nr == 1):
                    remote_ip = generate_random_ip()
                elif(random_nr == 2):
                    remote_ip = generate_random_ip_range()
                else:
                    remote_ip = generate_random_ip_range_by_subnet()

                rule = SGRule(ruleId, sg_id, direction, remote_ip, protocol, ports, ethertype, project_id, f"Security rule {ruleId} for Security group {security_group_name}")
                rules.append(rule)

                # Add the ip to the correct Trie and look for a corresponding rule in the opposite trie to check connectivity:
                if direction == SGDirection.EGRESS:
                    self.egressTrie.insert(remote_ip, protocol, ruleId, sg_id)
                    returned = self.ingressTrie.findruleIdByIpAndProtocol(remote_ip, protocol)
                    if returned is not None:
                        for i in range (len(returned)):
                            (returned_sg_id, returned_ruleId) = returned[i]
                            # A connection between SGs is possible, create the edge and store the ruleIds and protocol responsible within.
                            self.sg_Graph.add_edge(sg_id, returned_sg_id, **{'ruleIds': ((sg_id, ruleId), (returned_sg_id, returned_ruleId)), 'protocol': protocol})
                elif direction == SGDirection.INGRESS:
                    self.ingressTrie.insert(remote_ip, protocol, ruleId, sg_id)
                    returned = self.egressTrie.findruleIdByIpAndProtocol(remote_ip, protocol)
                    if returned is not None:
                        for i in range (len(returned)):
                            (returned_sg_id, returned_ruleId) = returned[i]
                            # A connection between SGs is possible, create the edge and store the ruleIds and protocol responsible within.
                            self.sg_Graph.add_edge(returned_sg_id, sg_id, **{'ruleIds': ((returned_sg_id, returned_ruleId), (sg_id, ruleId)), 'protocol': protocol})


            sg = Security_Group(sg_id, security_group_name, f"Security group {sg_id} with name {security_group_name}", project_id, rules)
            self.sg_Graph.add_node(sg_id)
            security_groups[sg_id] = sg
        self.security_groups = security_groups

        #STEP 2: Couple Nodes to Security groups and to their names
        for node in range(nr_of_nodes):
            self.link_nodeName_and_NodeId(nodes.items[node].metadata.name, node)
            nr_of_sg_to_link = random.randint(1,3)
            while nr_of_sg_to_link > 0:
                sg_to_link = random.randint(0, nr_of_sg - 1)
                self.link_node_and_sg(node, sg_to_link)
                nr_of_sg_to_link -= 1
        self.create_VM_matrix(nr_of_nodes)

    def create_VM_matrix(self, nr_of_nodes):
        tempMatrix = [[0] * nr_of_nodes for _ in range(nr_of_nodes)]

        # A node can communicate with itself
        for n in range(nr_of_nodes):
            tempMatrix[n][n] = 1

        # Check which SGs can communicate in the graph
        for sg1 in self.sg_Graph.nodes():
            for sg2 in self.sg_Graph.nodes():
                if self.sg_Graph.has_edge(sg1, sg2):
                    # Get the nodes associated with these security groups
                    nodes1 = self.get_nodes_for_security_group(sg1)
                    nodes2 = self.get_nodes_for_security_group(sg2)

                    # If nodes associated with these security groups exist,
                    # indicate communication in the vmMatrix
                    if nodes1 and nodes2:
                        for node1 in nodes1:
                            for node2 in nodes2:
                                tempMatrix[node1][node2] = 1

        self.vmMatrix = tempMatrix

    def print_info(self, verbose):
        if verbose:
            print("# Security Groups and rules:\n#")
            for i in self.security_groups:
                print(f"# {self.security_groups[i]}\n#")

            print("# Security Group nodes:")
            for sg in self.sg_Graph.nodes():
                print(f"# SG: {sg}, Out Edges: {list(self.sg_Graph.successors(sg))}, In Edges: {list(self.sg_Graph.predecessors(sg))}")

            # Print edge information
            print("#\n# Edges:")
            for edge in self.sg_Graph.edges():
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

        print("#\n# VM matrix:")
        
        for i in range(len(self.vmMatrix)):
            print(f"# {self.vmMatrix[i]}")
        print("#")
            
    def check_sg_connectivity(self, nodeName1, nodeName2, connection_wanted):
        sg1Set = self.node_to_sgs[self.nodeName_to_nodeId[nodeName1]]
        sg2Set = self.node_to_sgs[self.nodeName_to_nodeId[nodeName2]]
        print (f"\n  Node {nodeName1} is part of the following security groups:")
        for sg1 in sg1Set:
            print(f"   -{self.security_groups[sg1].name}")
        print (f"\n  Node {nodeName2} is part of the following security groups:")
        for sg2 in sg2Set:
            print(f"   -{self.security_groups[sg2].name}")

        connection = False
        for sg1 in sg1Set:
            for sg2 in sg2Set:
                if self.sg_Graph.has_edge(sg1, sg2):
                    connection = True
                    rule_ids = self.sg_Graph.get_edge_data(sg1, sg2).get('ruleIds', [])
                    print("\n  There is already a connection between the nodes in the right direction due to the following Security group rules:")
                    for rule_id in rule_ids:
                        sec_group = self.security_groups[rule_id[0]]
                        print(f"   -{sec_group.rules[rule_id[1]].description}")
                        print(f"      This rule is a {sec_group.rules[rule_id[1]].protocol} {sec_group.rules[rule_id[1]].direction.value} rule wich focusses the following ip range: {sec_group.rules[rule_id[1]].remote_ip_prefix}\n")
        if connection:
            if connection_wanted:
                print("  CONCLUSION: NO CONFLICTS\n")
            else:
                print("\n  Thus there is no communication possible between these nodes according to the Network Policies but their Security Groups still allow communication between their nodes")
                print("\n  CONCLUSTION: CONFLICT NEEDS REVIEWING\n")
        else:
            if connection_wanted:
                print("\n  There is however no communication possible in the right direction between these nodes since their Security Groups do not allow it")
                print("  CONCLUSTION: CONFLICT NEEDS REVIEWING\n")
            else:
                print("\n  None of the Security Groups of the respective nodes are able to communicate to each other.")
                print("  Thus there is no communication possible between these nodes on the NetworkPolicy level and their security groups also block their communication")
                print("\n  CONCLUSION: NO CONFLICTS\n")

    def link_node_and_sg(self, node, sg):
        if node not in self.node_to_sgs:
            self.node_to_sgs[node] = set()

        self.node_to_sgs[node].add(sg)

        if sg not in self.sg_to_nodes:
            self.sg_to_nodes[sg] = set()

        self.sg_to_nodes[sg].add(node)

    def link_nodeName_and_NodeId(self, name, id):
        self.nodeName_to_nodeId[name] = id
        self.nodeId_to_nodeName[id] = name


    # Given a security group, get all its nodes
    def get_nodes_for_security_group(self, security_group):
        return self.sg_to_nodes.get(security_group, set())

    # Given a node, get all its security groups
    def get_security_groups_for_node(self, node):
        return self.node_to_sgs.get(node, set())
    
    
if __name__ == '__main__':
    sgic = Security_Groups_Information_Cluster()
    sgic.generate_sg_information()
