from model import *
from parser import ConfigParser
import copy
from bitarray import bitarray
import numpy as np
from sgic import Security_Groups_Information_Cluster
from kic import Kubernetes_Information_Cluster
from labelTrie import LabelTrie

def is_matrix_all_zero(matrix):
    for row in matrix:
        if row.any():
            return False  
    return True 

class EventAnalyzer:
    verbose: bool
    sgic: Security_Groups_Information_Cluster
    kic: Kubernetes_Information_Cluster
    cp = ConfigParser
    def __init__(self, verbose = False):
        self.sgic = Security_Groups_Information_Cluster()
        self.kic = Kubernetes_Information_Cluster()
        self.cp = ConfigParser('/home/ubuntu/current-cluster-objects/')
        self.verbose = verbose


    def startup(self):
        # Retrieve the current containers and policies
        new_containers, new_policies = self.cp.parse() 

        # Generate and store the reachabilitymatrix
        self.kic.generateKanoMatrix(new_containers, new_policies)

        # store the containers and policies 
        for cont in new_containers:
           self.kic.insert_container(cont)

        for pol in new_policies:
           pol.working_select_set = None
           pol.working_allow_set = None
           self.kic.insert_policy(pol)

        # Generate security groups, security rules, and the corresponding VM matrix and store them. 
        self.sgic.generate_sg_information()

        # Set to true if you want all generated security groups and rules to be printed as well
        self.sgic.print_info(self.verbose)
        self.kic.print_info(self.verbose)


    def analyseStartup(self):    
        for i, container1 in self.kic.reachabilitymatrix.dict_pods.items():
            for j, container2 in self.kic.reachabilitymatrix.dict_pods.items():
                if self.kic.reachabilitymatrix.matrix[container1.matrix_id][container2.matrix_id] == 1:
                    nodeName1 = container1.nodeName
                    nodeName2 = container2.nodeName
                    print(f'{colorize(f"  *", 36)} {container1.name} on node {nodeName1} can communicate towards {container2.name} on node {nodeName2} according to the NetworkPolicies')
                    # We have a connection let us see if it is also allowed by the Security Groups
                    self.sgic.check_sg_connectivity(nodeName1, nodeName2, True)

    def analyseEvent(self, event):
        obj = self.cp.create_object_from_event(event)

        if isinstance(obj, Policy):
            if event['custom'] == "create":
                obj.id = max(self.kic.reachabilitymatrix.dict_pols.keys()) + 1
                new_reach = self.kic.reachabilityAddNP(obj)
                deltakano = [row1 ^ row2 for row1, row2 in zip(self.kic.reachabilitymatrix.matrix, new_reach.matrix)]
                   
                if is_matrix_all_zero(deltakano):
                    print("\n  The new network policy does not trigger any new container connections")
                    print(f'\n    {colorize(f"=>", 32)} CONCLUSION: NO POD LEVEL CONFLICTS\n')
                else:
                    for i, row in enumerate(deltakano):
                         for j, value in enumerate(row):
                            if deltakano[i][j] == 1:
                              
                                # So connectivity between these 2 containers has been created, let us see if the Security groups allow this.
                                # First we get the nodes they are deployed on.
                                nodeName1 = self.kic.matrixId_to_Container[i].nodeName
                                nodeName2 = self.kic.matrixId_to_Container[j].nodeName

                                print("  The new NetworkPolicy has effect on the connectivity between following pods:")
                                print(f"  {self.kic.matrixId_to_Container[i].name} on node {nodeName1} can now communicate towards {self.kic.matrixId_to_Container[j].name} on node {nodeName2} according to the NetworkPolicies")
                                                                
                                # Now we look at SGs
                                self.sgic.check_sg_connectivity(nodeName1, nodeName2, True)

                                
                # Lets update all that needs updating before finishing up
                self.kic.insert_policy(obj)

            elif event['custom'] == "delete":
                for i, pol in self.kic.reachabilitymatrix.dict_pols.items():
                    if pol.name == obj.name:
                        obj =  self.kic.reachabilitymatrix.dict_pols[pol.id]
                        break
            
                new_reach = self.kic.reachabilityDeleteNP(obj)
                deltakano = [row1 ^ row2 for row1, row2 in zip(self.kic.reachabilitymatrix.matrix, new_reach.matrix)]
                if is_matrix_all_zero(deltakano):
                    # So even though a NP was removed there is still a connection between the containers according to the labels.
                    print("\n  This NetworkPolicy deletion does not remove any existing container connections")
                    for select_label in obj.selector.concat_labels:
                        for allow in obj.allow:
                            for allow_label in allow.concat_labels:     
                                select_trie = self.kic.containerTrie.find(select_label)
                                allow_trie = self.kic.containerTrie.find(allow_label)
                                if select_trie is not None and allow_trie is not None:
                                    for select_cont in select_trie:
                                        for allow_cont in allow_trie:
                                            print(f"\n   container {select_cont.name} connected to {allow_cont.name} used this networkPolicy. This connection is however maintained by the following:")
                                            for (index1, index2) in new_reach.resp_policies.get_items(select_cont.id, allow_cont.id):
                                                if obj.direction.direction:
                                                    print(f"\n   - Networkpolicy {new_reach.dict_pols[index1].name}")
                                                else:
                                                    print(f"\n   - Networkpolicy {new_reach.dict_pols[index2].name}")
                                       
                                            print("   Any conflicts with the corresponding Security Groups would have been detected previously, hence should not be a concern now")                                              
                    print(f'\n    {colorize(f"=>", 32)} CONCLUSION: NO POD LEVEL CONFLICTS\n')

                else:
                    for i, row in enumerate(deltakano):
                         for j, value in enumerate(row):
                            # First we get the nodes they are deployed on.
                            nodeName1 = self.kic.matrixId_to_Container[i].nodeName
                            nodeName2 = self.kic.matrixId_to_Container[j].nodeName
                            if deltakano[i][j] == 1:
                                # So connectivity between these 2 containers has been removed, let us see see which security groups they belong to.
                                print("  The NetworkPolicy deletion has effect on the connectivity between following pods:")
                                print(f"  {self.kic.matrixId_to_Container[i].name} on node {nodeName1} can not send messages to {self.kic.matrixId_to_Container[j].name} on node {nodeName2} anymore")
                                
                                # Now we look at SGs
                                self.sgic.check_sg_connectivity(nodeName1, nodeName2, False)
              
                # Lets update all that needs updating before finishing up
                self.kic.delete_policy(obj)


        elif isinstance(obj, Container):
            if event['custom'] == "create":
                obj.id = max(self.kic.reachabilitymatrix.dict_pods.keys()) + 1
                new_reach = self.kic.reachabilityAddContainer(obj)

                any_connection = False
                for j, i in new_reach.dict_pods.items():
                    if new_reach.matrix[obj.matrix_id][i.matrix_id] == 1:
                        any_connection = True
                        nodeName1 = obj.nodeName
                        nodeName2 = i.nodeName
                        print(f'{colorize(f"  *", 36)} The new pod {obj.name} is deployed on node {nodeName1} and can communicate to pod {i.name} on node {nodeName2} according to the following NetworkPolicies\n')
                        for (index1, index2) in new_reach.resp_policies.get_items(obj.id, i.id):
                            policy1 = new_reach.dict_pols[index1]
                            print(f"    - NetworkPolicy {policy1.name}")
                            policy2 = new_reach.dict_pols[index2]
                            print(f"    - NetworkPolicy {policy2.name}")
                        # stops reprinting the same policies for a self-connecting container
                        if obj.id != i.id:
                            for (index1, index2) in new_reach.resp_policies.get_items(i.id, obj.id):
                                policy1 = new_reach.dict_pols[index1]
                                print(f"    - NetworkPolicy {policy1.name}")
                                policy2 = new_reach.dict_pols[index2]
                                print(f"    - NetworkPolicy {policy2.name}")
                        # Now we look at SGs
                        self.sgic.check_sg_connectivity(nodeName1, nodeName2, True)

                    # The first part of the if stops reprinting the same policies for a self-connecting container
                    if not i.id == obj.id and new_reach.matrix[i.matrix_id][obj.matrix_id] == 1:
                        any_connection = True
                        nodeName1 = i.nodeName
                        nodeName2 = obj.nodeName
                        print(f'{colorize(f"  *", 36)} pod {i.name} on node {nodeName2} can communicate to the new pod {obj.name} which is deployed on node {nodeName1} according to the following NetworkPolicies\n')
                        for (index1, index2) in new_reach.resp_policies.get_items(i.id, obj.id):
                            policy1 = new_reach.dict_pols[index1]
                            print(f"    - NetworkPolicy {policy1.name}")
                            policy2 = new_reach.dict_pols[index2]
                            print(f"    - NetworkPolicy {policy2.name}")
                        for (index1, index2) in new_reach.resp_policies.get_items(obj.id, i.id):
                            policy1 = new_reach.dict_pols[index1]
                            print(f"    - NetworkPolicy {policy1.name}")
                            policy2 = new_reach.dict_pols[index2]
                            print(f"    - NetworkPolicy {policy2.name}")
                        
                        # Now we look at SGs
                        self.sgic.check_sg_connectivity(nodeName1, nodeName2, True)
                if not any_connection:
                    print(f"  pod {obj.name} is deployed on node {obj.nodeName} but is not able to communicate to any other pods according to the current Network Policies")
                    print("  Checking the Security Groups is therefore also not necessary")                    
                    print(f'\n    {colorize(f"=>", 32)} CONCLUSION: NO POD LEVEL CONFLICTS\n')
                # Lets update all that needs updating before finishing up
                self.kic.insert_container(obj)

            elif event['custom'] == "delete":
                obj =  self.kic.reachabilitymatrix.dict_pods[obj.id]
                new_reach = self.kic.reachabilityDeleteContainer(obj)
                affected_policies = set()
                any_connections = False
                for j, i in self.kic.reachabilitymatrix.dict_pods.items():
                    if self.kic.reachabilitymatrix.matrix[obj.matrix_id][i.matrix_id] == 1:
                        any_connections = True
                        nodeName1 = obj.nodeName
                        nodeName2 = i.nodeName
                        # This connection was possible, so lets report the deletion of this connection
                        print(f'\n{colorize(f"  *", 36)} The deleted pod {obj.name} was deployed on node {nodeName1} and could communicate to pod {i.name} on node {nodeName2} according to the following NetworkPolicies\n')
                        for (index1, index2) in self.kic.reachabilitymatrix.resp_policies.get_items(obj.id, i.id):
                            policy = self.kic.reachabilitymatrix.dict_pols[index1]
                            print(f"    -NetworkPolicy {policy.name}")
                            policy2 = self.kic.reachabilitymatrix.dict_pols[index2]
                            print(f"    -NetworkPolicy {policy2.name}")
                            affected_policies.add(index1)
                            affected_policies.add(index2)
                        for (index1, index2) in self.kic.reachabilitymatrix.resp_policies.get_items(i.id, obj.id):
                            # This connection with itself will be printed in the previous loop and thus this prevents double printing.
                            if i.id != obj.id:
                                policy1 = self.kic.reachabilitymatrix.dict_pols[index1]
                                print(f"    - NetworkPolicy {policy1.name}")
                                policy2 = self.kic.reachabilitymatrix.dict_pols[index2]
                                print(f"    -NetworkPolicy {policy2.name}")
                                affected_policies.add(index1)
                                affected_policies.add(index2)

                        print("\n    Let us look at these NetworkPolicies for redundancy:")
                        any_redundant = False
                        for index in affected_policies:
                            policy = self.kic.reachabilitymatrix.dict_pols[index]
                            redundant = self.is_policy_redundant(policy, i.id)

                            if redundant:
                                any_redundant = True  
                                if policy.direction.direction:
                                    dir = "ingress"
                                else:
                                    dir = "egress"
                                print(f"\n      -NetworkPolicy {policy.name} is an {dir} policy that has become redundant as no connection between pods is established with the help of it")
                                print("       Consider deleting this NetworkPolicy")
                        if not any_redundant:
                            print("\n    No aforementioned NetworkPolicies have become redundant since either their select or one of their allow labels is still used by another pod")

                        self.sgic.check_sg_connectivity(nodeName1, nodeName2, False)
                
                if not any_connections:
                    print(f"\n  The deleted pod {obj.name} was deployed on node {obj.nodeName} but had no connections to other pods according to the current NetworkPolicies")
                    print("  Checking the Security Groups is therefore also not necessary")
                    print(f'\n    {colorize(f"=>", 32)} CONCLUSION: NO POD LEVEL CONFLICTS\n')

                # Lets update all that needs updating before finishing up
                self.kic.delete_container(obj)
        else:           
            raise ValueError("\ERROR: This is not a correct event and can not be handled correctly\n")
        
        if self.verbose:
            print("  ***********************************************************************")
            print(f"  * Old KanoMatrix:")
            for i, j in self.kic.reachabilitymatrix.dict_pods.items():
                print(f"  *   matrix index {j.matrix_id}: {j.name}")
            for row in self.kic.reachabilitymatrix.matrix:
                print(f"  *     {row}")
            print(f"  *\n  * New KanoMatrix:")
            for i, j in new_reach.dict_pods.items():
                print(f"  *   matrix index {j.matrix_id}: {j.name}")
            for row in new_reach.matrix:
                print(f"  *     {row}")
            print("  ***********************************************************************")

        self.kic.reachabilitymatrix = new_reach

    def is_policy_redundant(self, pol, cont):
    # For each responsible policy where the connection was severed we look if it is responsible for another 
        # We find all duos of containers by the policies select + an allow label
        for selectlabel in pol.selector.concat_labels:
            select_containers = self.kic.containerTrie.find(selectlabel)
            if select_containers is not None:
                for allow in pol.allow:
                    for allowlabel in allow.concat_labels:
                        allow_containers = self.kic.containerTrie.find(allowlabel)
                        # Now that we have the containers for a specific select and allow label we can checkt ehm
                        if allow_containers is not None:
                            for select_container in select_containers:
                                # Make sure this select is not the just deleted container
                                if select_container.id != cont:
                                    for allow_container in allow_containers:
                                        # Make sure this allow is not the just deleted container
                                        if allow_container.id != cont:
                                            # Lets get the responsible pols from this container duo
                                            responsible_pols = self.kic.reachabilitymatrix.resp_policies.get_items(select_container.id, allow_container.id)
                                            for policy in responsible_pols:
                                                # If the policy is within the responsible policies of this duo of containers it is clearly not redundant
                                                if policy == pol.id:
                                                    return False
        return True
if __name__ == '__main__':
    # Create a fake event for testing

    testevent = {'api_version': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': {'annotations': {'kubectl.kubernetes.io/last-applied-configuration': '{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"annotations":{},"name":"green-from-blue","namespace":"test"},"spec":{"ingress":[{"from":[{"podSelector":{"matchLabels":{"color":"blue"}}}],"ports":[{"port":80}]}],"podSelector":{"matchLabels":{"color":"green"}},"policyTypes":["Ingress"]}}\n'}, 'creation_timestamp': None, 'deletion_grace_period_seconds': None, 'deletion_timestamp': None, 'finalizers': None, 'generate_name': None, 'generation': 1, 'labels': None, 'managed_fields': [{'api_version': 'networking.k8s.io/v1', 'fields_type': 'FieldsV1', 'fields_v1': {'f:metadata': {'f:annotations': {'.': {}, 'f:kubectl.kubernetes.io/last-applied-configuration': {}}}, 'f:spec': {'f:ingress': {}, 'f:podSelector': {}, 'f:policyTypes': {}}}, 'manager': 'kubectl-client-side-apply', 'operation': 'Update', 'subresource': None, 'time': None}], 'name': 'green-from-blue', 'namespace': 'test', 'owner_references': None, 'resource_version': '38841157', 'self_link': None, 'uid': '0df34ecd-dc19-4eb1-b2c7-59132fca9314'}, 'spec': {'egress': None, 'ingress': [{'_from': [{'ip_block': None, 'namespace_selector': None, 'pod_selector': {'match_expressions': None, 'match_labels': {'color': 'blue'}}}], 'ports': [{'end_port': None, 'port': 80, 'protocol': 'TCP'}]}], 'pod_selector': {'match_expressions': None, 'match_labels': {'color': 'green'}}, 'policy_types': ['Ingress']}, 'status': None, 'custom': 'create'}
    analyzer = EventAnalyzer()
    analyzer.startup()
    analyzer.analyseEvent(testevent)

