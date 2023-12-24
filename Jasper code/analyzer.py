from model import *
from parser import ConfigParser
import copy
from bitarray import bitarray
from sgic import Security_Groups_Information_Cluster
from kic import Kubernetes_Information_Cluster
from labelTree import LabelTree

def is_matrix_all_zero(matrix):
    for row in matrix:
        if row.any():
            return False  
    return True 

def find_obj_differences(obj1, obj2, parent_key=''):
    differences = {}
    for key, value1 in obj1.__dict__.items():
        value2 = obj2.__dict__[key]
        if isinstance(value1, dict) and isinstance(value2, dict):
            sub_differences = find_dict_differences(value1, value2, f"{parent_key}.{key}" if parent_key else key)
            differences.update(sub_differences)
        elif value1 != value2:
            differences[parent_key + '.' + key if parent_key else key] = (value1, value2)
    return differences

def find_dict_differences(dict1, dict2, parent_key=''):
    differences = {}
    
    for key in dict1:
        if key in dict2:
            value1 = dict1[key]
            value2 = dict2[key]
            if value1 != value2:
                differences[parent_key + '.' + key if parent_key else key] = (value1, value2)
        else:
            differences[parent_key + '.' + key if parent_key else key] = (dict1[key], None)
    
    for key in dict2:
        if key not in dict1:
            differences[parent_key + '.' + key if parent_key else key] = (None, dict2[key])
    
    return differences

class EventAnalyzer:
    verbose: bool
    debug: bool
    sgic: Security_Groups_Information_Cluster
    kic: Kubernetes_Information_Cluster
    cp = ConfigParser
    def __init__(self, verbose = False, debug = False):
        self.sgic = Security_Groups_Information_Cluster()
        self.kic = Kubernetes_Information_Cluster()
        self.cp = ConfigParser('/home/ubuntu/current-cluster-objects/')
        self.verbose = verbose
        self.debug = debug


    def startup(self, init_pods, init_pols):
        # Generate and store the reachabilitymatrix
   
        self.kic.generateAndStoreReachability(init_pods, init_pols)

        # store the containers and policies 
        for cont in init_pods:
           self.kic.insert_container(cont)

        for pol in init_pols:
           pol.working_select_set = None
           pol.working_allow_set = None
           self.kic.insert_policy(pol)

        # Generate security groups, security rules, and the corresponding VM matrix and store them. 
        self.sgic.generate_sg_information()

        # Set to true if you want all generated security groups and rules to be printed as well
        self.sgic.print_info(self.debug, self.verbose)
        self.kic.print_info(self.debug, self.verbose)


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
                if self.kic.reachabilitymatrix.dict_pols.keys():
                    obj.id = max(self.kic.reachabilitymatrix.dict_pols.keys()) + 1
                else:
                    obj.id = 0
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
                        obj = self.kic.reachabilitymatrix.dict_pols[i]
                        break
                new_reach = self.kic.reachabilityDeleteNP(obj)
                deltakano = [row1 ^ row2 for row1, row2 in zip(self.kic.reachabilitymatrix.matrix, new_reach.matrix)]
                if is_matrix_all_zero(deltakano):
                    # So even though a NP was removed there is still a connection between the containers according to the labels.
                    print("\n  This NetworkPolicy deletion does not remove any existing container connections")
                    # we get the containers that have all the labels in the select set
                    select_containers = bitarray('0'*len(new_reach.dict_pods))
                    first = True
                    for label in obj.selector.concat_labels:
                        conts = copy.deepcopy(new_reach.label_map.get(label))
                        if conts is not None:
                            if first:
                                first = False
                                select_containers = conts
                            else:
                                select_containers &= conts
                        else:
                            select_containers = bitarray('0'*len(new_reach.dict_pods))

                    # we get the containers that have all the labels in the allow set
                    allow_containers_final = bitarray('0'*len(new_reach.dict_pods))
                    for allow in obj.allow:
                        allow_containers = bitarray('0'*len(new_reach.dict_pods))
                        first = True
                        for allow_label in allow.concat_labels:
                            conts = copy.deepcopy(new_reach.label_map.get(allow_label))
                            if conts is not None:
                                if first:
                                    first = False
                                    allow_containers = conts
                                else:
                                    allow_containers &= conts 
                            else:
                                allow_containers = bitarray('0'*len(new_reach.dict_pods))
                                break
                        allow_containers_final |= allow_containers

                    if select_containers and allow_containers_final:
                        for select_cont in list(select_containers.itersearch(1)):
                            for allow_cont in list(allow_containers_final.itersearch(1)):
                                print(f"\n   container {self.kic.matrixId_to_Container[select_cont].name} connected to {self.kic.matrixId_to_Container[allow_cont].name} used this networkPolicy. This connection is however maintained by the following:")
                                for (index1, index2) in new_reach.resp_policies.get_items(self.kic.matrixId_to_Container[select_cont].id, self.kic.matrixId_to_Container[allow_cont].id):
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
            
            elif event['custom'] == "update":
                for key, value in self.kic.reachabilitymatrix.dict_pols.items():
                    if value.name == obj.name:
                        old_obj = value
                        break
                differences = find_obj_differences(old_obj, obj)
                if differences:
                    print("  The following changes have been found between the old NetworkPolicy and the updated Networkpolicy")

                    for key, (value1, value2) in differences.items():
                        #some keys should be ignored.
                        if key != "id" and key != "working_select_set" and key != "working_allow_set":
                            print(f"\n    -{key}:")
                            print(f"       old:     {value1}")
                            print(f"       updated: {value2}")
                    
                obj.id = old_obj.id

                old_matrix = copy.deepcopy(self.kic.reachabilitymatrix)
                old_matrixId_to_Container = copy.deepcopy(self.kic.matrixId_to_Container)
                deleted_reach = self.kic.reachabilityDeleteNP(old_obj)
                self.kic.delete_policy(old_obj)
                self.kic.reachabilitymatrix = deleted_reach

                new_reach = self.kic.reachabilityAddNP(obj)
                self.kic.insert_policy(obj)
             
                deltakano = [row1 ^ row2 for row1, row2 in zip(old_matrix.matrix, new_reach.matrix)]
                if is_matrix_all_zero(deltakano):
                    print("\n  The updated network policy does not trigger any change in connections and thus does not introduce any new conflicts")
                    print(f'\n    {colorize(f"=>", 32)} CONCLUSION: NO CONFLICTS\n')
                else:
                    for i, row in enumerate(deltakano):
                         for j, value in enumerate(row):
                            
                            if deltakano[i][j] == 1:
                                # First we get the nodes they are deployed on.
                                nodeName1 = old_matrixId_to_Container[i].nodeName
                                nodeName2 = old_matrixId_to_Container[j].nodeName
                                # So connectivity between these 2 containers has been removed, let us see see which security groups they belong to.
                                print("\n  The NetworkPolicy update has effect on the connectivity between following pods:")
                                if old_matrix.matrix[i][j] == 1:
                                    print(f"  {old_matrixId_to_Container[i].name} on node {nodeName1} can not send messages to {old_matrixId_to_Container[j].name} on node {nodeName2} anymore")
                                    # Now we look at SGs
                                    self.sgic.check_sg_connectivity(nodeName1, nodeName2, False)
                                else:
                                    print(f"  {old_matrixId_to_Container[i].name} on node {nodeName1} can now send messages to {old_matrixId_to_Container[j].name} on node {nodeName2}")
                                    # Now we look at SGs
                                    self.sgic.check_sg_connectivity(nodeName1, nodeName2, True)
                

        elif isinstance(obj, Container):
            if event['custom'] == "create":
                if (self.kic.reachabilitymatrix.dict_pods.keys()):
                    obj.id = max(self.kic.reachabilitymatrix.dict_pods.keys()) + 1
                else: 
                    obj.id = 0

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
                    if i.id != obj.id and new_reach.matrix[i.matrix_id][obj.matrix_id] == 1:
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
                for key, value in self.kic.reachabilitymatrix.dict_pods.items():
                    if value.name == obj.name:
                        obj.id = value.id
                        break
                obj =  self.kic.reachabilitymatrix.dict_pods[obj.id]  
                (new_reach, new_matrixId_to_Container) = self.kic.reachabilityDeleteContainer(obj)

                any_connections = False
                affected_policies = set()
                for j, i in self.kic.reachabilitymatrix.dict_pods.items():
                    if self.kic.reachabilitymatrix.matrix[obj.matrix_id][i.matrix_id] == 1:
                        any_connections = True
                        nodeName1 = obj.nodeName
                        nodeName2 = i.nodeName
                        # This connection was possible, so lets report the deletion of this connection
                        print(f'\n{colorize(f"  *", 36)} The deleted pod {obj.name} was deployed on node {nodeName1} and could communicate to pod {i.name} on node {nodeName2} thanks to the now deleted NetworkPolicy.\nThis connection has now been broken\n')
                        for (index1, index2) in self.kic.reachabilitymatrix.resp_policies.get_items(obj.id, i.id):   
                            if index1 in self.kic.reachabilitymatrix.dict_pols.keys():
                                affected_policies.add(index1)
                            if index2 in self.kic.reachabilitymatrix.dict_pols.keys():
                                affected_policies.add(index2)
                        self.sgic.check_sg_connectivity(nodeName1, nodeName2, False)

                    # The first part of the if stops reprinting the same policies for a self-connecting container
                    if i.id != obj.id and self.kic.reachabilitymatrix.matrix[i.matrix_id][obj.matrix_id] == 1:
                        any_connections = True
                        nodeName1 = i.nodeName
                        nodeName2 = obj.nodeName
                        for (index1, index2) in self.kic.reachabilitymatrix.resp_policies.get_items(i.id, obj.id):
                            # This connection with itself will be printed in the previous loop and thus this prevents double printing.
                            if i.id != obj.id:
                                print(f'\n{colorize(f"  *", 36)} pod {i.name} on node {nodeName1} could communicate to the deleted pod {obj.name} which was deployed on node {nodeName2} thanks to the now deleted NetworkPolicy\nThis connection has now been broken\n')
                                if index1 in self.kic.reachabilitymatrix.dict_pols.keys():
                                    affected_policies.add(index1)
                                if index2 in self.kic.reachabilitymatrix.dict_pols.keys():
                                    affected_policies.add(index2)
                        self.sgic.check_sg_connectivity(nodeName1, nodeName2, False)
                if affected_policies:
                    print("\n    Let us look at the NetworkPolicies that were used in combination with the now deleted pod, to check them for redundancy:")
                any_redundant = False
                for index in affected_policies:
                    policy = self.kic.reachabilitymatrix.dict_pols[index]
                    redundant = self.is_policy_redundant(policy, obj, new_reach, new_matrixId_to_Container)
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


                if not any_connections:
                    print(f"\n  The deleted pod {obj.name} was deployed on node {obj.nodeName} but had no connections to other pods according to the current NetworkPolicies")
                    print("  Checking the Security Groups is therefore also not necessary")
                    print(f'\n    {colorize(f"=>", 32)} CONCLUSION: NO POD LEVEL CONFLICTS\n')

                # # Lets update all that needs updating before finishing up
                self.kic.delete_container(obj)
                self.kic.matrixId_to_Container = new_matrixId_to_Container

            elif event['custom'] == "update":
                for key, value in self.kic.reachabilitymatrix.dict_pods.items():
                    if value.name == obj.name:
                        old_obj = value
                        break
                self.kic.update_container(old_obj, obj)
                differences = find_obj_differences(old_obj, obj)
                if differences:
                    print("  The following changes have been found between the old Pod and the updated Pod")

                    for key, (value1, value2) in differences.items():
                        # id is not assigned yet so should be ignored.
                        if key != "id":
                            print(f"\n    -{key}:")
                            print(f"       old:     {value1}")
                            print(f"       updated: {value2}")
                
                new_reach = self.kic.generateReachability(self.kic.pods, self.kic.pols)
                deltakano = [row1 ^ row2 for row1, row2 in zip(self.kic.reachabilitymatrix.matrix, new_reach.matrix)]
                if is_matrix_all_zero(deltakano):
                    print("\n  The updated container does not trigger any change in connections and thus does not introduce any new conflicts")
                    print(f'\n    {colorize(f"=>", 32)} CONCLUSION: NO CONFLICTS\n')
                else:
                    for i, row in enumerate(deltakano):
                         for j, value in enumerate(row):
                            
                            if deltakano[i][j] == 1:
                                # First we get the nodes they are deployed on.
                                nodeName1 = self.kic.matrixId_to_Container[i].nodeName
                                nodeName2 = self.kic.matrixId_to_Container[j].nodeName
                                # So connectivity between these 2 containers has been removed, let us see see which security groups they belong to.
                                print("\n  The container update has effect on the connectivity between following pods:")
                                if self.kic.reachabilitymatrix.matrix[i][j] == 1:
                                    print(f"  {self.kic.matrixId_to_Container[i].name} on node {nodeName1} can not send messages to {self.kic.matrixId_to_Container[j].name} on node {nodeName2} anymore")
                                    # Now we look at SGs
                                    self.sgic.check_sg_connectivity(nodeName1, nodeName2, False)
                                else:
                                    print(f"  {self.kic.matrixId_to_Container[i].name} on node {nodeName1} can now send messages to {self.kic.matrixId_to_Container[j].name} on node {nodeName2}")
                                    # Now we look at SGs
                                    self.sgic.check_sg_connectivity(nodeName1, nodeName2, True)
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
            

            print(f"\n   Responsible:")
            for cont1 in new_reach.dict_pods.values():
                for cont2 in new_reach.dict_pods.values():
                    a = new_reach.resp_policies.get_items(cont1.id, cont2.id)
                    if a:
                        print(f"{cont1.name} to {cont2.name}: {a}")
            print("  ***********************************************************************")
        self.kic.reachabilitymatrix = new_reach
        

    def is_policy_redundant(self, pol, cont, new_reach, new_matrixId_to_Container):
        # For each responsible policy where the connection was severed we look if it is responsible for another 
        # we get the containers that have all the labels in the select set
        select_containers = bitarray('0'*len(new_reach.dict_pods))
        first = True
        for label in pol.selector.concat_labels:
            if label in new_reach.label_map.keys():
                conts = copy.deepcopy(new_reach.label_map.get(label))
                if conts is not None:
                    if first:
                        first = False
                        select_containers = conts
                    else:
                        select_containers &= conts
                else:
                    select_containers = bitarray('0'*len(new_reach.dict_pods))
                    break
        # we get the containers that have all the labels in the allow set
        allow_containers_final = bitarray('0'*len(new_reach.dict_pods))
        for allow in pol.allow:
            allow_containers = bitarray('0'*len(new_reach.dict_pods))
            first = True
            for allow_label in allow.concat_labels:
                if allow_label in new_reach.label_map.keys():
                    conts = copy.deepcopy(new_reach.label_map.get(allow_label))
                    if conts is not None:
                        if first:
                            first = False
                            allow_containers = conts
                        else:
                            allow_containers &= conts 
                    else:            
                        allow_containers = bitarray('0'*len(new_reach.dict_pods))
                        break
            allow_containers_final |= allow_containers
        # If any other container is allowed it is clearly not redundant
        for matrix_id1 in select_containers:
            if self.kic.matrixId_to_Container[matrix_id1].id != cont.id:
                for matrix_id2 in allow_containers_final:
                    if self.kic.matrixId_to_Container[matrix_id2].id != cont.id:
                        resp1 = new_reach.resp_policies.get_items(new_matrixId_to_Container[matrix_id1].id, new_matrixId_to_Container[matrix_id2].id)
                        resp2 = new_reach.resp_policies.get_items(new_matrixId_to_Container[matrix_id2].id, new_matrixId_to_Container[matrix_id1].id)
                        if resp1 or resp2:
                            return False 
        return True
