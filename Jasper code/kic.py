from time import pthread_getcpuclockid
from labelTrie import LabelTrie
from model import *
import copy

def formatlabel(label, value):
    return str.format(label +  ":" + value)

class Kubernetes_Information_Cluster:
    eggressTrie: LabelTrie
    ingressTrie: LabelTrie
    containerTrie: LabelTrie
    reachabilitymatrix: ReachabilityMatrix
    pods: list
    pols: list
    

    def __init__(self):
        self.eggressTrie = LabelTrie()
        self.ingressTrie = LabelTrie()
        self.containerTrie = LabelTrie()
        self.reachabilitymatrix = ReachabilityMatrix()
        self.matrixId_to_Container = {}
        self.pods = []
        self.pols = []

    def insert_container(self, obj):
        if isinstance(obj, Container):
            for lab in obj.concat_labels:
                self.containerTrie.insert(lab, obj)
            self.matrixId_to_Container[obj.matrix_id]= obj
            self.pods.append(obj)

        else:
            raise ValueError("data is not a Container object")
        
    def delete_container(self, obj):
        if isinstance(obj, Container):
            for lab in obj.concat_labels:
                self.containerTrie.delete(lab, obj)
            del self.matrixId_to_Container[obj.matrix_id]
            self.pods.remove(obj)
        else:
            raise ValueError("Data is not a Container object")
        
    def update_container(self, old_obj, obj):
        if isinstance(obj, Container):
            for lab in old_obj.concat_labels:
                self.containerTrie.delete(lab, old_obj)
            for lab in obj.concat_labels:
                self.containerTrie.insert(lab, obj)
            obj.matrix_id = old_obj.matrix_id
            obj.id = old_obj.id
            self.matrixId_to_Container[old_obj.matrix_id] = obj
            index = self.pods.index(old_obj)
            self.pods.remove(old_obj)
            self.pods.insert(index, obj)
        else:
            raise ValueError("Data is not a Container object")

    # We store the selector labels, so we can e.g. search all ingress rules applied to a label
    def insert_policy(self, obj):
        if isinstance(obj, Policy):
            self.pols.append(obj)
            if obj.direction.direction:
                # Ingress
                for lab in obj.selector.concat_labels:
                    self.ingressTrie.insert(lab, obj)
            else:
                # Egress
                for lab in obj.selector.concat_labels:
                    self.eggressTrie.insert(lab, obj)
        else:
            raise ValueError("data is not a Policy object")
        
    def delete_policy(self, obj):
        if isinstance(obj, Policy):
            self.pols.remove(obj)
            if obj.direction.direction:
                # Ingress
                for lab in obj.selector.concat_labels:
                    self.ingressTrie.delete(lab, obj)
            else:
                # Egress
                for lab in obj.selector.concat_labels:
                    self.eggressTrie.delete(lab, obj)
        else:
            raise ValueError("Data is not a Policy object")
        
    def generateAndStoreReachability(self, containers, policies):
        self.reachabilitymatrix.build_matrix(containers, policies)
    
    def generateReachability(self, containers, policies):
        reach = ReachabilityMatrix()
        reach.build_matrix(containers, policies)
        return reach
    
    def reachabilityAddNP(self, obj: Policy):
        new_reachability = copy.deepcopy(self.reachabilitymatrix)
        # we get the containers that have all the labels in the select set
        select_containers = set()
        first = True
        for select_label in obj.selector.concat_labels:
            matrix_ids = set()
            conts = self.containerTrie.find(select_label)
            if conts:
                matrix_ids.update(cont.matrix_id for cont in conts)
        
            if first and matrix_ids:
                first = False
                select_containers = matrix_ids
            else:
                select_containers = select_containers.intersection(matrix_ids)

        # we get the containers that have all the labels in the allow set
        allow_containers_final = set()
        for allow in obj.allow:
            allow_containers = set()
            first = True
            for allow_label in allow.concat_labels:
                matrix_ids = set()
                conts = self.containerTrie.find(allow_label)
                if conts:
                    
                    matrix_ids.update(cont.matrix_id for cont in conts)
                if first and matrix_ids:
                    first = False
                    allow_containers = matrix_ids
                else:
                    allow_containers = allow_containers.intersection(matrix_ids)   
            allow_containers_final.update(allow_containers)

        # Now for each of the labels in these allow containers we find the existing NPs in the opposite direction
        if select_containers and allow_containers_final:
            opposite_policies = set()
            for container in allow_containers_final:
                for cont_label in self.matrixId_to_Container[container].concat_labels:
                    if obj.direction.direction:
                        # INGRESS -> we look at existing egress rules
                        trienode = self.eggressTrie.find(cont_label)
                        
                    else:
                        # EGRESS -> we look at existing ingress rules
                        trienode = self.ingressTrie.find(cont_label)
                    # we add all opposite policies to a set if their select labels match our containers labels
                    if trienode is not None:
                        for item in trienode:
                            if all(item_label in self.matrixId_to_Container[container].concat_labels for item_label in item.selector.concat_labels):
                                opposite_policies.add((item.id, container))
            # Now we check if the opposite policy allows the select containers from the original policy
            for (pol_id, allowed_cont) in opposite_policies:
                pol = self.reachabilitymatrix.dict_pols[pol_id]
                for container2 in select_containers:
                    for pol_allow in pol.allow:
                        if all(pol_label in self.matrixId_to_Container[container2].concat_labels for pol_label in pol_allow.concat_labels):
                            # We have containers that can connect. Lets change the new matrix to reflect this. 
                            # This is dependant on the type of the new policy as well
                            if obj.direction.direction:
                                # INGRESS
                                new_reachability.matrix[allowed_cont][container2] = 1
                                new_reachability.resp_policies.add_item(self.matrixId_to_Container[allowed_cont].id, self.matrixId_to_Container[container2].id, (obj.id, pol.id))
                            else:
                                # EGRESS
                                new_reachability.matrix[container2][allowed_cont] = 1
                                new_reachability.resp_policies.add_item(self.matrixId_to_Container[container2].id, self.matrixId_to_Container[allowed_cont].id, (pol.id, obj.id))
        new_reachability.dict_pols[obj.id] = obj
        return new_reachability

    def reachabilityDeleteNP(self, obj: Policy):
        new_reachability = copy.deepcopy(self.reachabilitymatrix)
        # we get the containers that have all the labels in the select set
        # we get the containers that have all the labels in the select set
        select_containers = set()
        first = True
        for select_label in obj.selector.concat_labels:
            matrix_ids = set()
            conts = self.containerTrie.find(select_label)
            if conts:
                matrix_ids.update(cont.matrix_id for cont in conts)
        
            if first and matrix_ids:
                first = False
                select_containers = matrix_ids
            else:
                select_containers = select_containers.intersection(matrix_ids)

        # we get the containers that have all the labels in the allow set
        allow_containers_final = set()
        for allow in obj.allow:
            allow_containers = set()
            first = True
            for allow_label in allow.concat_labels:
                matrix_ids = set()
                conts = self.containerTrie.find(allow_label)
                if conts:
                    matrix_ids.update(cont.matrix_id for cont in conts)
                if first and matrix_ids:
                    first = False
                    allow_containers = matrix_ids
                else:
                    allow_containers = allow_containers.intersection(matrix_ids)   
            allow_containers_final.update(allow_containers)


        
        # Now for each of the labels in these allow containers we find the existing NPs in the opposite direction
        if select_containers and allow_containers_final:
            opposite_policies = set()
            for container in allow_containers_final:
                for cont_label in self.matrixId_to_Container[container].concat_labels:
                    if obj.direction.direction:
                        # INGRESS -> we look at existing egress rules
                        trienode = self.eggressTrie.find(cont_label)
                        
                    else:
                        # EGRESS -> we look at existing ingress rules
                        trienode = self.ingressTrie.find(cont_label)
                    # we add all opposite policies to a set if there select labels match our containers labels
                    if trienode is not None:
                        for item in trienode:
                            if all(item_label in self.matrixId_to_Container[container].concat_labels for item_label in item.selector.concat_labels):
                                opposite_policies.add((item.id, container))

            # Now we check if the opposite policy allows the select containers from the original policy
            for (pol_id, allowed_cont) in opposite_policies:
                pol = self.reachabilitymatrix.dict_pols[pol_id]
                for container in select_containers:
                    for pol_allow in pol.allow:
                        if all(pol_label in self.matrixId_to_Container[container].concat_labels for pol_label in pol_allow.concat_labels):
                            # We have containers that can connect due to this policy. Lets remove the policy from their responsibe policies. 
                            # This is dependant on the type of the new policy as well
                            if obj.direction.direction:
                                # INGRESS
                                new_reachability.resp_policies.remove_item(self.matrixId_to_Container[allowed_cont].id, self.matrixId_to_Container[container].id, (obj.id, pol.id))
                                # Now we check the responsible policies again. If there still exist some the connection is maintained by other policies and thus nothing really changed.
                                # Otherwise the matrix needs updating.
                                if not new_reachability.resp_policies.get_items(self.matrixId_to_Container[allowed_cont].id, self.matrixId_to_Container[container].id):
                                    new_reachability.matrix[allowed_cont][container] = 0
                            else:
                                # EGRESS
                                new_reachability.resp_policies.remove_item(self.matrixId_to_Container[container].id, self.matrixId_to_Container[allowed_cont].id, (pol.id, obj.id))
                                # Now we check the responsible policies again. If there still exist some the connection is maintained by other policies and thus nothing really changed.
                                # Otherwise the matrix needs updating.      
                                if not new_reachability.resp_policies.get_items(self.matrixId_to_Container[container].id, self.matrixId_to_Container[allowed_cont].id):
                                    new_reachability.matrix[container][allowed_cont] = 0

        del new_reachability.dict_pols[obj.id]
        return new_reachability
    
    def reachabilityAddContainer(self, obj: Container):
        new_reachability = copy.deepcopy(self.reachabilitymatrix)
        # First add the container to the list and extend the matrix with a row and colum
        obj.matrix_id = copy.deepcopy(len(new_reachability.dict_pods))
        
        new_reachability.dict_pods[obj.id] = obj

        self.matrixId_to_Container[obj.matrix_id] = obj

        # We need this temporary container Trie to check for connections to itself as well. 
        cont_trie = copy.deepcopy(self.containerTrie)
        for label in obj.concat_labels:
           cont_trie.insert(label, obj)
        for row in new_reachability.matrix:
            row.append(0)
        new_reachability.matrix.append(bitarray('0' * len(new_reachability.dict_pods)))
        # Now lets find rules that are applied on this new container's labels and add them to matrix and other data structures
        # Create a set of all the Policies using the container's labels
        rules = set()
        for label in obj.concat_labels:
            egresses = self.eggressTrie.find(label)
            if egresses is not None:
                for pol in egresses:
                    # Add the policies to which the container does not match the entire select labels
                    if all(label2 in obj.concat_labels for label2 in pol.selector.concat_labels):
                        rules.add(pol.id)
            ingresses = self.ingressTrie.find(label)
            if ingresses is not None:
                for pol in ingresses:
                    # Add the policies to which the container does not match the entire select labels
                    if all(label2 in obj.concat_labels for label2 in pol.selector.concat_labels):
                        rules.add(pol.id)

        for id in rules:
            rule = new_reachability.dict_pols[id]
            # we get the containers that have all the labels in the rules allow sets
            allow_containers_final = set()
            for allow in rule.allow:
                allow_containers = set()
                first = True
                for allow_label in allow.concat_labels:
                    matrix_ids = set()
                    conts = cont_trie.find(allow_label)
                    if conts:
                        matrix_ids.update(cont.matrix_id for cont in conts)
                    if first and matrix_ids:
                        first = False
                        allow_containers = matrix_ids
                    else:
                        allow_containers = allow_containers.intersection(matrix_ids)
                allow_containers_final.update(allow_containers)

            # For these allowed containers we find policies in the opposite direction from this new container to our original
            for sec_cont_id in allow_containers_final:
                second_container = self.matrixId_to_Container[sec_cont_id]
                secondrules = set()
                for sec_label in second_container.concat_labels:
                    if rule.direction.direction:
                        # INGRESS
                        egresses2 = self.eggressTrie.find(sec_label)
                    else:
                        egresses2 = self.ingressTrie.find(sec_label)
                    if egresses2 is not None:
                        secondrules.update(pol2.id for pol2 in egresses2)
                
                for second_id in secondrules:
                    secondrule = new_reachability.dict_pols[second_id]
                    if all(label2 in second_container.concat_labels for label2 in secondrule.selector.concat_labels):
                        for a in secondrule.allow:
                            if all(label3 in obj.concat_labels for label3 in a.concat_labels):
                                # WE GOT A MATCH!
                                if rule.direction.direction:
                                    # INGRESS
                                    new_reachability.matrix[second_container.matrix_id][obj.matrix_id] = 1
                                    new_reachability.resp_policies.add_item(second_container.id, obj.id, (rule.id, secondrule.id))
                                else:
                                    # EGRESS
                                    new_reachability.matrix[obj.matrix_id][second_container.matrix_id] = 1
                                    new_reachability.resp_policies.add_item(obj.id, second_container.id, (secondrule.id, rule.id))
        return new_reachability
    
    def reachabilityDeleteContainer(self, obj: Container):
        new_reachability = copy.deepcopy(self.reachabilitymatrix)
        new_matrixId_to_Container = {}
        del new_reachability.dict_pods[obj.id]

        # Create a new all 0 matrix
        new_reachability.matrix = [bitarray('0' * len(new_reachability.dict_pods)) for _ in range(len(new_reachability.dict_pods))]
        

        for i, container in new_reachability.dict_pods.items():
            row = copy.deepcopy(self.reachabilitymatrix.matrix[container.matrix_id])
            row.pop(obj.matrix_id)

            if container.matrix_id > obj.matrix_id:
                container.matrix_id -= 1
            new_matrixId_to_Container[container.matrix_id] = container
            new_reachability.matrix[container.matrix_id] = row

            new_reachability.resp_policies.remove_all_for_ids(obj.id, container.id)
            new_reachability.resp_policies.remove_all_for_ids(container.id, obj.id)

        self.pods.remove
        for pod in self.pods:
            if pod.matrix_id > obj.matrix_id:
                pod.matrix_id -= 1

        return (new_reachability, new_matrixId_to_Container)
    
    def print_info(self, debug, verbose):
        if debug:
            print("# Container Trie:")
            print(f"# {self.containerTrie}\n")
            print("# Egress Trie:")
            print(f"# {self.eggressTrie}\n")
            print("# Ingress Trie:")
            print(f"# {self.ingressTrie}\n")

            print("# matrixIdtoContainer:")
            print(f"# {self.matrixId_to_Container}\n")
         
         
            print("# Policy Ids:")
            for i, pol in self.reachabilitymatrix.dict_pols.items():
                print(f"# {i}: {pol}\n#")

            print("#")
        if verbose:
            print("# Container Ids:")
            for i, pod in self.reachabilitymatrix.dict_pods.items():
                    print(f"# {i}: {pod.name}")
            print("#")    
            print("# Kano Matrix:")
            for row in range(len(self.reachabilitymatrix.dict_pods)):
                print(f"{self.reachabilitymatrix.matrix[row]}")
            print("#")

