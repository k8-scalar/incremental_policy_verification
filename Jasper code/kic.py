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
        for select_label in obj.selector.concat_labels:
            matrix_ids = set()
            conts = self.containerTrie.find(select_label)
            if conts is None:
                select_containers = None
                break
            matrix_ids.update(cont.matrix_id for cont in conts)
            if not select_containers and conts:
                select_containers = matrix_ids
            else:
                select_containers = select_containers.intersection(matrix_ids)

        # we get the containers that have all the labels in the allow set
        allow_containers = set()
        for allow in obj.allow:
            for allow_label in allow.concat_labels:
                matrix_ids = set()
                conts = self.containerTrie.find(allow_label)
                if conts is None:
                    select_containers = None
                    break
                matrix_ids.update(cont.matrix_id for cont in conts)
                if not allow_containers and conts:
                    allow_containers = matrix_ids
                else:
                    allow_containers = allow_containers.intersection(matrix_ids)

        # Now for each of the labels in these allow containers we find the existing NPs in the opposite direction
        if select_containers is not None and allow_containers is not None:
            for container in allow_containers:
                for cont_label in self.matrixId_to_Container[container].concat_labels:
                    if obj.direction.direction:
                        # INGRESS -> we look at existing egress rules
                        trienode = self.eggressTrie.find(cont_label)
                    else:
                        # EGRESS -> we look at existing ingress rules
                        trienode = self.ingressTrie.find(cont_label)
                    # Now we get the allow of these opposite direction NPs and see if they match any of our select containers.
                    if trienode is not None and len(trienode) != 0:
                        for item in trienode:
                            if isinstance(item, Policy):
                                for allow in item.allow:
                                    for allowlabel in allow.concat_labels:
                                        cont_trie_allow = self.containerTrie.find(allowlabel)
                                        if cont_trie_allow is not None:
                                            for allow_cont in cont_trie_allow:
                                                if allow_cont.matrix_id in select_containers:
                                                    # We have containers that can connect. Lets change the new matrix to reflect this. 
                                                    # This is dependant on the type of the new policy as well
                                                    if obj.direction.direction:
                                                        # INGRESS
                                                        new_reachability.matrix[allow_cont.matrix_id][container] = 1
                                                        new_reachability.resp_policies.add_item(allow_cont.id, self.matrixId_to_Container[container].id, (len(new_reachability.dict_pols), item.id))
                                                    else:
                                                        # EGRESS
                                                        new_reachability.matrix[container][allow_cont.matrix_id] = 1
                                                        new_reachability.resp_policies.add_item(self.matrixId_to_Container[container].id, allow_cont.id, (item.id, len(new_reachability.dict_pols)))
        new_reachability.dict_pols[obj.id] = obj
        return new_reachability

    def reachabilityDeleteNP(self, obj: Policy):
        new_reachability = copy.deepcopy(self.reachabilitymatrix)
        # we get the containers that have all the labels in the select set
        select_containers = set()
        for select_label in obj.selector.concat_labels:
            matrix_ids = set()
            conts = self.containerTrie.find(select_label)
            if conts is None:
                select_containers = None
                break
            matrix_ids.update(cont.matrix_id for cont in conts)
            if not select_containers and conts:
                select_containers = matrix_ids
            else:
                select_containers = select_containers.intersection(matrix_ids)

        # we get the containers that have all the labels in the allow set
        allow_containers = set()
        for allow in obj.allow:
            for allow_label in allow.concat_labels:
                matrix_ids = set()
                conts = self.containerTrie.find(allow_label)
                if conts is None:
                    select_containers = None
                    break
                matrix_ids.update(cont.matrix_id for cont in conts)
                if not allow_containers and conts:
                    allow_containers = matrix_ids
                else:
                    allow_containers = allow_containers.intersection(matrix_ids)    

        if select_containers is not None and allow_containers is not None:

            for allow_matrix_id in allow_containers:
                for select_matrix_id in select_containers:
                # So for each container that is indicated by the policy's labels we look if the policy is within the responsible policies and delete it.
                    resp = self.reachabilitymatrix.resp_policies.get_items(self.matrixId_to_Container[allow_matrix_id].id, self.matrixId_to_Container[select_matrix_id].id)
                    for (index, index2) in resp:
                        if index == obj.id or index2 == obj.id:
                            new_reachability.resp_policies.remove_item(self.matrixId_to_Container[allow_matrix_id].id, self.matrixId_to_Container[select_matrix_id].id, (index, index2))
                    resp2 = self.reachabilitymatrix.resp_policies.get_items(self.matrixId_to_Container[select_matrix_id].id, self.matrixId_to_Container[allow_matrix_id].id)
                    for (index, index2) in resp2:
                        if index == obj.id or index2 == obj.id:
                            new_reachability.resp_policies.remove_item(self.matrixId_to_Container[select_matrix_id].id, self.matrixId_to_Container[allow_matrix_id].id, (index, index2))


                    # Now we check the responsible policies again. If there still exist some the connection is maintained by other policies and thus nothing really changed.
                    # Otherwise the matrix needs updating.
                    if not new_reachability.resp_policies.get_items(self.matrixId_to_Container[allow_matrix_id].id, self.matrixId_to_Container[select_matrix_id].id):
                        new_reachability.matrix[allow_matrix_id][select_matrix_id] = 0

                    if not new_reachability.resp_policies.get_items(self.matrixId_to_Container[select_matrix_id].id, self.matrixId_to_Container[allow_matrix_id].id):
                        new_reachability.matrix[select_matrix_id][allow_matrix_id] = 0

        del new_reachability.dict_pols[obj.id]                        
        return new_reachability
    
    def reachabilityAddContainer(self, obj: Container):
        new_reachability = copy.deepcopy(self.reachabilitymatrix)
        # First add the container to the list and extend the matrix with a row and colum
        obj.matrix_id = copy.deepcopy(len(new_reachability.dict_pods))
        new_reachability.dict_pods[obj.id] = obj

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
                rules.update(pol.id for pol in egresses)
            ingresses = self.ingressTrie.find(label)
            if ingresses is not None:
                rules.update(pol.id for pol in ingresses)

        # Remove the policies to which the container does not match the entire select labels
        for id in rules:
            rule = new_reachability.dict_pols[id]
            if not all(label in obj.concat_labels for label in rule.selector.concat_labels):
                rules.remove(id)
                break

        for id in rules:
            rule = self.reachabilitymatrix.dict_pols[id]
            for allow in rule.allow:
                opposites = set()
                for allowlabel in allow.concat_labels:
                    if rule.direction.direction:
                        # INGRESS
                        opegress = self.eggressTrie.find(allowlabel)
                        if opegress is not None:
                            opposites.update(op.id for op in opegress)
                    else:
                        # EGRESS
                        opingress = self.ingressTrie.find(allowlabel)
                        if opingress is not None:
                            opposites.update(op.id for op in opingress)
                for oppositeId in opposites:
                    opposite = self.reachabilitymatrix.dict_pols[oppositeId]
                    opposite_containers = set()
                    for opposite_selector_label in opposite.selector.concat_labels:
                        opposite_containers = cont_trie.find(opposite_selector_label)
                        if not opposite_containers is None:
                            for cont in opposite_containers:
                                if all(label in cont.concat_labels for label in  opposite.selector.concat_labels):
                                    if rule.direction.direction:
                                        # INGRESS
                                        new_reachability.matrix[cont.matrix_id][obj.matrix_id] = 1
                                        new_reachability.resp_policies.add_item(cont.id, obj.id, (id, oppositeId))  
                                    else:
                                        new_reachability.matrix[obj.matrix_id][cont.matrix_id] = 1
                                        new_reachability.resp_policies.add_item(obj.id, cont.id, (oppositeId, id)) 
        return new_reachability
    
    def reachabilityDeleteContainer(self, obj: Container):
        new_reachability = copy.deepcopy(self.reachabilitymatrix)
        new_matrixId_to_Container = {}
        # Create a new all 0 matrix
        del new_reachability.dict_pods[obj.id]

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

        return (new_reachability, new_matrixId_to_Container)
    
    def print_info(self, verbose):
        if verbose:
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
      
        print("# Container Ids:")
        for i, pod in self.reachabilitymatrix.dict_pods.items():
                print(f"# {i}: {pod.name}")
        print("#")    
        print("# Kano Matrix:")
        for row in range(len(self.reachabilitymatrix.dict_pods)):
            print(f"# {self.reachabilitymatrix.matrix[row]}")
        print("#")

