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
    

    def __init__(self):
        self.eggressTrie = LabelTrie()
        self.ingressTrie = LabelTrie()
        self.containerTrie = LabelTrie()
        self.reachabilitymatrix = ReachabilityMatrix()
        self.matrixId_to_Container = {}

    def insert_container(self, obj):
        if isinstance(obj, Container):
            for lab in obj.concat_labels:
                self.containerTrie.insert(lab, obj)
                self.matrixId_to_Container[obj.id] = obj
        else:
            raise ValueError("data is not a Container object")
        
    def delete_container(self, obj):
        if isinstance(obj, Container):
            for lab in obj.concat_labels:
                self.containerTrie.delete(lab, obj)
            del self.matrixId_to_Container[obj.id]
        else:
            raise ValueError("Data is not a Container object")

    # We store the selector labels, so we can e.g. search all ingress rules applied to a label
    def insert_policy(self, obj):
        if isinstance(obj, Policy):
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
        
    
    def generateKanoMatrix(self, containers, policies):
        self.reachabilitymatrix.build_matrix(containers, policies)

    def reachabilityAddNP(self, obj: Policy):
        new_reachability = copy.deepcopy(self.reachabilitymatrix)
        #we collect all the oposite policies that have use the new policy's allow as a select.
        for new_allow in obj.allow:
            for new_allow_label in new_allow.concat_labels:
                trienode = None
                if obj.direction.direction:
                    # INGRESS -> we look at existing egress rules
                    trienode = self.eggressTrie.find(new_allow_label)
                else:
                    # EGRESS -> we look at existing ingress rules
                    trienode = self.ingressTrie.find(new_allow_label)
                if trienode is not None and len(trienode) != 0:
                
                    # So we have the opposite diretion's policies that have the same selector, now let us look at their allow
                    for item in trienode:
                        if isinstance(item, Policy):
                            for allow in item.allow:
                                for allowlabel in allow.concat_labels:
                                    # So we look at all allow labels from the new policy and see if a match exists.
                                    for new_select in obj.selector.concat_labels:
                                        if allowlabel == new_select:

                                            # We got a match meaning we have an allowed connection by both an egress and ingress policy between specific labels.
                                            # Lets find the containers based on the labels

                                            cont_trie_select = self.containerTrie.find(new_select)
                                            cont_trie_allow = self.containerTrie.find(new_allow_label)

                                            if cont_trie_select is not None and cont_trie_allow is not None:
                                                # We got a connection between these containers!
                                                for select_cont in cont_trie_select:
                                                    for allow_cont in cont_trie_allow:

                                                        # We have containers that can connect. Lets change the new matrix to reflect this. 
                                                        # This is dependant on the type of the new policy as well
                                                        if obj.direction.direction:
                                                            new_reachability.matrix[allow_cont.matrix_id][select_cont.matrix_id] = 1
                                                            new_reachability.resp_policies.add_item(allow_cont.id, select_cont.id, (len(new_reachability.dict_pols), item.id))
                                                        else:
                                                            new_reachability.matrix[select_cont.matrix_id][allow_cont.matrix_id] = 1
                                                            new_reachability.resp_policies.add_item(select_cont.id, allow_cont.id, (item.id, len(new_reachability.dict_pols)))
        new_reachability.dict_pols[obj.id] = obj
        return new_reachability

    def reachabilityDeleteNP(self, obj: Policy):
        new_reachability = copy.deepcopy(self.reachabilitymatrix)
        for new_select in obj.selector.concat_labels:
            select_trienode = self.containerTrie.find(new_select)
            if not select_trienode is None:
                for new_allow in obj.allow:
                    for new_allow_label in new_allow.concat_labels:
                        allow_trienode = self.containerTrie.find(new_allow_label)
                        if not allow_trienode is None:
                            for allow_cont in allow_trienode:
                                for select_cont in select_trienode:
                                    # So for each container that is indicated by the policy's labels we look if the policy is within the responsible policies and delete it.
                                    resp = self.reachabilitymatrix.resp_policies.get_items(allow_cont.id, select_cont.id)
                                    for (index, index2) in resp:
                                        if index == obj.id or index2 == obj.id:
                                            new_reachability.resp_policies.remove_item(allow_cont.id, select_cont.id, (index, index2))
                                    resp2 = self.reachabilitymatrix.resp_policies.get_items(select_cont.id, allow_cont.id)
                                    for (index, index2) in resp2:
                                        if index == obj.id or index2 == obj.id:
                                            new_reachability.resp_policies.remove_item(select_cont.id, allow_cont.id, (index, index2))
                                    
                                    # Now we check the responsible policies again. If there still exist some the connection is maintained by other policies and thus nothing really changed.
                                    # Otherwise the matrix needs updating.
                                    resp3 = new_reachability.resp_policies.get_items(allow_cont.id, select_cont.id)
                                    if not resp3:
                                        new_reachability.matrix[allow_cont.matrix_id][select_cont.matrix_id] = 0

                                    resp4 = new_reachability.resp_policies.get_items(select_cont.id, allow_cont.id)
                                    if not resp4:
                                        new_reachability.matrix[select_cont.matrix_id][allow_cont.matrix_id] = 0

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
        for label in obj.concat_labels:
            egressrules = self.eggressTrie.find(label)
            ingressrules = self.ingressTrie.find(label)
            # First look at egress rules
            if egressrules is not None:
                for egressrule in egressrules:
                    for egressallow in egressrule.allow:
                        for egressallowlabel in egressallow.concat_labels:
                            # For all labels in the allow of our egress rule we search corresponding ingress rules with that label as selector
                            allowingressrules = self.ingressTrie.find(egressallowlabel)
                            if allowingressrules != []:
                                # Now we check in each of these ingress rules if one of its allow labels equals our original egress selector label
                                for allowingressrule in allowingressrules:
                                    for allowingressruleallow in allowingressrule.allow:
                                        for allowingressruleallowllabel in allowingressruleallow.concat_labels:
                                            if allowingressruleallowllabel == label:
                                                # We got a match! lets get the containers we connected to
                                                connected_cont = cont_trie.find(egressallowlabel)
                                                if not connected_cont is None:
                                                    for cont in connected_cont:
                                                        # And set the matrix and responsible policies
                                                        new_reachability.matrix[obj.matrix_id][cont.matrix_id] = 1
                                                        new_reachability.resp_policies.add_item(obj.id, cont.id, (allowingressrule.id, egressrule.id))
            # Now look at ingress rules
            if ingressrules is not None:
                for ingressrule in ingressrules:
                    for ingressallow in ingressrule.allow:
                        for ingressallowlabel in ingressallow.concat_labels:
                            # For all labels in the allow of our ingress rule we search corresponding egress rules with that label as selector
                            allowegressrules = self.eggressTrie.find(ingressallowlabel)
                            if allowegressrules != []:
                                # Now we check in each of these egress rules if one of its allow labels equals our original ingress selector label
                                for allowegressrule in allowegressrules:
                                    for allowegressruleallow in allowegressrule.allow:
                                        for allowegressruleallowlabel in allowegressruleallow.concat_labels:
                                            if allowegressruleallowlabel == label:
                                                # We got a match! lets get the containers we connected to
                                                connected_cont = cont_trie.find(ingressallowlabel)
                                                if not connected_cont is None:
                                                    for cont in connected_cont:
                                                        # And set the matrix and responsible policies
                                                        new_reachability.matrix[cont.matrix_id][obj.matrix_id] = 1
                                                        new_reachability.resp_policies.add_item(cont.id, obj.id, (ingressrule.id, allowegressrule.id))  
        return new_reachability
    
    def reachabilityDeleteContainer(self, obj: Container):
        new_reachability = copy.deepcopy(self.reachabilitymatrix)
        # Create a new all 0 matrix
        new_reachability.matrix = [bitarray('0' * len(new_reachability.dict_pods)) for _ in range(len(new_reachability.dict_pods))]
        del new_reachability.dict_pods[obj.id]

        for i, container in new_reachability.dict_pods.items():
            row = copy.deepcopy(self.reachabilitymatrix.matrix[container.matrix_id])
            row.pop(obj.matrix_id)

            if container.matrix_id > obj.matrix_id:
                container.matrix_id -= 1
            new_reachability.matrix[container.matrix_id] = row

            new_reachability.resp_policies.remove_all_for_ids(obj.id, container.id)
            new_reachability.resp_policies.remove_all_for_ids(container.id, obj.id)

        return new_reachability
    
    def print_info(self, verbose):
        if verbose:
            print("# Container Trie:")
            print(f"# {self.containerTrie}\n")
            print("# Egress Trie:")
            print(f"# {self.eggressTrie}\n")
            print("# Ingress Trie:")
            print(f"# {self.ingressTrie}\n")
            print("# Container Ids:")
            for i, pod in self.reachabilitymatrix.dict_pods.items():
                    print(f"# {i}: {pod}\n#")
            print("# Policy Ids:")
            for i, pol in self.reachabilitymatrix.dict_pols.items():
                print(f"# {i}: {pol}\n#")

            print("#")
        print("#")    
        print("# Kano Matrix:")
        for row in range(len(self.reachabilitymatrix.dict_pods)):
            print(f"# {self.reachabilitymatrix.matrix[row]}")
        print("#")

