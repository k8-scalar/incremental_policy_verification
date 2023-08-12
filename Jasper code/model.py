from re import L
from typing import *
from dataclasses import dataclass, field
from bitarray import bitarray
from abc import abstractmethod

@dataclass
class Event:
    def __init__(self, name):
        self.name = name
        

@dataclass
class Container(Event):
    name: str
    labels: Dict[str, str]
    nodeName: str
    select_policies: List[int] = field(default_factory=list)
    allow_policies: List[int] = field(default_factory=list)

    def getValueOrDefault(self, key: str, value: str):
        if key in self.labels:
            return self.labels[key]
        return value

    def getLabels(self):
        return self.labels


@dataclass
class PolicySelect:
    labels: Dict[str, str]
    is_allow_all = False
    is_deny_all = False



@dataclass
class PolicyAllow:
    labels: Dict[str,str]
    is_allow_all = False
    is_deny_all = False


@dataclass
class PolicyDirection:
    direction: bool

    def is_ingress(self) -> bool:
        return self.direction

    def is_egress(self) -> bool:
        return not self.direction


PolicyIngress = PolicyDirection(True)
PolicyEgress = PolicyDirection(False)


@dataclass
class PolicyProtocol:
    protocols: List[str]

T = TypeVar('T')
class LabelRelation(Protocol[T]):
    @abstractmethod
    def match(self, rule: T, value: T) -> bool:
        raise NotImplementedError


class DefaultEqualityLabelRelation(LabelRelation):
    def match(self, rule: Any, value: Any) -> bool:
        return rule == value


@dataclass
class Policy(Event):
    name: str
    selector: PolicySelect
    allow: PolicyAllow
    direction: PolicyDirection
    protocol: PolicyProtocol
    ##port: PolicyPort
    cidr: Any
    matcher: LabelRelation[str] = DefaultEqualityLabelRelation()
    working_select_set: bitarray = None
    working_allow_set: bitarray = None

    @property
    def working_selector(self):
        if self.is_egress():
            return self.selector
        return self.selector

    @property
    def working_allow(self):
        if self.is_egress():
            return self.allow
        return self.allow

    def select_policy(self, container: Container) -> bool:
        cl = container.labels
        sl = self.working_selector.labels
        for k, v in cl.items():
            if k in sl.keys() and \
                not self.matcher.match(sl[k], v):
                return False
        return True


    def allow_policy(self, container: Container) -> bool:
        cl = container.labels
        for items in self.working_allow:
            al = items.labels
        for k, v in cl.items():
            if k in al.keys() and \
                not self.matcher.match(al[k], v):
                return False
        return True

    def is_ingress(self):
        return self.direction.is_ingress()

    def is_egress(self):
        return self.direction.is_egress()

    def store_bcp(self, select_set: bitarray, allow_set: bitarray):
        self.working_select_set = select_set
        self.working_allow_set = allow_set


# Used to store set of policies responsible for pod connectivity: Store[pod,pod] = policy
# and to store affectedVMConnection: Store(VM, VM) = (pod, pod)
class Store:
    def __init__(self):
        self.items = {}

    def add_item(self, id1, id2, item):
        key = (id1, id2)
        if key not in self.items:
            self.items[key] = [item]
        else:
            self.items[key].append(item)

    def get_items(self, id1, id2):
        key = (id1, id2)
        return self.items.get(key, [])

    def remove_item(self, id1, id2, item):
        key = (id1, id2)
        if key in self.items and item in self.items[key]:
            self.items[key].remove(item)
            if not self.items[key]:  # Remove the entry if the list becomes empty
                del self.items[key]

class ReachabilityMatrix:
    @staticmethod
    def build_matrix(containers: List[Container], policies: List[Policy], 
            containers_talk_to_themselves=False, 
            build_transpose_matrix=False):
        n_container = len(containers)
        n_policies = len(policies)

        labelMap: Dict[str, bitarray] = DefaultDict(lambda: bitarray('0' * n_container))

        in_matrix = [bitarray('0' * n_container) for _ in range(n_container)]
        out_matrix = [bitarray('0' * n_container) for _ in range(n_container)]
        have_seen = bitarray('0' * n_container)

        # Maps to know which indexes refer to which policies and pods.
        # and map with all found labels.
        index_map_pols = [] 
        index_map_pods = [] 

        for i, policy in enumerate(policies):
            index_map_pols.append('{}:{}'.format(i,policy.name))
        for idx, cont_info in enumerate (containers):
            index_map_pods.append('{}:{}'.format(idx,cont_info.name))
        for i, container in enumerate(containers):
            for key, value in container.labels.items():
                labelMap[key][i] = True

        # DEBUGGING PURPOSES
        # print(f'index map pods: {index_map_pods}' )
        # print(f'index map policies: {index_map_pols}' )
        # print(f'label map: {list(labelMap)}\n' )

        in_resp_policies = Store()
        out_resp_policies = Store()

        for i, policy in enumerate(policies):
            select_set = bitarray(n_container)
            select_set.setall(True)
            allow_set = bitarray(n_container)
            allow_set.setall(True)


            # read the labels and set the select and allow sets
            for k, v in policy.working_selector.labels.items():
                if k in labelMap.keys(): #all keys in containers
                    select_set &= labelMap[k]
                else:
                    if not policy.working_selector.labels:
                        continue
                    select_set.setall(False)

            for items in  policy.working_allow:
                for k, v in items.labels.items():
                    if k in labelMap.keys():
                        allow_set &= labelMap[k]

            # dealing with non-matched values (needs a customized predicate)
            for idx, cont_info in enumerate (containers):
                if select_set[idx] and not policy.select_policy(containers[idx]):
                    select_set[idx] = False

                if allow_set[idx] and not policy.allow_policy(containers[idx]):
                    allow_set[idx] = False

            # store the select and allow set in their working_set
            policy.store_bcp(select_set, allow_set)

            # Check for deny or allow all policies.
            for items in policy.working_allow:
                if items.is_allow_all:
                    allow_set.setall(True)
                elif items.is_deny_all:
                    allow_set.setall(False)

            if policy.working_selector.is_allow_all:
                select_set.setall(True)
            elif policy.working_selector.is_deny_all:
                select_set.setall(False)    

            # DEBUGGING PURPOSES
            # if(policy.direction.direction == False):
            #     print("Policy type = Egress")
            # else:
            #     print("Policy type = Ingress")
            # print(f"select set =  {select_set}")
            # print(f"allow set = {allow_set}\n")

            # Now we create the in_matrix (Ingress) and out_matrix (Egress)
            
            for idx in range(n_container):
                if allow_set[idx]:
                    if policy.is_ingress() and not have_seen[idx]:
                        out_matrix[idx].setall(False)
                        for j in range(n_container):
                            in_matrix[j][idx] = False
                        have_seen[idx] = True
                    containers[idx].allow_policies.append(i)
            for idx in range(n_container):
                if select_set[idx]:
                    if policy.is_egress() and not have_seen[idx]:
                        out_matrix[idx].setall(False)
                        for j in range(n_container):
                            in_matrix[j][idx] = False
                        have_seen[idx] = True
                        
                    if policy.is_ingress():   
                        # print(f"in_matrix before adding: {in_matrix}\n")

                        in_matrix[idx] |= allow_set
                        # print(f'ingress matrix adding idx: {in_matrix[idx]} \n idx: {idx} \n allow_set: {allow_set}')
                        # print(f"in_matrix after adding: {in_matrix}\n")
                        # print('*******************************************')
                        for index, value in enumerate(allow_set):
                            if value:
                                in_resp_policies.add_item(idx, index, i)

                    else:
                        # print(f"out_matrix before adding: {out_matrix}\n")

                        out_matrix[idx] |= allow_set
                        # print(f'egress matrix adding idx: {in_matrix[idx]}  \n idx: {idx} \n allow_set: {allow_set}')
                        # print(f"out_matrix after adding: {out_matrix}\n")
                        # print('*******************************************') 
                        for index, value in enumerate(allow_set):
                            if value:
                                out_resp_policies.add_item(idx, index, i)

                    containers[idx].select_policies.append(i)

            # DEBUG PURPOSES    
            # print(f"Matrices after accounting for this policy:")
            # print(f"out_matrix: {out_matrix}")
            # print(f"in_matrix: {in_matrix}\n")

        # DEBUG PURPOSES    
        # print("*******************************IN RESPONSIBLE POLICIES:*******************************")
        # for i in range(n_container):
        #     for j in range(n_container): 
        #         if in_resp_policies.get_items(i, j) != []:
        #             print(f'in_resp_policies for containers ({i}, {j}) = {in_resp_policies.get_items(i, j)}\n')

        # DEBUG PURPOSES    
        # print("*******************************OUT RESPONSIBLE POLICIES:*******************************")
        # for i in range(n_container):
        #     for j in range(n_container): 
        #         if out_resp_policies.get_items(i, j) != []:
        #             print(f'out_resp_policies for containers ({i}, {j}) = {out_resp_policies.get_items(i, j)}')   

        # DEBUGGING PURPOSES
        # print("-------------------MAKING THE FINAL MATRIX---------------------------\n")
        # print(f"total out_matrix: {out_matrix}")
        # print(f"total in_matrix: {in_matrix}\n")


        # Time to create the final kano matrix.

        matrix = [bitarray('0' * n_container) for _ in range(n_container)]
        final_resp_policies = Store()

        for i in range(n_container):
            for j in range(n_container): 
                if in_matrix[j][i] and out_matrix[i][j]:
                    matrix[i][j] = True
                    for k in range (len(in_resp_policies.get_items(j, i))):
                        final_resp_policies.add_item(i, j, in_resp_policies.get_items(j, i)[k])
                    for l in range (len(out_resp_policies.get_items(i, j))):
                        final_resp_policies.add_item(i, j, out_resp_policies.get_items(i, j)[l])
                
            #container accepting connections from itself
            if containers_talk_to_themselves:
                matrix[i][i] = True


            # These next 2 lines are for cleanly printing out the matrix BUT BREAKS DETECTION.PY DUE TO THE EXTRA SYMBOLS IN THE ARRAYS.
            # matrix[i]=matrix[i].to01()
            # matrix[i]='[' + ' '.join(matrix[i]) + ']'

            # DEBUGGING PURPOSES
            # print(matrix[i])
                  
        # DEBUGGING PURPOSES
        # for i in range(n_container):
        #     for j in range(n_container): 
        #         if final_resp_policies.get_items(i, j) != []:
        #             print(f'final responsible policies for containers ({i}, {j}) = {final_resp_policies.get_items(i, j)}')   

        return ReachabilityMatrix(n_container, n_policies, index_map_pods, index_map_pols, final_resp_policies,  matrix, build_transpose_matrix)

    def build_tranpose(self):
        self.transpose_matrix = [bitarray('0' * self.container_size) for _ in range(self.container_size)]
        for i in range(self.container_size):
            for j in range(self.container_size):
                self.transpose_matrix[i][j] = self.matrix[j][i]

    def __init__(self, container_size: int, policy_size: int, index_map_pods, index_map_pols, resp_policies,  matrix: Any, build_transpose_matrix=False) -> None:
        self.container_size = container_size
        self.policy_size = policy_size
        self.index_map_pods=index_map_pods
        self.index_map_pols=index_map_pols
        self.resp_policies=resp_policies
        self.matrix = matrix       
        self.transpose_matrix = None
        if build_transpose_matrix:
            self.build_tranpose()

    def __setitem__(self, key, value):
        self.matrix[key[0]][key[1]] = value
    
    def __getitem__(self, key):
        return self.matrix[key[0]][key[1]]

    def getrow(self, index):
        return self.matrix[index]

    def getcol(self, index):
        if self.transpose_matrix is not None:
            return self.transpose_matrix[index]
        value = bitarray(self.container_size)
        for i in range(self.container_size):
            value[i] = self.matrix[i][index]
        return value
