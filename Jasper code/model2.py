from re import L
from typing import *
from dataclasses import dataclass, field
from bitarray import bitarray
from abc import abstractmethod

@dataclass
class Container:
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
class Policy:
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

        # Map to know which indexes refer to which policies and pods.
        # and map with all found labels.
        index_map = [] 
        for i, policy in enumerate(policies):
            index_map.append('{}:{}'.format(i,policy.name))
        for idx, cont_info in enumerate (containers):
            index_map.append('{}:{}'.format(idx,cont_info.name))
        for i, container in enumerate(containers):
            for key, value in container.labels.items():
                labelMap[key][i] = True
        print(f'index map: {index_map}\n' )
        print(f'label map: {list(labelMap)}\n' )

        for i, policy in enumerate(policies):
            # print(f'------------------------POLICY {policy.name}--------------------')
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

            # Now we put the in_matrix (Ingress) and out_matrix (Egress) together
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
                        in_matrix[idx] |= allow_set
                    else:
                        for i in range(n_container):
                            if allow_set[i]:
                                out_matrix[i] |= select_set
                    containers[idx].select_policies.append(i)

            # DEBUG PURPOSES    
            # print(f"Matrices after accounting for this policy:")
            # print(f"out_matrix: {out_matrix}")
            # print(f"in_matrix: {in_matrix}\n")


        # DEBUGGING PURPOSES
        # print("-------------------MAKING THE FINAL MATRIX---------------------------\n")
        # print(f"total out_matrix: {out_matrix}")
        # print(f"total in_matrix: {in_matrix}\n")


        # Time to create the final kano matrix.
        matrix = [bitarray('0' * n_container) for _ in range(n_container)]

        for i in range(n_container):
            for j in range(n_container): 
                matrix[i] = in_matrix[i] & out_matrix[i]
            #container accepting connections from itself
            if containers_talk_to_themselves:
                matrix[i][i] = True
            # These next 3 lines is for cleanly printing out the matrix.
            matrix[i]=matrix[i].to01()
            matrix[i]='[' + ' '.join(matrix[i]) + ']'
            print(matrix[i])

        return ReachabilityMatrix(n_container, n_policies, index_map,  matrix, build_transpose_matrix)

    def build_tranpose(self):
        self.transpose_matrix = [bitarray('0' * self.container_size) for _ in range(self.container_size)]
        for i in range(self.container_size):
            for j in range(self.container_size):
                self.transpose_matrix[i][j] = self.matrix[j][i]

    def __init__(self, container_size: int, policy_size: int, index_map,  matrix: Any, build_transpose_matrix=False) -> None:
        self.container_size = container_size
        self.policy_size = policy_size
        self.index_map=index_map
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
