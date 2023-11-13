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

        # Check if all labels in the selector are present in the container
        for k, v in sl.items():
            if k not in cl or not self.matcher.match(sl[k], cl[k]):
                return False
        if all((sll_k, sll_v) in cl.items() for (sll_k, sll_v) in sl.items()):
            return True

        return False

    def allow_policy(self, container: Container) -> bool:
        cl = container.labels
     
        for allow_clause in self.working_allow:
            allow_clause_labels = allow_clause.labels
            if all((acl_k, acl_v) in cl.items() for (acl_k, acl_v) in allow_clause_labels.items()):
                return True
        
        return False

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
            check_self_ingress_traffic=False, 
            build_transpose_matrix=False):
        n_container = len(containers)
        n_policies = len(policies)

        labelMap: Dict[str, bitarray] = DefaultDict(lambda: bitarray('0' * n_container))

        in_matrix = [bitarray('0' * n_container) for _ in range(n_container)]
        out_matrix = [bitarray('0' * n_container) for _ in range(n_container)]
        have_seen = bitarray('1' * n_container)

        index_map = [] # Just to know which index to which pod
        for i, policy in enumerate(policies):
            index_map.append('{}:{}'.format(i,policy.name))
        for idx, cont_info in enumerate (containers):
            index_map.append('{}:{}'.format(idx,cont_info.name))
        for i, container in enumerate(containers):
            for key, value in container.labels.items():
                labelMap[f"{key}:{value}"][i] = True
                
        for i, policy in enumerate(policies):
            select_set = bitarray(n_container)
            select_set.setall(True)
            allow_set = bitarray(n_container)
            allow_set.setall(False)

            # read the labels and set the select and allow sets
            for k, v in policy.working_selector.labels.items():
                if f"{k}:{v}" in labelMap.keys(): #all key-values in containers
                     select_set &= labelMap[f"{k}:{v}"]
                else:
                    if not policy.working_selector.labels:
                        continue
                    select_set.setall(False)
                    break

            for allow_clause in policy.working_allow:
                selector_set = bitarray(n_container)
                selector_set.setall(True)

                for k, v in allow_clause.labels.items():
                    if f"{k}:{v}" in labelMap.keys():
                        selector_set &= labelMap[f"{k}:{v}"]
                    else:
                        if not allow_clause.labels:
                            continue
                        selector_set.setall(False)
                        break
                
                allow_set |= selector_set

            # dealing with not matched values (needs a customized predicate)
            for idx, cont_info in enumerate (containers):
                if select_set[idx] and not policy.select_policy(containers[idx]):
                    select_set[idx] = False

                if allow_set[idx] and not policy.allow_policy(containers[idx]):
                    allow_set[idx] = False

            
            policy.store_bcp(select_set, allow_set)

            for items in policy.working_allow:
                if items.is_allow_all:
                    allow_set.setall(True)
                elif items.is_deny_all:
                    allow_set.setall(False)

            if policy.working_selector.is_allow_all:
                select_set.setall(True)
            elif policy.working_selector.is_deny_all:
                select_set.setall(False)           

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
                        out_matrix[idx] |= allow_set
                    containers[idx].select_policies.append(i)
        new_in_matrix = [bitarray('0' * n_container) for _ in range(n_container)]
        for i in range(n_container):
            for j in range(n_container):
                new_in_matrix[i][j] = in_matrix[j][i]

        matrix = [bitarray('0' * n_container) for _ in range(n_container)]
        ##container accepting connections from itself??
        for i in range(n_container):
            if check_self_ingress_traffic:
                new_in_matrix[i][i] = True
            matrix[i] = new_in_matrix[i] & out_matrix[i]
            #matrix[i]=matrix[i].to01()
            #matrix[i]='[' + ' '.join(matrix[i]) + ']'
            # print(matrix[i])

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
