
from typing import *
from dataclasses import dataclass
from bitarray import bitarray

@dataclass
class sgspernode:
    nodename: str
    attachedsgs: List
    
@dataclass
class Rules:
    direction: str 
    ipProtocol: str
    portRange: Any
    remoteIP: Any
    remoteSG: str
    
@dataclass
class OpSG:
    sg_id: Any
    name: str
    sg_rules: Rules
    attachedTo: List

class VMMatrix:
    @staticmethod
    def build_vm_matrix(sgs:List[OpSG], nodes: List[sgspernode]):
        in_matrix = [bitarray('0' * len(nodes)) for _ in range(len(nodes))]
        out_matrix = [bitarray('0' * len(nodes)) for _ in range(len(nodes))]
        vm_matrix = [bitarray('0' * len(nodes)) for _ in range(len(nodes))]
        for i, vmi in enumerate(nodes):
            for atti in vmi.attachedsgs:
                for sgsi in sgs:
                    if sgsi.sg_id == atti:
                        for rulzi in sgsi.sg_rules:
                            for j,vmj in enumerate(nodes):
                                if i==j: #node does not isolate from itself
                                    in_matrix[i][j]=True
                                    out_matrix[i][j]=True
                                    vm_matrix[i][j]=True                                
                                for attj in vmj.attachedsgs:
                                    for sgsj in sgs:
                                        if sgsj.sg_id == attj:
                                            for rulzj in sgsj.sg_rules:
                                                if rulzi.portRange ==rulzi.portRange and rulzi.ipProtocol == rulzj.ipProtocol: #if both rules have same port range and protocol
                                                    if rulzi.remoteSG ==attj and rulzj.remoteSG == atti:                                                   
                                                        if rulzi.direction =="ingress" and rulzj.direction=="egress":
                                                            in_matrix[i][j]=True
                                                        if rulzi.direction =="egress" and rulzj.direction=="ingress":
                                                            out_matrix[i][j]=True  
                                                        vm_matrix[i][j] = in_matrix[i][j] & out_matrix[i][j]
                             
        return VMMatrix(in_matrix, out_matrix, vm_matrix)
    def __init__(self,ingress_matrix:Any, egress_matrix:Any, matrix: Any) -> None:
        self.matrix = matrix  
        self.ingress_matrix = ingress_matrix 
        self.egress_matrix = egress_matrix    
