from model import ReachabilityMatrix
from algorithm import *
from parser import ConfigParser
from pprint import pprint



def test_reachability_matrix():
    cp = ConfigParser('current-cluster-objects/')
    containers, policies = cp.parse() 
    matrix = ReachabilityMatrix.build_matrix(containers, policies)# ,containers_talk_to_themselves=False, build_transpose_matrix=True)
    print("=====================================================================================")
    pprint (vars(matrix), sort_dicts=False)
    print("=====================================================================================")
    pprint (containers)
    print("=====================================================================================")
    pprint(policies)
    

if __name__ == '__main__':
    test_reachability_matrix()
