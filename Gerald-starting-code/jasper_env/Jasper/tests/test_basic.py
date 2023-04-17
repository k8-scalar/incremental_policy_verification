from kano.model import ReachabilityMatrix
from kano.algorithm import *
from generate import ConfigFiles
from kano.parser import ConfigParser
from pprint import pprint

import unittest


class BasicTestSuite(unittest.TestCase):

    def test_reachability_matrix(self):
        config = ConfigFiles()
        config.generateConfigFiles()

        cp = ConfigParser('data/')
        containers, policies = cp.parse() 
        containers = config.getPods()

        matrix = ReachabilityMatrix.build_matrix(containers, policies)#, build_transpose_matrix=True)
        print("=====================================================================================")
        pprint (vars(matrix), sort_dicts=False)
        print("=====================================================================================")
        pprint (containers)
        print("=====================================================================================")
        pprint(policies)
        

if __name__ == '__main__':
    unittest.main()
