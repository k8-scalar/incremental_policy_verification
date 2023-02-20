
from security_group.sgparser import ConfigParser
from security_group.sg_model import VMMatrix
from pprint import pprint


import unittest


class BasicTestSuite(unittest.TestCase):

    def test_reachability_matrix(self):
        cp = ConfigParser()
        sg, sg_per_node = cp.build_vm_matrix()

        vm_mat=VMMatrix.build_vm_matrix(sg, sg_per_node)
        pprint(vars(vm_mat))

if __name__ == '__main__':
    unittest.main()