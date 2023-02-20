'''import numpy as np
a1=[1,44,55],[2,33,66],[3,77,91]  
a2=[1,44,55],[2,45,66],[3,77,91] 

x = np.array(a1)
y = np.array(a2)
delta = x==y
print(delta)

values =[]
for i in delta:
    g =[int(x) for x in i]
    b = list(map(int, i))
    values.append(g)
print(values)'''

#-----------------------------
'''import numpy as np
m1 = [[0,  0,  0],
      [255,0,255],
      [0  ,0,  0]]

m2 = [[255,0,255],
      [0  ,0,  0],
      [255,0,255]]
    
m3 = [[-1,  -1,  -1],
      [-1,-1,-1],
      [-1  ,-1,  -1]]

for x in range(np.array(m1).shape[0]):
    for y in range(np.array(m1).shape[0]):
        if (m1[x][y] == m2[x][y]):
            m3[x][y] =0
        else:
            m3[x][y] =1
print(m3)'''
#----------------------------------
'''m1 = [[0,  0,  0],
      [255,0,255],
      [0  ,0,  0]]
m1 = np.array(m1)
m2 = [[255,0,255],
      [0  ,0,  0],
      [255,0,255]]
m2=np.array(m2)   
m3 = [[-1,  -1,  -1],
      [-1,-1,-1],
      [-1  ,-1,  -1]]
m3=np.array(m3)
for x in range(m1.shape[0]):
    for y in range(m1.shape[0]):
        if (m1[x][y] == m2[x][y]):
            m3[x][y] =0
        else:
            m3[x][y] =1
print(type(m3))

#padding
a = np.array([[ 1.,  1.,  1.,  1.,  1.],
               [ 1.,  1.,  1.,  1.,  1.],
               [ 1.,  1.,  1.,  1.,  1.]])
b=np.pad(a, [(0, 1), (0, 1)], mode='constant')
print(b)'''

'''from ipaddress import IPv4Network, IPv4Address
net = IPv4Network("192.4.2.0/24")
print(type(net))
net.num_addresses
net.netmask
netadd = IPv4Address("192.4.2.12") 
print(netadd in net)'''


from neutronclient.v2_0 import client as neutclient
from novaclient import client as novaclient
from credentials import get_nova_creds
from bitarray import bitarray
import numpy as np

creds = get_nova_creds()
nova = novaclient.Client(**creds)
neutron = neutclient.Client(**creds)

def exception_handler(func):
    def inner_function(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except Exception as e:
            print(type(e).__name__ + ": " + str(e))
    return inner_function

#@exception_handler
def connectivity():
    already_created_sgs = [] #all sg names in the project
    all_nodes = [] #all worker nodes in the project
    inst_sg_map=[] #sgs on each node
    for sg_items in neutron.list_security_groups()['security_groups']:
        already_created_sgs.append(sg_items['name'])
        for items in sg_items['security_group_rules']:
            all = '{}:{}'.format(items['direction'], items['security_group_id'])
            print(items)

    for instance in nova.servers.list():
        if instance.name == "master" or instance.name == "client":
            continue
        all_nodes.append(instance.name)
    all_nodes.sort() 

    for idx, items in enumerate(all_nodes):
        att_sg =[]
        remote_sgs=[]
        instance = nova.servers.find(name=items)

        for sg in instance.list_security_group():
            att_sg.append(sg.name)
            #att_sg.append(item.id) #looks like item and item.id return the same thing
            #print(item.name,item.id)
            for rulz in sg.rules:
                #D =(rulz['group'].get('name'))
                #print(D)
                try:
                    remote_sgs.append((rulz['group']['name']))
                except Exception:
                    continue
            
        inst_dic = {instance.name:{'sgs':att_sg, "remotesg":remote_sgs}}
        inst_sg_map.append(inst_dic)

    instance_matrix = [np.nan for _ in range(len(all_nodes))]
    vm_matrix = []
    
    test_mat= bitarray('11101111') #example for comparison purposes
    for i, ip in enumerate(inst_sg_map): 
        for k1, v1 in ip.items():   
            for j, dikts in enumerate(inst_sg_map):
                for k, v in dikts.items():
                    if k1 == k:
                        instance_matrix[j] =np.nan
                    else:
                        for itemz in v['remotesg']:
                            if '{}'.format(itemz) in v1['sgs']:
                                instance_matrix[j] =1
                                break
                            else:
                                instance_matrix[j] =0
                            #break 
        vm_matrix.append({k1:instance_matrix[:]})
        in_matrix = bitarray('0' * len(all_nodes)) 
        g=[]
        for idx, ins in enumerate(all_nodes):
            if instance_matrix[idx]:
                in_matrix[idx] =True
                              
            if in_matrix[idx] !=test_mat[idx]: #for comparison testing
                g.append([k1, in_matrix, test_mat, ins])
        #print(k1,in_matrix)
        #print(g)
    #print(vm_matrix) 

    '''n_max = max(len(x) for x in vm_matrix)
    n_min = min(len(x) for x in vm_matrix)
    if n_max ==n_min:
        n =n_max 
    n_ones = sum(l.count(1) for l in vm_matrix)   

    with open('out.py', 'w') as f:
        print('import numpy as np', file =f)
        print('nan = np.nan', file =f)
        print('m = {}'.format(vm_matrix), file=f)
    with open('tt.txt', 'w') as f1:
        print('==========================', file =f1)
        for items in vm_matrix:
            print(items, file=f1)
        print('==========================', file =f1)
        print(f"\nnumber of nodes = {n}\n \nsuccessful connections = {n_ones}\n", file =f1)
        connections = (n_ones/(n**2 - n))*100
        print(f"connectivity = {connections}%\n", file =f1)
        print("==========================\n", file =f1)'''

connectivity()
