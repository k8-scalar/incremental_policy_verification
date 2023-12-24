nodes="60 107 69 99 43 22 59"
subnetmask=172.23.1
for i in `echo $nodes`; do scp install_docker.sh install_kubeadm_worker.sh $subnetmask.$i:; ssh $subnetmask.$i 'chmod 700 *.sh; ./install_docker.sh; ./install_kubeadm_worker.sh'; done
sudo  kubeadm init --pod-network-cidr=194.168.0.0/16
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.25.0/manifests/tigera-operator.yaml
kubectl create -f custom-resources.yaml
