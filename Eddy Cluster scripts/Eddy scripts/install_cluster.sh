nodes="26 79 123 97 52"
for i in `echo $nodes`; do scp -i .ssh/756245.pem install_docker.sh install_kubeadm_worker.sh 172.23.3.$i:; ssh -i .ssh/756245.pem 172.23.3.$i 'chmod 700 *.sh; ./install_docker.sh; ./install_kubeadm_worker.sh'; done
sudo  kubeadm init --pod-cird-network=194.168.0.0/16
for i in `echo $nodes`; do scp -i .ssh/756245.pem preinstall_weave.sh 172.23.3.$i:; ssh -i .ssh/756245.pem 172.23.3.$i 'chmod 700 *.sh; ./preinstall_weave.sh'; done
kubectl apply -f weave-daemonset-k8s.yaml
