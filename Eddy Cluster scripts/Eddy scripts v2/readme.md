execute chmod 750 *.sh
edit the variables nodes and subnetmask in install_cluster.sh
execute ./run.sh
then follow the instructions to give user ubuntu also access rights to k8s cluster
then copy the outputted kubeadm join command into a safe place
then execute:

kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.25.0/manifests/tigera-operator.yaml
kubectl create -f custom-resources.yaml

then go to every worker node to execute the the copied kubeadm join command 
