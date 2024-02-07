
# Incremental policy verification
This repo contains the code for the thesis of Jasper Goris, submitted January 2024 for the obtaining of the degree of Master in Applied Computer Science at the KULeuven.

The algorithm will detect conflicts that arise due to misconfiguration between Kubernetes network policies and OpenStack security groups. For more information please refer to [the thesis itself](https://github.com/k8-scalar/incremental_policy_verification/blob/main/Jasper%20Files/Thesis/Thesis-Jasper-Goris-R0703236.pdf).


## Prerequisites

You must have a working Kubernetes cluster with direct access to a master/control-plane node. To install a cluster you can take a look at [the scripts provided by Eddy Truyen](https://github.com/k8-scalar/incremental_policy_verification/tree/main/Eddy%20Cluster%20scripts/Eddy%20scripts%20v2) 

The algorithm was developed with Python 3.10.12, which the master node must have installed. Other Python versions remain untested. 

clone the repository onto the master node:
 ```bash
  git clone git@github.com:k8-scalar/incremental_policy_verification.git
```   

In the main folder of the repository you can find the requirements.txt file which lists all the required libraries. Install these with the following command:

 ```bash
  pip install -r requirements.txt
```   
## Usage

To deploy the algorithm clone this repository onto a master node of your Kubernetes cluster, and within the "Jasper Code" folder execute the following command.

```bash
  python3 watcher.py $namespace$
```
with $namespace$ the already existing namespace you want to check for conflicting policies.

### Options
The algorithm offers some flags to be enabled

--verbose / -v  
&nbsp;&nbsp;&nbsp;&nbsp;allows for a more verbose output upon initialization and for each captured event, such as the previous and newly generated reachabilitymatrix

--debug / -d  
&nbsp;&nbsp;&nbsp;&nbsp; Prints out a lot of variables upon each captured event that is being handled, in order to help debugging

--startup / -s  
&nbsp;&nbsp;&nbsp;&nbsp; Starts a quick detection of conflicts upon startup  
&nbsp;&nbsp;&nbsp;&nbsp; PLEASE NOT THAT THIS IS EXPERIMENTAL AND UNTESTED







## Experiments
Within the master thesis we executed two experiments: 
- Experiment1 is a comparison between our incremental approach for updating the reachabilitymatrix and Kano's original generative method. 
- Experiment2 shows the time and memory consumption of the entire conflict detection algorithm. 
For more information we once again refer to [the thesis itself](https://github.com/k8-scalar/incremental_policy_verification/blob/main/Jasper%20Files/Thesis/Thesis-Jasper-Goris-R0703236.pdf).

### experiment execution
To execute the experiments you must checkout the corresponding branch. We will illustrate an example for experiment1:
 ```bash
  git checkout experiments-1
```   

You can go to the "Jasper code" directory and  execute the experiment1.py file with the following experiment variables in the described order:

- Number of runs: The number of executions in the experiment
- Number of pods: The number of pods to be deployed
- Number of policies: The number of network policies to be deployed
- namespace: The namespace in which the experiment will be executed. This namespace must already exist on the cluster.
- Key limit: The number of keys from which a network policy can choice to create its randomised label selector
- event type: The type of event that must be executed

Example:
 ```bash
  cd "Jasper code"
  python3 experiment1.py 100 50 20 test 2 addPod
```   

After the experiment the results will be stored in result.xlsx

