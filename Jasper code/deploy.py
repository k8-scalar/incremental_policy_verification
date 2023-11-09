import argparse
import random
from kubernetes import client, config

config.load_kube_config()
pod_api_instance = client.CoreV1Api()
np_api_instance = client.NetworkingV1Api()

parser = argparse.ArgumentParser()
parser.add_argument("nr_of_pods")
parser.add_argument("nr_of_policies")
args = parser.parse_args()

values = [
    "Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta", "Eta", "Theta",
    "Iota", "Kappa", "Lambda", "Mu", "Nu", "Xi", "Omicron", "Pi",
    "Rho", "Sigma", "Tau", "Upsilon", "Phi", "Chi", "Psi", "Omega"
]

keys = ["color", "env", "tier", "release", "name", "version", "component","zone","project","team","role",
        "service","region","customer","stack","cluster","owner","app_type"
    ]

policytypes = [("Ingress", "from"), ("Egress", "to")]



print("\n------------POLICIES-------------")
for j in range(int(args.nr_of_policies)):

    nr_select = random.randint(1,3)
    for _ in range(nr_select):
        num_select_labels = random.randint(1, 4)
        match_labels = {random.choice(keys): random.choice(values) for _ in range(num_select_labels)}

        selector = {
            "matchLabels": match_labels
        }

    nr_allow = random.randint(1,5)
    for _ in range(nr_allow):
        num_allow_labels = random.randint(1, 4)
        match_labels = {random.choice(keys): random.choice(values) for _ in range(num_allow_labels)}

        allow = []
        for _ in range(nr_allow):
            allow.append({"podSelector": {"matchLabels": {random.choice(keys): random.choice(values) for _ in range(num_allow_labels)}}})
        


    (type, tf) =  random.choice(policytypes)
    network_policy_manifest = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"policy-{j}",
            "namespace": "test",
        },
        "spec": {
            "podSelector" : selector,
            "policyTypes": [type],
            type.lower(): [
                {
                    tf: allow,
                    "ports": [{"port": 80}]
                }
            ]
        }
    }

    try:
        api_response = np_api_instance.create_namespaced_network_policy(body=network_policy_manifest, namespace="test")
        print(f"policy-{j} created successfully.")
    except client.exceptions.ApiException as e:
        print(f"Error creating policy-{j}: {e}")

print("\n------------PODS-------------")
for i in range(int(args.nr_of_pods)):

    labels = {}
    amount = random.randint(1,5)
    for p in range(amount):
        key = random.choice(keys)
        value = random.choice(values)
        labels[key] = value


    pod_manifest = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {
        "name": f"pod-{i}", 
        "namespace": "test",
        "labels": 
            labels
        },
    "spec": {
        "containers": [
            {
                "name": "nginx",
                "image": "nginx:latest",
                "ports": [{"containerPort": 80}]
            }
        ]
        }
    }
    try:
        api_response = pod_api_instance.create_namespaced_pod(body=pod_manifest, namespace="test")
        print(f"Pod-{i} created")
    except client.exceptions.ApiException as e:
        print(f"Error creating pod-{i}: {e}")




