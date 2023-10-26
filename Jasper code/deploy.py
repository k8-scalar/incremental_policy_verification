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

distinct_colors_100 = [
    "red", "green", "blue", "yellow", "orange", "purple", "pink", "brown", "cyan", "teal",
    "magenta", "gray", "lime", "olive", "maroon", "navy", "indigo", "violet", "turquoise", "beige",
    "lavender", "salmon", "plum", "gold", "peach", "tan", "ivory", "rose", "aqua", "mint",
    "black", "white", "silver", "cream", "darkred", "darkgreen", "darkblue", "darkyellow", "darkorange", "darkpurple",
    "darkpink", "darkbrown", "darkcyan", "darkteal", "darkmagenta", "darkgray", "darklime", "darkolive", "darkmaroon", "darknavy", "darkindigo",
    "darkviolet", "darkturquoise", "darkbeige", "darklavender", "darksalmon", "darkplum", "darkgold", "darkpeach", "darktan", "darkivory",
    "darkrose", "darkaqua", "darkmint", "lightred", "lightgreen", "lightblue", "lightyellow", "lightorange", "lightpurple", "lightpink", "lightbrown",
    "lightcyan", "lightteal", "lightmagenta", "lightgray", "lightlime", "lightolive", "lightmaroon", "lightnavy", "lightindigo", "lightviolet", "lightturquoise",
    "lightbeige", "lightlavender", "lightsalmon", "lightplum", "lightgold", "lightpeach", "lighttan", "lightivory", "lightrose", "lightaqua", "lightmint",
    "darkbluegray", "lightcoral", "darkkhaki", "lightslategray", "darkorchid", "lightsteelblue"
]

distinct_key_values_100 = ["key" + str(i) for i in range(1, 101)]

print("\n------------PODS-------------")
for i in range(int(args.nr_of_pods)):

    pod_manifest = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {
        "name": f"pod-{i}", 
        "namespace": "test",
        "labels": 
            {
                random.choice(distinct_key_values_100): random.choice(distinct_colors_100)
            }
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

policytypes = [{"Ingress", "from"}, {"Egress", "to"}]
print("\n------------POLICIES-------------")
for j in range(int(args.nr_of_policies)):
    type, tf =  random.choice(policytypes)
    network_policy_manifest = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"policy-{j}",
            "namespace": "test",
        },
        "spec": {
            "podSelector": {
                "matchLabels": {
                    random.choice(distinct_key_values_100): random.choice(distinct_colors_100),
                }
            },
            "policyTypes": [type],
            type.lower(): [
                {
                    tf: [
                        {
                            "podSelector": {
                                "matchLabels": {
                                    random.choice(distinct_key_values_100): random.choice(distinct_colors_100)
                                }
                            }
                        }
                    ],
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