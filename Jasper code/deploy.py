import argparse
import random
from kubernetes import client, config
import time

config.load_kube_config()

def deploy(podsnr, policiesnr, ns, key_limit):
    pod_api_instance = client.CoreV1Api()
    np_api_instance = client.NetworkingV1Api()
    values = [
    "Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta", "Eta", "Theta",
    "Iota", "Kappa", "Lambda", "Mu", "Nu", "Xi", "Omicron", "Pi",
    "Rho", "Sigma", "Tau", "Upsilon", "Phi", "Chi", "Psi", "Omega",
    "AlphaPrime", "BetaPrime", "GammaPrime", "DeltaPrime", "EpsilonPrime", "ZetaPrime"
]


    # CONSTANT: value limit 10
    shortened_values = values[:10]

    keys = [
    "color", "env", "tier", "release", "name", "version", "component", "zone", "project", "team", "role",
    "service", "region", "customer", "stack", "cluster", "owner", "app_type",
    "app", "namespace", "label_selector", "pod_selector", "ingress", "egress",
    "protocol", "port", "target_port", "source_ip", "destination_ip",
    "ingress_policy", "egress_policy", "priority", "pod_type", "api_version",
    "kind", "container_name", "port_name", "host_network", "host_pid",
    "host_ipc", "privileged", "app_id", "subnet", "ingress_pod", "egress_pod",
    "max_connections", "max_connections_per_source", "policy_type", "egress_rule",
    "ingress_rule", "pod_security_policy", "egress_group", "ingress_group",
    "group", "namespace_selector", "ingress_api_version", "egress_api_version",
    "labels", "annotations", "app_protocol", "egress_pod_selector",
    "ingress_pod_selector", "egress_pod_labels", "ingress_pod_labels",
    "egress_pod_annotations", "ingress_pod_annotations",
    "allowed_ports", "disallowed_ports", "destination_selector",
    "source_selector", "port_range", "dns_policy", "target_selector",
    "target_labels", "target_annotations", "source_labels", "source_annotations",
    "selector_labels", "selector_annotations", "pod_affinity", "pod_anti_affinity",
    ]

    
    # VARIABLE KEY LIMIT
    shortened_keys = keys[:key_limit]
    policytypes = [("Ingress", "from"), ("Egress", "to")]


    if policiesnr != 0:
        print("\n------------CREATING POLICIES-------------")
        nrofexistingpolicies = len(np_api_instance.list_namespaced_network_policy(ns).items)
        for j in range(nrofexistingpolicies, (nrofexistingpolicies + policiesnr)):

            # CONSTANT: selects limit 1
            nr_select = random.randint(1,1)
            for _ in range(nr_select):
                # CONSTANT: select label limit 3
                num_select_labels = random.randint(1, 3)
                match_labels = {random.choice(shortened_keys): random.choice(shortened_values) for _ in range(num_select_labels)}

                selector = {
                    "matchLabels": match_labels
                }
            # CONSTANT: allows limit 3
            nr_allow = random.randint(3,3)
            for _ in range(nr_allow):
                # CONSTANT: allow label limit 3
                num_allow_labels = random.randint(1, 3)
                match_labels = {random.choice(shortened_keys): random.choice(shortened_values) for _ in range(num_allow_labels)}

                allow = []
                for _ in range(nr_allow):
                    allow.append({"podSelector": {"matchLabels": {random.choice(shortened_keys): random.choice(shortened_values) for _ in range(num_allow_labels)}}})
                


            (type, tf) =  random.choice(policytypes)
            network_policy_manifest = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": f"policy-{j}",
                    "namespace": ns,
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
            retries = 0
            while retries < 8:
                try:
                    np_api_instance.create_namespaced_network_policy(body=network_policy_manifest, namespace=ns)
                    retries = 10
                except client.exceptions.ApiException as e:
                    if "object is being deleted" in str(e):
                        time.sleep(2)    
                        retries += 1
                    else:
                        print(f"Error creating policy-{j}: {e}")
                        retries = 10
        print(f"{policiesnr} policies created")
    if podsnr != 0:
        print("\n------------CREATING PODS-------------")
        nrofexistingpods = len(pod_api_instance.list_namespaced_pod(ns).items)
        for i in range(nrofexistingpods, (nrofexistingpods + podsnr)):

            labels = {}
            # CONSTANT: max 5 pod labels
            amount = random.randint(1,5)
            for p in range(amount):
                key = random.choice(shortened_keys)
                value = random.choice(shortened_values)
                labels[key] = value


            pod_manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": f"pod-{i}", 
                "namespace": ns,
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
            retries = 0
            while retries < 8:
                try:
                    pod_api_instance.create_namespaced_pod(body=pod_manifest, namespace=ns)
                    retries = 10
                except client.exceptions.ApiException as e:
                    if "object is being deleted" in str(e):
                        time.sleep(2)    
                        retries += 1
                    else:
                        print(f"Error creating pod-{j}: {e}")
                        retries = 10
        print(f"{podsnr} pods created")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("nr_of_pods", type=int)
    parser.add_argument("nr_of_policies", type=int)
    parser.add_argument("namespace", type=str)
    parser.add_argument("key_limit", type=int)
    args = parser.parse_args()
    deploy(args.nr_of_pods, args.nr_of_policies, args.namespace, args.key_limit)

   
