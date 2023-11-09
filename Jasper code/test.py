import argparse
import random
from kubernetes import client, config
spec = {}
select = []
allow = []
policytypes = [{"Ingress", "from"}, {"Egress", "to"}]
type, tf =  random.choice(policytypes)

values = [
    "Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta", "Eta", "Theta",
    "Iota", "Kappa", "Lambda", "Mu", "Nu", "Xi", "Omicron", "Pi",
    "Rho", "Sigma", "Tau", "Upsilon", "Phi", "Chi", "Psi", "Omega"
]

keys = ["color", "env", "tier", "release", "name", "version", "component","zone","project","team","role",
        "service","region","customer","stack","cluster","owner","app_type"
    ]


nr_select = random.randint(1,3)
for _ in range(nr_select):
    num_select_labels = random.randint(1, 4)
    match_labels = {random.choice(keys): random.choice(values) for _ in range(num_select_labels)}

    pod_selector = {
        "podSelector": {
            "matchLabels": match_labels
        }
    }
    select.append(pod_selector)

nr_allow = random.randint(1,5)
for _ in range(nr_allow):
    num_allow_labels = random.randint(1, 4)
    match_labels = {random.choice(keys): random.choice(values) for _ in range(num_allow_labels)}

    pod_selector = {
        "podSelector": {
            "matchLabels": match_labels
        }
    }
    select.append(pod_selector)

spec = select
spec["policyTypes"] = [type]
spec[type.lower] = {tf: allow, "ports": [{"port": 80}] }

print(spec)