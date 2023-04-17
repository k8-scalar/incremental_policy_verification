#!/usr/bin/env python
import os

'''def get_keystone_creds():
    d = {}
    d['username'] = os.environ['OS_USERNAME']
    d['password'] = os.environ['OS_PASSWORD']
    d['auth_url'] = os.environ['OS_AUTH_URL']
    d['tenant_name'] = os.environ['OS_TENANT_NAME']
    return d
'''

def get_nova_creds():
    d = {}
    d['version'] = os.environ['OS_VERSION']
    d['username'] = os.environ['OS_USERNAME']
    d['password'] = os.environ['OS_PASSWORD']
    d['project_id'] = os.environ['OS_PROJECT_ID']
    d['auth_url'] = os.environ['OS_AUTH_URL']
    return d
