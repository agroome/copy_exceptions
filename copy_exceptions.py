import argparse
import requests
import os
import sys
import dotenv 
from pprint import pprint
from collections import defaultdict

dotenv.load_dotenv()
requests.packages.urllib3.disable_warnings()


parser = argparse.ArgumentParser()
parser.add_argument('-r', '--source-repository')
parser.add_argument('-t', '--target-repository')
parser.add_argument('-s', '--tsc-server', required=True, help='Tenable.sc hostname or ip address')
parser.add_argument('-p', '--tsc-port', default=443, help='Tenable.sc port')
args = parser.parse_args()

base_url = f'https://{args.tsc_server}:{args.tsc_port}/rest'

access_key = os.getenv('TSC_ACCESS_KEY')
secret_key = os.getenv('TSC_SECRET_KEY')

session = requests.Session()
session.headers = {
    'X-ApiKey': f'accessKey={access_key}; secretKey={secret_key}',
    'Accept': 'application/json'
}
session.verify = False

def get_repositories():
    response = session.get(f'{base_url}/repository')
    return {repo['name']: repo for repo in response.json()['response']}


def rule_to_tuple(rule):
    """convert rule dict to tuple 
    
       if this is as payload to be posted it will have 'repositories' instead of 'repository'
    """
    repository_id = rule['repository']['id'] if 'repository' in rule else rule['repositories'][0]['id']
    host_value = rule['hostValue'] if type(rule['hostValue']) is str else rule['hostValue']['id']

    if 'newSeverity' in rule:
        return (
            rule['plugin']['id'], rule['port'], rule['protocol'], rule['newSeverity'],
            rule['hostType'], host_value, repository_id
        )
    else:
        return (
            rule['plugin']['id'], rule['port'], rule['protocol'], rule['expires'], 
            rule['hostType'], host_value, repository_id
        )


def copy_accept_risk_rules(source_repo, target_repo):
    fields='%2C'.join([
        'name', 'plugin', 'hostValue', 'hostType', 'port', 'protocol', 'expires', 'repository', 'comments'
    ])
    resp = session.get(f'{base_url}/acceptRiskRule?fields={fields}')
    rules = resp.json()['response']

    # put rule tuples in a set so we can match duplicates
    rule_set = set()
    for rule in rules:
        rule_set.add(rule_to_tuple(rule))

    for rule in rules:
        payload = {
            'hostType': rule['hostType'], 
            'hostValue': rule['hostValue'], 
            'plugin': rule['plugin'], 
            'protocol': rule['protocol'], 
            'port': rule['port'], 
            'comments': "AUTO GENERATED: " + rule['comments'], 
            'repositories': [ target_repo ], 
            'expires': rule['expires']
        }

        # continue if not from correct source_repo
        if rule['repository']['id'] != source_repo['id']:
            continue

        # continue if rule already exists
        payload_tuple = rule_to_tuple(payload)
        if payload_tuple in rule_set:
            print(f'RULE ALREADY EXISTS id={rule["id"]}')
            continue

        print("ADDING RULE")
        pprint(payload)
        result = session.post(f'{base_url}/acceptRiskRule', json=payload)
        if not result.status_code == 200:
            sys.exit(f'{result.status_code}: {result.reason}')


def copy_recast_risk_rules(source_repo, target_repo):
    fields='%2C'.join([
        'name', 'plugin', 'hostValue', 'hostType', 'port', 'protocol', 'repository', 'comments', 'newSeverity'
    ])
    resp = session.get(f'{base_url}/recastRiskRule?fields={fields}')
    rules = resp.json()['response']

    # put rule tuples in a set so we can match duplicates
    rule_set = set()
    for rule in rules:
        rule_set.add(rule_to_tuple(rule))

    for rule in rules:
        payload = {
            'hostType': rule['hostType'], 
            'hostValue': rule['hostValue'], 
            'plugin': rule['plugin'], 
            'protocol': rule['protocol'], 
            'port': rule['port'], 
            'comments': "AUTO GENERATED: " + rule['comments'], 
            'repositories': [ target_repo ], 
            'newSeverity': rule['newSeverity']
        }

        # continue if not from correct source_repo
        if rule['repository']['id'] != source_repo['id']:
            print("not source repository, skipping")
            continue

        # continue if rule already exists
        payload_tuple = rule_to_tuple(payload)
        if payload_tuple in rule_set:
            print(f'RULE ALREADY EXISTS id={rule["id"]}')
            continue

        print("ADDING RULE")
        pprint(payload)
        result = session.post(f'{base_url}/recastRiskRule', json=payload)
        if not result.status_code == 200:
            sys.exit(f'{result.status_code}: {result.reason}')


repositories = get_repositories()
try:
    source_repository = repositories[args.source_repository]
except KeyError as e:
    sys.exit(f'repository not found: {args.source_repository}')

try:
    target_repository = repositories[args.target_repository]
except KeyError as e:
    sys.exit(f'repository not found: {args.target_repository}')

copy_accept_risk_rules(source_repository, target_repository)
# copy_recast_risk_rules(source_repository, target_repository)

