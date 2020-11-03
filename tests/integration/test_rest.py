import pytest
import random
import yaml
from fastapi.testclient import TestClient

from tests.conftest import cli_commands
from tests import conftest
from suzieq.server.restServer import app, get_configured_api_key, API_KEY_NAME

ENDPOINT = "http://localhost:8000/api/v1"

VERBS = ['show', 'summarize', 'assert', 'lpm',
         'unique']  # add 'top' when it's supported
FILTERS = ['', 'hostname=leaf01', 'namespace=ospf-ibgp',
           'hostname=leaf01%20spine01',
           'namespace=ospf-ibgp%20ospf-single',
           'address=10.127.1.2',
           'dest=172.16.2.104&src=172.16.1.101&namespace=ospf-ibgp',
           'columns=namespace',
           'view=latest',
           'address=10.127.1.2&view=all',
           'ipAddress=10.127.1.2',
           'vrf=default',
           'ipvers=v4',
           'macaddr=22:5c:65:2f:98:b6',
           'macaddr=52:54:00:b0:9c:c9%2052:54:00:f5:3a:a9',
           'peer=eth1.2',
           'vni=13',
           'vni=13%2024',
           'mountPoint=/',
           'ifname=swp1',
           'type=ethernet',
           'vlan=13',
           'remoteVtepIp=10.0.0.101',
           'bd=',
           'state=pass',
           'oif=eth1.4',
           'localOnly=True',
           'prefix=10.0.0.101/32',
           'protocol=bgp',
           'prefixlen=24',
           'service=device',
           'polled-neighbor=True',
           'usedPercent=8'
           ]

# these should only succeed for the specific service/verb tuples
GOOD_FILTERS_FOR_SERVICE_VERB = {
    'address=10.127.1.2': ['route/lpm'],
    'address=10.127.1.2&view=all': ['route/lpm'],
    'bd=': ['mac/show'],
    'dest=172.16.2.104&src=172.16.1.101&namespace=ospf-ibgp':
    ['path/show', 'path/summarize'],
    'ifname=swp1': ['interface/show', 'interface/assert',
                    'lldp/show', 'ospf/show', 'ospf/assert'],
    'ipAddress=10.127.1.2': ['arpnd/show'],
    'ipvers=v4': ['address/show'],
    'localOnly=True': ['mac/show'],
    'macaddr=22:5c:65:2f:98:b6': ['arpnd/show', 'mac/show'],
    'mountPoint=/': ['fs/show'],
    'oif=eth1.4': ['arpnd/show'],
    'peer=eth1.2': ['bgp/show'],
    'polled_neighbor=True': ['topology/show', 'topology/summarize'],
    'prefix=10.0.0.101/32': ['route/show'],
    'prefixlen=24': ['route/show'],
    'protocol=bgp%20ospf': ['route/show'],
    'service=device': ['sqPoller'],
    'remoteVtepIp=10.0.0.101': ['mac/show'],
    'state=up': ['interface/show'],
    'state=Established': ['bgp/show'],
    'state=NotEstd': ['bgp/show'],
    'state=all': ['ospf/show'],
    'state=full': ['ospf/show'],
    'state=other': ['ospf/show'],
    'state=passive': ['ospf/show'],
    'type=ethernet': ['interface/show'],
    'usedPercent=8': ['fs/show'],
    'vlan=13': ['mac/show', 'vlan/show'],
    'vni=13': ['evpnVni/show'],
    'vni=13%2024': ['evpnVni/show'],
    'vrf=default': ['address/show', 'bgp/show', 'bgp/assert',
                    'ospf/assert', 'ospf/show',
                    'route/show', 'route/summarize', 'topology/show',
                    ]
}

GOOD_VERB_FILTERS = {
    'unique': ['columns=namespace'],
}

GOOD_SERVICE_VERB_FILTER = {
    'path/show': ['dest=172.16.2.104&src=172.16.1.101&namespace=ospf-ibgp'],
    'path/summarize': ['dest=172.16.2.104&src=172.16.1.101&namespace=ospf-ibgp'],
    'route/lpm': ['address=10.127.1.2', 'address=10.127.1.2&view=all'],

}


# these service/verb pairs should return errors
BAD_VERBS = {'address/assert': 422, 'address/lpm': 422,
             'arpnd/assert': 422, 'arpnd/lpm': 422,
             'bgp/lpm': 422,
             'device/assert': 422, 'device/lpm': 422,
             'evpnVni/lpm': 422,
             'fs/assert': 422, 'fs/lpm': 422,
             'interface/lpm': 422,
             'lldp/assert': 422, 'lldp/lpm': 422,
             'mac/assert': 422, 'mac/lpm': 422,
             'mlag/assert': 422, 'mlag/lpm': 422,
             'ospf/lpm': 422,
             'path/assert': 422, 'path/unique': 422,
             'path/lpm': 422,
             'sqpoller/assert': 422, 'sqpoller/lpm': 422,
             'route/assert': 422,
             'topology/assert': 422,
             'topology/lpm': 422,
             'topology/unique': 422,
             'vlan/assert': 422, 'vlan/lpm': 422,
             }

# these are always bad filters for these verbs no matter the service
BAD_VERB_FILTERS = {'assert?address=10.0.0.1': 405,
                    'summarize?columns=namespace': 405,
                    'summarize?hostname=leaf01': 405,
                    'summarize?hostname=leaf01%20spine01': 405,
                    'unique?': 405,
                    'unique?hostname=leaf01': 405,
                    'unique?hostname=leaf01%20spine01': 405,
                    'unique?namespace=ospf-ibgp': 405,
                    'unique?view=latest': 405,
                    }

# these service/verb/filter tuples should return errors
#  because they are invalid filters for the service/verb combos
BAD_FILTERS = {
    'address/summarize?address=10.127.1.2': 405,
    'address/summarize?address=10.127.1.2&view=all': 405,
    'address/summarize?ipvers=v4': 405,
    'address/summarize?vrf=default': 405,
    'arpnd/summarize?macaddr=22:5c:65:2f:98:b6': 405,
    'arpnd/summarize?macaddr=52:54:00:b0:9c:c9%2052:54:00:f5:3a:a9': 405,
    'arpnd/summarize?ipAddress=10.127.1.2': 405,
    'arpnd/summarize?oif=eth1.4': 405,
    'bgp/show?state=pass': 405,
    'bgp/assert?peer=eth1.2': 405,
    'bgp/assert?state=pass': 405,
    'bgp/summarize?peer=eth1.2': 405,
    'bgp/summarize?state=pass': 405,
    'bgp/summarize?state=Established': 405,
    'bgp/summarize?state=NotEstd': 405,
    'bgp/summarize?vrf=default': 405,
    'evpnVni/assert?vni=13': 405,
    'evpnVni/assert?vni=13%2024': 405,
    'evpnVni/summarize?vni=13': 405,
    'evpnVni/summarize?vni=13%2024': 405,
    'fs/summarize?usedPercent=8': 405,
    'fs/summarize?mountPoint=/': 405,
    'interface/show?state=pass': 405,
    'interface/assert?type=ethernet': 405,
    'interface/assert?state=pass': 405,
    'interface/summarize?ifname=swp1': 405,
    'interface/summarize?state=pass': 405,
    'interface/summarize?type=ethernet': 405,
    'lldp/summarize?ifname=swp1': 405,
    'mac/summarize?bd=': 405,
    'mac/summarize?macaddr=22:5c:65:2f:98:b6': 405,
    'mac/summarize?macaddr=52:54:00:b0:9c:c9%2052:54:00:f5:3a:a9': 405,
    'mac/summarize?localOnly=True': 405,
    'mac/summarize?remoteVtepIp=10.0.0.101': 405,
    'mac/summarize?vlan=13': 405,
    'ospf/assert?hostname=leaf01': 405,
    'ospf/assert?hostname=leaf01%20spine01': 405,
    'ospf/assert?state=pass': 405,
    'ospf/assert?ifname=swp1': 405,
    'ospf/summarize?ifname=swp1': 405,
    'ospf/summarize?state=pass': 405,
    'ospf/summarize?vrf=default': 405,
    'ospf/show?state=pass': 405,
    'path/summarize?hostname=leaf01': 404,
    'path/summarize?hostname=leaf01%20spine01': 404,
    'path/summarize?columns=namespace': 404,

    'path/unique?columns=namespace': 404,
    'route/lpm?': 404,
    'route/lpm?columns=namespace': 404,
    'route/lpm?hostname=leaf01': 404,
    'route/lpm?namespace=ospf-ibgp': 404,
    'route/summarize?address=10.127.1.2': 405,
    'route/summarize?address=10.127.1.2&view=all': 405,
    'route/summarize?ipvers=v4': 405,
    'route/summarize?prefix=10.0.0.101/32': 405,
    'route/summarize?prefixlen=24': 405,
    'route/summarize?protocol=bgp': 405,
    'route/show?ipvers=v4': 405,
    'route/lpm?view=latest': 404,
    'sqpoller/summarize?service=device': 405,
    'vlan/show?state=pass': 405,
    'vlan/summarize?vlan=13': 405,
    'vlan/summarize?state=pass': 405,
}


def get(endpoint, service, verb, args):
    api_key = get_configured_api_key()
    #url = f"{endpoint}/{service}/{verb}?access_token={api_key}&{args}"
    url = f"{endpoint}/{service}/{verb}?{args}"

    client = TestClient(app)
    response = client.get(url, headers={API_KEY_NAME: api_key})

    c_v = f"{service}/{verb}"
    c_v_f = f"{c_v}?{args}"
    v_f = f"{verb}?{args}"
    if response.status_code != 200:
        if c_v in BAD_VERBS:
            assert BAD_VERBS[c_v] == response.status_code, response.content.decode(
                'utf8')
        elif c_v_f in BAD_FILTERS:
            assert BAD_FILTERS[c_v_f] == response.status_code, response.content.decode(
                'utf8')
        elif v_f in BAD_VERB_FILTERS:
            assert BAD_VERB_FILTERS[v_f] == response.status_code, response.content.decode(
                'utf8')
        # elif args in GOOD_FILTERS_FOR_SERVICE_VERB:

        #      assert c_v not in GOOD_FILTERS_FOR_SERVICE_VERB[args]
        #      assert response.status_code == 405 or response.status_code == 404
        elif verb in GOOD_VERB_FILTERS:
            assert args not in GOOD_VERB_FILTERS[verb]
        elif c_v in GOOD_SERVICE_VERB_FILTER:
            assert args not in GOOD_SERVICE_VERB_FILTER[c_v]
        else:
            print(
                f" RESPONSE {response.status_code} {response.content.decode('utf8')}")
            response.raise_for_status()
    else: # you've gotten a 200, need to make sure that's what we expect
        assert c_v not in BAD_VERBS
        assert c_v_f not in BAD_FILTERS
        assert v_f not in BAD_VERB_FILTERS
        if verb in GOOD_VERB_FILTERS:
            assert args in GOOD_VERB_FILTERS[verb]
        if c_v in GOOD_SERVICE_VERB_FILTER:
            assert args in GOOD_SERVICE_VERB_FILTER[c_v]

        # make sure it's not empty when it shouldn't be
        assert len(response.content.decode('utf8')) > 10
    return response.status_code


@pytest.mark.parametrize("service, verb, arg", [
    (cmd, verb, filter) for cmd in cli_commands
    for verb in VERBS for filter in FILTERS
])
def test_rest_services(setup_nubia, start_server, service, verb, arg):
    get(ENDPOINT, service, verb, arg)


def create_config():
    # We need to create a tempfile to hold the config
    tmpconfig = conftest._create_context_config()

    tmpconfig['data-directory'] = './tests/data/multidc/parquet-out'
    r_int = random.randint(17, 2073)
    fname = f'/tmp/suzieq-cfg-{r_int}.yml'

    with open(fname, 'w') as f:
        f.write(yaml.dump(tmpconfig))
    return fname


@pytest.fixture(scope="session")
def start_server():
    app.cfg_file = create_config()


def test_bad_rest():
    pass