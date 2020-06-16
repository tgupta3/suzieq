from suzieq.poller.services.service import Service
import re


class LldpService(Service):
    """LLDP service. Different class because of munging ifname"""

    def get_key_flds(self):
        """The MAC table in Linux can have weird keys"""
        return ['ifname', 'peerHostname', 'peerIfname']

    def clean_data(self, processed_data, raw_data):

        devtype = self._get_devtype_from_input(raw_data)

        for entry in processed_data:
            if not entry:
                continue
            entry['ifname'] = entry['ifname'].replace('/', '-')
            if entry.get('subtype', None) == 'Mac address':
                entry['peerIfname'] = '-'
            else:
                entry['peerMacaddr'] = '00:00:00:00:00:00'

            if devtype == 'nxos':
                entry['peerHostname'] = re.sub(r'\(.*\)', '',
                                               entry['peerHostname'])
            elif any(devtype == x for x in ['cumulus', 'linux', 'eos']):
                entry['origIfname'] = entry['ifname']

        return super().clean_data(processed_data, raw_data)
