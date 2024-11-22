class Vuln:
    def __init__(self, data):
        self.data = data

    def id(self):
        try:
            return self.data['vulnerabilityWithRemediation']['vulnerabilityName']
        except KeyError:
            return ''

    def status(self):
        try:
            return self.data['vulnerabilityWithRemediation']['remediationStatus']
        except KeyError:
            return ''

    def severity(self):
        try:
            return self.data['vulnerabilityWithRemediation']['severity']
        except KeyError:
            return ''

    def related_vuln(self):
        try:
            return self.data['vulnerabilityWithRemediation']['relatedVulnerability'].split('/')[-1]
        except KeyError:
            return ''

    def component(self):
        try:
            return f"{self.data['componentName']}/{self.data['componentVersionName']}"
        except KeyError:
            return ''

    def get_linked_vuln(self, bd):
        vuln_url = f"{bd.base_url}/api/vulnerabilities/{self.id()}"
        vuln_data = self.get_data(bd, vuln_url, "application/vnd.blackducksoftware.vulnerability-4+json")

        try:
            if vuln_data['source'] == 'BDSA':
                for x in vuln_data['_meta']['links']:
                    if x['rel'] == 'related-vulnerability':
                        if x['label'] == 'NVD':
                            cve = x['href'].split("/")[-1]
                            return cve
                        break
            else:
                return self.id()
        except KeyError:
            return ''

    def get_data(self, bd, url, accept_hdr):
        headers = {
            'accept': accept_hdr,
        }
        res = bd.get_json(url, headers=headers)
        return res


