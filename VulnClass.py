import global_values
# import config
import re


class Vuln:
    def __init__(self, data, id=''):

        self.comp_vuln_data = data
        self.bdsa_data = None
        self.cve_data = None
        self.linked_cve_data = None
        self.id = id
        self.in_kernel = True
        if self.id == '':
            self.id = self.get_id()

    def get_id(self):
        try:
            if 'vulnerability' in self.comp_vuln_data:
                return self.comp_vuln_data['vulnerability']['vulnerabilityId']
            else:
                return self.id
        except KeyError:
            return ''

    def status(self):
        try:
            return self.comp_vuln_data['vulnerability']['remediationStatus']
        except KeyError:
            return ''

    def severity(self):
        try:
            return self.comp_vuln_data['vulnerability']['severity']
        except KeyError:
            return ''

    def related_vuln(self):
        try:
            return self.comp_vuln_data['vulnerability']['relatedVulnerability'].split('/')[-1]
        except KeyError:
            return ''

    def component(self):
        try:
            return f"{self.comp_vuln_data['componentName']}/{self.comp_vuln_data['componentVersionName']}"
        except KeyError:
            return ''

    def get_linked_vuln(self):
        # vuln_url = f"{bd.base_url}/api/vulnerabilities/{self.id()}"
        # vuln_data = self.get_data(bd, vuln_url, "application/vnd.blackducksoftware.vulnerability-4+json")

        try:
            if self.get_vuln_source() == 'BDSA':
                if self.comp_vuln_data['vulnerability']['relatedVulnerability'] != '':
                    cve = self.comp_vuln_data['vulnerability']['relatedVulnerability'].split("/")[-1]
                    return cve

                # for x in self.comp_vuln_data['_meta']['links']:
                #     if x['rel'] == 'related-vulnerability':
                #         if x['label'] == 'NVD':
                #             cve = x['href'].split("/")[-1]
                #             return cve
                #         break
            else:
                return ''
        except KeyError:
            return ''

    @staticmethod
    def get_data(bd, url, accept_hdr):
        headers = {
            'accept': accept_hdr,
        }
        res = bd.get_json(url, headers=headers)
        return res

    def is_ignored(self):
        if self.comp_vuln_data['vulnerability']['remediationStatus'] == 'IGNORED':
            return True
        else:
            return False

    def get_component(self):
        return self.comp_vuln_data['componentName']

    def get_url(self, bd):
        return f"{bd.base_url}/api/vulnerabilities/{self.get_id()}"

    def get_associated_vuln_url(self, bd):
        return f"{bd.base_url}/api/vulnerabilities/{self.get_linked_vuln()}"

    def add_data(self, data):
        try:
            if data['source'] == 'BDSA':
                self.bdsa_data = data
            elif data['source'] == 'NVD':
                self.cve_data = data
        except KeyError:
            return

    def add_linked_cve_data(self, data):
        self.linked_cve_data = data

    @staticmethod
    def find_sourcefile(sline):
        pattern = r'[\w/\.-]+\.[ch]\b'
        res = re.findall(pattern, sline)
        arr = []
        for str in res:
            if str not in arr:
                arr.append(str)
        return arr

    def get_vuln_source(self):
        try:
            if 'source' in self.comp_vuln_data and self.comp_vuln_data['source'] != '':
                return self.comp_vuln_data['source']
            elif self.get_id().startswith('BDSA-'):
                return 'BDSA'
            elif self.get_id().startswith('CVE-'):
                return 'NVD'
            else:
                return ''

        except KeyError:
            return ''

    def process_kernel_vuln(self):
        try:
            sourcefiles = []
            if self.get_vuln_source() == 'NVD':
                sourcefiles = self.find_sourcefile(self.cve_data['description'])
                if len(sourcefiles) == 0:
                    global_values.logger.debug(f"CVE {self.get_id()} - Description: {self.cve_data['description']}")
            elif self.get_vuln_source() == 'BDSA':
                sourcefiles = self.find_sourcefile(self.bdsa_data['description'])
                if len(sourcefiles) == 0:
                    sourcefiles = self.find_sourcefile(self.bdsa_data['technicalDescription'])
                    if len(sourcefiles) == 0:
                        global_values.logger.debug(f"BDSA {self.get_id()} - Description: {self.bdsa_data['description']}")
                        global_values.logger.debug(f"BDSA {self.get_id()} - Technical Description: {self.bdsa_data['technicalDescription']}")
                        if self.linked_cve_data:
                            # No source file found - need to check for linked CVE
                            sourcefiles = self.find_sourcefile(self.linked_cve_data['description'])
                            global_values.logger.debug(f"Linked CVE Description: {self.linked_cve_data['description']}")

            return sourcefiles
            # print(f"{self.get_id()}: {sourcefile}")
        except KeyError:
            return []

    def is_kernel_vuln(self):
        if self.comp_vuln_data['componentName'] == 'Linux Kernel':
            return True
        return False

    def set_not_in_kernel(self):
        self.in_kernel = False

    async def async_get_vuln_data(self, bd, session, token):
        if global_values.bd_trustcert:
            ssl = False
        else:
            ssl = None

        headers = {
            # 'accept': "application/vnd.blackducksoftware.bill-of-materials-6+json",
            'Authorization': f'Bearer {token}',
        }
        # resp = globals.bd.get_json(thishref, headers=headers)
        async with session.get(self.get_url(bd), headers=headers, ssl=ssl) as resp:
            result_data = await resp.json()
        return self.get_id(), result_data

    async def async_get_associated_vuln_data(self, bd, session, token):
        if global_values.bd_trustcert:
            ssl = False
        else:
            ssl = None

        headers = {
            # 'accept': "application/vnd.blackducksoftware.bill-of-materials-6+json",
            'Authorization': f'Bearer {token}',
        }
        # resp = globals.bd.get_json(thishref, headers=headers)
        async with session.get(self.get_associated_vuln_url(bd), headers=headers, ssl=ssl) as resp:
            result_data = await resp.json()
        return self.get_id(), result_data
