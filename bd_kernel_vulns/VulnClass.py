# from . import global_values
# import config
import re
import datetime
# import json


class Vuln:
    def __init__(self, data, conf, id='', cve_data=None):
        self.comp_vuln_data = data
        self.bdsa_data = None
        self.cve_data = cve_data
        self.linked_cve_data = None
        self.id = id
        self.in_kernel = True
        if self.id == '':
            # self.id = self.get_id()
            if 'vulnerability' in self.comp_vuln_data:
                self.id = self.comp_vuln_data['vulnerability']['vulnerabilityId']
            else:
                conf.logger.error('Unable to determine vuln id')

    def get_id(self):
        return self.id

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

    def get_component(self):
        try:
            return self.comp_vuln_data['componentName']
        except KeyError:
            return ''

    def vuln_url(self, bd):
        return f"{bd.base_url}/api/vulnerabilities/{self.get_id()}"

    def url(self):
        try:
            return self.comp_vuln_data['_meta']['href']
        except KeyError:
            return ''

    def get_associated_vuln_url(self, bd):
        return f"{bd.base_url}/api/vulnerabilities/{self.get_linked_vuln()}"

    def is_ignored(self):
        if self.comp_vuln_data['ignored']:
            return True
        if 'vulnerability' in self.comp_vuln_data:
            if self.comp_vuln_data['vulnerability']['remediationStatus'] == 'IGNORED':
                return True
            else:
                return False
        else:
            return False

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

    def process_kernel_vuln(self, conf):
        try:
            sourcefiles = []
            if self.get_vuln_source() == 'NVD':
                sourcefiles = self.find_sourcefile(self.cve_data['description'])
                if len(sourcefiles) == 0:
                    desc = self.cve_data['description'].replace('\n', ' ')
                    conf.logger.debug(f"CVE {self.get_id()} - Description: {desc}")
            elif self.get_vuln_source() == 'BDSA':
                sourcefiles = self.find_sourcefile(self.bdsa_data['description'])
                if len(sourcefiles) == 0:
                    sourcefiles = self.find_sourcefile(self.bdsa_data['technicalDescription'])
                    if len(sourcefiles) == 0:
                        bdsa = self.bdsa_data['description'].replace('\n', ' ')
                        conf.logger.debug(f"BDSA {self.get_id()} - Description: {bdsa}")
                        tech = self.bdsa_data['technicalDescription'].replace('\n', ' ')
                        conf.logger.debug(f"BDSA {self.get_id()} - Technical Description: {tech}")
                        if self.linked_cve_data:
                            # No source file found - need to check for linked CVE
                            sourcefiles = self.find_sourcefile(self.linked_cve_data['description'])
                            cve = self.linked_cve_data['description'].replace('\n', ' ')
                            conf.logger.debug(f"Linked CVE Description: {cve}")

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

    def ignore_vuln(self, bd, logger):
        try:
            # vuln_name = comp['vulnerabilityWithRemediation']['vulnerabilityName']
            x = datetime.datetime.now()
            mydate = x.strftime("%x %X")

            payload = self.comp_vuln_data
            # payload['remediationJustification'] = "NO_CODE"
            payload[
                'comment'] = (f"Remediated by bd-vulns utility {mydate} - "
                              f"vuln refers to source file not compiled in kernel")
            payload['remediationStatus'] = "IGNORED"

            # result = hub.execute_put(comp['_meta']['href'], data=comp)
            href = self.comp_vuln_data['_meta']['href']
            # href = '/'.join(href.split('/')[3:])
            r = bd.session.put(href, json=self.comp_vuln_data)
            r.raise_for_status()
            if r.status_code != 202:
                raise Exception(f"PUT returned {r.status_code}")
            return True

        except Exception as e:
            logger.error("Unable to update vulnerabilities via API\n" + str(e))
            return False

    async def async_get_vuln_data(self, bd, conf, session, token):
        if conf.bd_trustcert:
            ssl = False
        else:
            ssl = None

        headers = {
            # 'accept': "application/vnd.blackducksoftware.bill-of-materials-6+json",
            'Authorization': f'Bearer {token}',
        }
        # resp = globals.bd.get_json(thishref, headers=headers)
        async with session.get(self.vuln_url(bd), headers=headers, ssl=ssl) as resp:
            result_data = await resp.json()
        return self.get_id(), result_data

    async def async_get_associated_vuln_data(self, bd, conf, session, token):
        if conf.bd_trustcert:
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

    async def async_ignore_vuln(self, conf, session, token):
        if conf.bd_trustcert:
            ssl = False
        else:
            ssl = None

        headers = {
            # 'accept': "application/vnd.blackducksoftware.bill-of-materials-6+json",
            'Authorization': f'Bearer {token}',
        }
        # resp = globals.bd.get_json(thishref, headers=headers)
        x = datetime.datetime.now()
        mydate = x.strftime("%x %X")

        payload = self.comp_vuln_data
        # payload['remediationJustification'] = "NO_CODE"
        payload['comment'] = (f"Remediated by bd-vulns utility {mydate} - "
                              f"vuln refers to source file not compiled in kernel")
        payload['remediationStatus'] = "IGNORED"

        conf.logger.debug(f"{self.id} - {self.url()}")
        async with session.put(self.url(), headers=headers, json=payload, ssl=ssl) as response:
            res = response.status

        # print(res)
        return self.get_id(), res
