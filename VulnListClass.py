import aiohttp
import asyncio
from VulnClass import Vuln
# import config
from KernelSourceClass import KernelSource
import global_values

# logger = config.setup_logger('kernel-vulns')


class VulnList:
    def __init__(self):
        self.vulns = []
        self.linked_vulns = []

    def add_comp_data(self, data):
        for vulndata in data:
            if vulndata['ignored']:
                continue
            vuln = Vuln(vulndata)
            if vuln.is_kernel_vuln():
                self.vulns.append(vuln)

    def get_vuln(self, id):
        for vuln in self.vulns:
            if id == vuln.get_id():
                return vuln

    def add_vuln_data(self, data):
        try:
            for id, entry in data.items():
                vuln = self.get_vuln(id)
                if vuln:
                    # vuln is in standard list (not a linked vuln)
                    if vuln.is_ignored():
                        continue
                    vuln.add_data(entry)
                    if vuln.get_vuln_source() == 'BDSA':
                        linked_vuln = vuln.get_linked_vuln()
                        if linked_vuln:
                            if linked_vuln in data.keys():
                                vuln.add_linked_cve_data(data[linked_vuln])
        except KeyError:
            return

    def process_kernel_vulns(self, kfiles: KernelSource):
        for vuln in self.vulns:
            if vuln.is_ignored():
                continue
            files = vuln.process_kernel_vuln()
            if len(files) == 0 or kfiles.check_files(files):
                global_values.logger.debug(f"VULN IN KERNEL: {vuln.get_id()} - {files}")
            else:
                global_values.logger.debug(f"VULN NOT IN KERNEL: {vuln.get_id()} - {files}")
                vuln.set_not_in_kernel()

    def count(self):
        return len(self.vulns)

    def count_in_kernel(self):
        count = 0
        for vuln in self.vulns:
            if vuln.in_kernel:
                count += 1

        return count

    # def remediate_vulns(self):
    #     for vuln in self.vulns:

    async def async_get_vuln_data(self, bd):
        token = bd.session.auth.bearer_token

        async with aiohttp.ClientSession(trust_env=True) as session:
            vuln_tasks = []
            for vuln in self.vulns:
                if vuln.is_ignored():
                    continue

                vuln_task = asyncio.ensure_future(vuln.async_get_vuln_data(bd, session, token))
                vuln_tasks.append(vuln_task)

                if vuln.get_vuln_source() == 'BDSA':
                    linked_vuln = vuln.get_linked_vuln()
                    if linked_vuln != '':
                        lvuln = Vuln({}, linked_vuln)
                        vuln_task = asyncio.ensure_future(lvuln.async_get_vuln_data(bd, session, token))
                        vuln_tasks.append(vuln_task)

            vuln_data = dict(await asyncio.gather(*vuln_tasks))
            await asyncio.sleep(0.250)

        return vuln_data
