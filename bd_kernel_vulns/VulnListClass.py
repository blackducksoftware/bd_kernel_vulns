import aiohttp
import asyncio
from .VulnClass import Vuln
# Removed unused import
from .KernelSourceClass import KernelSource
# Removed unused import

# Removed unused logger setup


class VulnList:
    def __init__(self):
        self.vulnlist_direct = {}
        self.vulnlist_associated = {}

    def add_comp_data(self, data, conf):
        conf.logger.debug(f"Vulnlist: processing {len(data)} vulns from compdata")
        ignored = 0
        for vulndata in data:
            # if vulndata['ignored']:
            #     ignored += 1
            #     continue
            vuln = Vuln(vulndata, conf)
            if not vuln:
                conf.logger.error(f"Unable to process vuln entry {vulndata}")
                continue
            if vuln.is_ignored():
                ignored += 1
                continue
            if vuln.is_kernel_vuln(conf):
                self.vulnlist_direct[vuln.url()] = vuln
                # self.vulns.append(vuln)
        conf.logger.debug(f"Skipped {ignored} ignored vulns")

    def get_directvuln_by_url(self, url):
        # for vuln in self.vulns:
        #     if url == vuln.url():
        #         return vuln
        if url in self.vulnlist_direct.keys():
            return self.vulnlist_direct[url]
        # global_values.logger.error(f"Unable to find vuln {id} in vuln list")
        return None

    def get_associated_vuln_by_id(self, id):
        if id in self.vulnlist_associated.keys():
            return self.vulnlist_associated[id]
        return None

    # def is_associated_vuln(self, id):
    #     if id in self.vulnlist_associated:
    #         return True
    #     return False

    def add_directvuln_data(self, data, conf):
        try:
            conf.logger.debug(f"Vulnlist: adding {len(data)} vulns from asyncdata")
            for url, entry in data.items():
                    vuln = self.get_directvuln_by_url(url)
                    if vuln:
                        # vuln is in standard list (not a linked vuln)
                        if vuln.is_ignored():
                            continue
                        vuln.add_data(entry)
                    else:
                        conf.logger.warning(f"Unable to locate vuln {url} in vulnlist")
        except KeyError as e:
            conf.logger.error(f"add_vuln_data(): Key Error {e}")

        return

    def add_associatedvuln_data(self, data, conf):
        try:
            conf.logger.debug(f"Vulnlist: adding {len(data)} vulns from associated asyncdata")
            for id, entry in data.items():
                if id in self.vulnlist_associated.keys():
                    # already exists
                    continue

                vuln = Vuln({}, conf, cve_data=entry)
                self.vulnlist_associated[id] = vuln

                    # vuln.add_data(entry)
                    # if vuln.get_vuln_source() == 'BDSA':
                    #     linked_vuln = vuln.get_linked_vuln()
                    #     if linked_vuln:
                    #         if linked_vuln in data.keys():
                    #             vuln.add_linked_cve_data(data[linked_vuln])
                    #             self.vulnlist_associated.append(id)
        except Exception as e:
            conf.logger.error(f"add_associatedvuln_data(): Error {e}")

        return

    def process_kernel_vulns(self, conf, kfiles: KernelSource):
        for url, vuln in self.vulnlist_direct.items():
            if vuln.is_ignored() or vuln.get_id() in self.vulnlist_associated.keys():
                continue
            files = vuln.get_kernel_vuln_sourcefiles(conf)
            if len(files) == 0 and vuln.get_vuln_origin() == 'BDSA':
                    cve = vuln.get_linked_cve()
                    if cve and cve in self.vulnlist_associated.keys():
                        cve_vuln = self.vulnlist_associated[cve]
                        files = cve_vuln.get_kernel_vuln_sourcefiles(conf)

            if len(files) == 0:
                conf.logger.debug(f"VULN IN KERNEL: {vuln.get_id()} - no affected source files reported in vuln")
            elif len(files) > 0 and kfiles.check_files(conf, files):
                conf.logger.debug(f"VULN IN KERNEL: {vuln.get_id()} - {files} matches file in supplied kernel source list")
            else:
                conf.logger.debug(f"VULN NOT IN KERNEL: {vuln.get_id()} - {files}")
                vuln.set_not_in_kernel()

    def count(self):
        return len(self.vulnlist_direct)

    def count_in_kernel(self):
        count = 0
        for url, vuln in self.vulnlist_direct.items():
            if vuln.in_kernel:
                count += 1

        return count

    # def remediate_vulns(self):
    #     for vuln in self.vulns:

    # def ignore_vulns(self, bd, conf):  # DEBUG
    #     for vuln in self.vulns:
    #         vuln.ignore_vuln(bd, conf)

    async def async_get_directvuln_data(self, bd, conf):
        token = bd.session.auth.bearer_token

        async with aiohttp.ClientSession(trust_env=True) as session:
            vuln_tasks = []
            for url, vuln in self.vulnlist_direct.items():
                if vuln.is_ignored():
                    continue

                vuln_task = asyncio.ensure_future(vuln.async_get_directvuln_data(bd, conf, session, token))
                vuln_tasks.append(vuln_task)

                # if vuln.get_vuln_source() == 'BDSA':
                #     linked_vuln = vuln.get_linked_vuln()
                #     if linked_vuln != '':
                #         lvuln = Vuln({}, conf, linked_vuln)
                #         # self.associated_vulns.append(lvuln)
                #         self.associated_vuln_ids.append(lvuln.id)
                #         vuln_task = asyncio.ensure_future(lvuln.async_get_vuln_data(bd, conf, session, token))
                #         vuln_tasks.append(vuln_task)

            vuln_data = dict(await asyncio.gather(*vuln_tasks))
            await asyncio.sleep(0.250)

        return vuln_data

    async def async_get_associatedvuln_data(self, bd, conf):
        token = bd.session.auth.bearer_token

        async with aiohttp.ClientSession(trust_env=True) as session:
            vuln_tasks = []
            count = 0
            processed_cves = []
            for url, vuln in self.vulnlist_direct.items():
                if vuln.is_ignored():
                    continue

                # vuln_task = asyncio.ensure_future(vuln.async_get_vuln_data(bd, conf, session, token))
                # vuln_tasks.append(vuln_task)

                if vuln.get_vuln_origin() == 'BDSA':
                    linked_vuln = vuln.get_linked_cve()
                    if linked_vuln != '':
                        if linked_vuln in processed_cves:
                            conf.logger.debug(f"Skipping {linked_vuln} as already processed")
                            continue
                        lvuln = Vuln({}, conf, id=linked_vuln)
                        # self.associated_vulns.append(lvuln)
                        vuln_task = asyncio.ensure_future(lvuln.async_get_associatedvuln_data(bd, conf, session, token))
                        vuln_tasks.append(vuln_task)
                        processed_cves.append(linked_vuln)
                        count += 1

            conf.logger.debug(f"Getting data for {count} associated vulns ...")
            vuln_data = dict(await asyncio.gather(*vuln_tasks))
            await asyncio.sleep(0.250)

        return vuln_data

    async def async_ignore_vulns(self, bd, conf):
        token = bd.session.auth.bearer_token

        async with aiohttp.ClientSession(trust_env=True) as session:
            vuln_tasks = []
            for vuln in self.vulnlist_direct.values():
                if vuln.is_ignored() or vuln.in_kernel:
                    continue

                vuln_task = asyncio.ensure_future(vuln.async_ignore_vuln(conf, session, token))
                vuln_tasks.append(vuln_task)

            vuln_data = dict(await asyncio.gather(*vuln_tasks))
            await asyncio.sleep(0.250)

        return vuln_data
