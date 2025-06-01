# import config
from ComponentListClass import ComponentList
# from ComponentClass import Component
from VulnListClass import VulnList
import global_values
# import logging
from blackduck import Client
import sys
# from tabulate import tabulate
# import aiohttp
import asyncio
import platform
# import re


class BOM:
    def __init__(self, proj, ver):
        try:
            self.bdprojname = proj
            self.bdvername = ver
            self.complist = ComponentList()
            self.vulnlist = VulnList()
            self.bd = None

            global_values.logger.info(f"Working on project '{proj}' version '{ver}'")

            self.bdver_dict = self.get_project(proj, ver)
            if not self.bd:
                raise ValueError("Unable to create BOM object")

            res = self.bd.list_resources(self.bdver_dict)
            self.projver = res['href']
            # thishref = f"{self.projver}/components"
            #
            # bom_arr = self.get_paginated_data(thishref, "application/vnd.blackducksoftware.bill-of-materials-6+json")
            #
            # for comp in bom_arr:
            #     if 'componentVersion' not in comp:
            #         continue
            #     # compver = comp['componentVersion']
            #
            #     compclass = Component(comp['componentName'], comp['componentVersionName'], comp)
            #     self.complist.add(compclass)
            #
        except ValueError as v:
            global_values.logger.error(v)
            sys.exit(-1)
        return

    def get_paginated_data(self, url, accept_hdr):
        headers = {
            'accept': accept_hdr,
        }
        url = url + "?limit=1000"
        res = self.bd.get_json(url, headers=headers)
        if 'totalCount' in res and 'items' in res:
            total_comps = res['totalCount']
        else:
            return []

        ret_arr = []
        downloaded_comps = 0
        while downloaded_comps < total_comps:
            downloaded_comps += len(res['items'])

            ret_arr += res['items']

            newurl = f"{url}&offset={downloaded_comps}"
            res = self.bd.get_json(newurl, headers=headers)
            if 'totalCount' not in res or 'items' not in res:
                break

        return ret_arr

    def get_project(self, proj, ver):
        self.bd = Client(
            token=global_values.bd_api,
            base_url=global_values.bd_url,
            verify=(not global_values.bd_trustcert),  # TLS certificate verification
            timeout=60
        )

        params = {
            'q': "name:" + proj,
            'sort': 'name',
        }

        ver_dict = None
        projects = self.bd.get_resource('projects', params=params)
        for p in projects:
            if p['name'] == proj:
                versions = self.bd.get_resource('versions', parent=p, params=params)
                for v in versions:
                    if v['versionName'] == ver:
                        ver_dict = v
                        break
                break
        else:
            global_values.logger.error(f"Version '{ver}' does not exist in project '{proj}'")
            sys.exit(2)

        if ver_dict is None:
            global_values.logger.warning(f"Project '{proj}' does not exist")
            sys.exit(2)

        return ver_dict

    def get_vulns(self):
        vuln_url = f"{self.projver}/vulnerable-bom-components"
        vuln_arr = self.get_paginated_data(vuln_url, "application/vnd.blackducksoftware.bill-of-materials-8+json")
        self.vulnlist.add_comp_data(vuln_arr)

    def process_data_async(self):
        if platform.system() == "Windows":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        self.vulnlist.add_vuln_data(asyncio.run(self.vulnlist.async_get_vuln_data(self.bd)))

    def ignore_vulns_async(self):
        if platform.system() == "Windows":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        data = asyncio.run(self.vulnlist.async_ignore_vulns(self.bd))
        return len(data)

    def ignore_vulns(self):  # DEBUG
        self.vulnlist.ignore_vulns(self.bd)

    def process_kernel_vulns(self, kfiles):
        self.vulnlist.process_kernel_vulns(kfiles)

    # def count_comps(self):
    #     return len(self.complist)

    def count_vulns(self):
        return self.vulnlist.count()

    def count_in_kernel_vulns(self):
        return self.vulnlist.count_in_kernel()

    def count_not_in_kernel_vulns(self):
        return self.vulnlist.count() - self.vulnlist.count_in_kernel()

    def check_kernel_comp(self):
        return self.complist.check_kernel()
