# import config
from .ComponentListClass import ComponentList
# from ComponentClass import Component
from .VulnListClass import VulnList
# from . import global_values
# import logging
from blackduck import Client
import sys
# from tabulate import tabulate
# import aiohttp
import asyncio
import platform
# import re


class BOM:
    def __init__(self, conf):
        try:
            self.complist = ComponentList()
            self.vulnlist = VulnList()
            self.bd = Client(
                token=conf.bd_api,
                base_url=conf.bd_url,
                verify=(not conf.bd_trustcert),  # TLS certificate verification
                timeout=60
            )

            conf.logger.info(f"Working on project '{conf.bd_project}' version '{conf.bd_version}'")

            self.bdver_dict = self.get_project(conf)
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
            conf.logger.error(v)
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

    def get_project(self, conf):
        params = {
            'q': "name:" + conf.bd_project,
            'sort': 'name',
        }

        ver_dict = None
        projects = self.bd.get_resource('projects', params=params)
        for p in projects:
            if p['name'] == conf.bd_project:
                versions = self.bd.get_resource('versions', parent=p, params=params)
                for v in versions:
                    if v['versionName'] == conf.bd_version:
                        ver_dict = v
                        break
                break
        else:
            conf.logger.error(f"Version '{conf.bd_version}' does not exist in project '{conf.bd_project}'")
            sys.exit(2)

        if ver_dict is None:
            conf.logger.warning(f"Project '{conf.bd_project}' does not exist")
            sys.exit(2)

        return ver_dict

    def get_vulns(self, conf):
        vuln_url = f"{self.projver}/vulnerable-bom-components"
        vuln_arr = self.get_paginated_data(vuln_url, "application/vnd.blackducksoftware.bill-of-materials-8+json")
        self.vulnlist.add_comp_data(vuln_arr, conf)

    def process_data_async(self, conf):
        if platform.system() == "Windows":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        self.vulnlist.add_vuln_data(asyncio.run(self.vulnlist.async_get_vuln_data(self.bd, conf)), conf)

    def ignore_vulns_async(self):
        if platform.system() == "Windows":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        data = asyncio.run(self.vulnlist.async_ignore_vulns(self.bd))
        return len(data)

    def ignore_vulns(self, conf):  # DEBUG
        self.vulnlist.ignore_vulns(self.bd, conf)

    def process_kernel_vulns(self, conf, kfiles):
        self.vulnlist.process_kernel_vulns(conf, kfiles)

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
