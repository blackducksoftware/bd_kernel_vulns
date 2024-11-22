from ComponentListClass import ComponentList
from ComponentClass import Component
from VulnListClass import VulnList
import global_values
import logging
from blackduck import Client
import sys
from tabulate import tabulate

class BOM:
    def __init__(self, proj, ver):
        self.bdprojname = proj
        self.bdvername = ver
        self.complist = ComponentList()
        self.vulnlist = VulnList()

        logging.info(f"Working on project '{proj}' version '{ver}'")

        self.bdver_dict = self.get_project(proj, ver)

        res = self.bd.list_resources(self.bdver_dict)
        self.projver = res['href']
        thishref = f"{self.projver}/components"

        bom_arr = self.get_paginated_data(thishref, "application/vnd.blackducksoftware.bill-of-materials-6+json")

        for comp in bom_arr:
            if 'componentVersion' not in comp:
                continue
            # compver = comp['componentVersion']

            compclass = Component(comp['componentName'], comp['componentVersionName'], comp)
            self.complist.add(compclass)

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
            logging.error(f"Version '{ver}' does not exist in project '{proj}'")
            sys.exit(2)

        if ver_dict is None:
            logging.warning(f"Project '{proj}' does not exist")
            sys.exit(2)

        return ver_dict


    def get_vulns(self):
        vuln_url = f"{self.projver}/vulnerable-bom-components"
        vuln_arr = self.get_paginated_data(vuln_url, "application/vnd.blackducksoftware.bill-of-materials-6+json")
        self.vulnlist.add(vuln_arr)


    def print_vulns(self):
        table, header = self.vulnlist.print(self.bd)
        print(tabulate(table, headers=header, tablefmt="tsv"))

