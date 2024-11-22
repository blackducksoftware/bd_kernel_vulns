from VulnClass import Vuln

class VulnList:
    def __init__(self):
        self.vulns = []

    def add(self, data):
        for vulndata in data:
            vuln = Vuln(vulndata)
            self.vulns.append(vuln)

    def print(self, bd):
        table = []
        vulnid_list = []
        for vuln in self.vulns:
            if vuln.id() in vulnid_list:
                continue
            vulnid_list.append(vuln.id())
            table.append([vuln.id(), vuln.status(), vuln.severity(), vuln.component(), vuln.get_linked_vuln(bd)])

        return table, ["ID", "Status", "Severity", "Component", "Linked Vuln"]


