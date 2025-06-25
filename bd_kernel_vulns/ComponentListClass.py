# from Component import Component
# import global_values
# import logging
# import requests

class ComponentList:
    def __init__(self):
        self.components = []

    def add(self, comp):
        self.components.append(comp)

    # def count(self):
    #     return len(self.components)
    #
    # def count_ignored(self):
    #     count = 0
    #     for comp in self.components:
    #         if comp.is_ignored():
    #             count += 1
    #     return count

    def get_vulns(self):
        for comp in self.components:
            comp.get_vulns()

    def count_kernel_comps(self, conf):
        count = 0
        for comp in self.components:
            if comp.check_kernel(conf):
                count += 1

        return count
