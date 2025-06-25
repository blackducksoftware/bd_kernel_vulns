# import global_values
# import re
# import global_values
# import logging
# from thefuzz import fuzz
from .VulnListClass import VulnList


class Component:
    def __init__(self, name, version, data):
        self.name = name
        self.version = version
        self.vulnlist = VulnList()
        self.data = data

    # def get_matchtypes(self):
    #     try:
    #         return self.data['matchTypes']
    #     except KeyError:
    #         return []
    #
    # def is_dependency(self):
    #     dep_types = ['FILE_DEPENDENCY_DIRECT', 'FILE_DEPENDENCY_TRANSITIVE']
    #     match_types = self.get_matchtypes()
    #     for m in dep_types:
    #         if m in match_types:
    #             return True
    #     return False
    #
    # def is_signature(self):
    #     sig_types = ['FILE_EXACT', 'FILE_SOME_FILES_MODIFIED', 'FILE_FILES_ADDED_DELETED_AND_MODIFIED',
    #                  'FILE_EXACT_FILE_MATCH']
    #     match_types = self.get_matchtypes()
    #     for m in sig_types:
    #         if m in match_types:
    #             return True
    #     return False

    def is_ignored(self):
        try:
            return self.data['ignored']
        except KeyError:
            return False

    # def process_signatures(self):
    #     all_paths_ignoreable = True
    #     unmatched = False
    #     reason = ''
    #     for sigentry in self.sigentry_arr:
    #         ignore, reason = sigentry.filter_folders()
    #         if not ignore:
    #             all_paths_ignoreable = False
    #         else:
    #             self.sigentry_arr.remove(sigentry)
    #
    #     if all_paths_ignoreable:
    #         # Ignore
    #         reason = f"Mark IGNORED - {reason}"
    #         self.reason = reason
    #         logging.debug(f"- Component {self.filter_name}/{self.version}: {reason}")
    #         self.set_ignore()
    #     else:
    #     #     print(f"NOT Ignoring {self.name}/{self.version}")
    #         self.sig_match_result = 0
    #         set_reviewed = False
    #         ignore = True
    #         unmatched = True
    #         reason = f"No Action - component name '{self.oriname_arr}' not found in signature paths"
    #         for sigentry in self.sigentry_arr:
    #             # compname_found, compver_found,\
    #             #     new_match_result = sigentry.search_component(self.filter_name, self.filter_version)
    #             compname_found, compver_found,\
    #                 new_match_result = sigentry.search_component(self.oriname_arr, self.filter_version)
    #             logging.debug(f"Compname in path {compname_found}, Version in path {compver_found}, "
    #                           f"Match result {new_match_result}, Path '{sigentry.path}'")
    #
    #             if compver_found:
    #                 self.compver_found = True
    #                 ignore = False
    #                 unmatched = False
    #             if compname_found:
    #                 self.compname_found = True
    #             if global_values.version_match_reqd:
    #                 if compver_found:
    #                     set_reviewed = True
    #                     ignore = False
    #                     unmatched = False
    #                 else:
    #                     reason = f"No Action - component version {self.filter_version} not found
    #                     (and required because --version_match_reqd set)"
    #             elif compname_found:
    #                 set_reviewed = True
    #                 ignore = False
    #                 unmatched = False
    #             if new_match_result > self.sig_match_result:
    #                 self.sig_match_result = new_match_result
    #                 self.best_sigpath = sigentry.path
    #             # print(self.name, self.version, src['commentPath'])
    #         if set_reviewed:
    #             if self.compver_found:
    #                 reason = f"Mark REVIEWED - Compname & version in path '{self.best_sigpath}'
    #                 (Match result {self.sig_match_result})"
    #             elif self.compname_found:
    #                 reason = f"Mark REVIEWED - Compname {self.oriname_arr} in path '{self.best_sigpath}'
    #                 (Match result {self.sig_match_result})"
    #
    #             logging.debug(f"- Component {self.name}/{self.version}: {reason}")
    #             self.set_reviewed()
    #             unmatched = False
    #     if ignore and global_values.ignore_no_path_matches:
    #         self.set_ignore()
    #         reason = f"Mark IGNORED - compname or version not found in paths & --ignore_no_path_matches set"
    #
    #     self.reason = reason
    #     self.unmatched = unmatched

    # @staticmethod
    # def filter_name_string(name, logger):
    #     # Remove common words
    #     # - for, with, in, on,
    #     # Remove strings in brackets
    #     # Replace / with space
    #     ret_name = re.sub(r"\(.*\)", r"", name)
    #     for rep in [r" for ", r" with ", r" in ", r" on ", r" a ", r" the ", r" by ",
    #                 r" and ", r"^apache | apache | apache$", r" bundle ", r" only | only$", r" from ",
    #                 r" to ", r" - "]:
    #         ret_name = re.sub(rep, " ", ret_name, flags=re.IGNORECASE)
    #     ret_name = re.sub(r"[/@#:]", " ", ret_name)
    #     ret_name = re.sub(r" \w$| \w |^\w ", r" ", ret_name)
    #     ret_name = ret_name.replace("::", " ")
    #     ret_name = re.sub(r" +", r" ", ret_name)
    #     ret_name = re.sub(r"^ ", r"", ret_name)
    #     ret_name = re.sub(r" $", r"", ret_name)
    #
    #     debug(f"filter_name_string(): Compname '{name}' replaced with '{ret_name}'")
    #     return ret_name.lower()

    # @staticmethod
    # def filter_version_string(version):
    #     # Remove +git*
    #     # Remove -snapshot*
    #     # Replace / with space
    #     ret_version = re.sub(r"\+git.*", r"", version, flags=re.IGNORECASE)
    #     ret_version = re.sub(r"-snapshot.*", r"", ret_version, flags=re.IGNORECASE)
    #     ret_version = re.sub(r"/", r" ", ret_version)
    #     ret_version = re.sub(r"^v", r"", ret_version, flags=re.IGNORECASE)
    #     ret_version = re.sub(r"\+*", r"", ret_version, flags=re.IGNORECASE)
    #
    #     return ret_version.lower()

    # def get_compid(self):
    #     try:
    #         compurl = self.data['component']
    #         return compurl.split('/')[-1]
    #     except KeyError:
    #         return ''

    # def print_origins(self):
    #     try:
    #         for ori in self.data['origins']:
    #             print(f"Comp '{self.name}/{self.version}' Origin '{ori['externalId']}' Name '{ori['name']}'")
    #     except KeyError:
    #         print(f"Comp '{self.name}/{self.version}' No Origin")
    #
    # def get_origin_compnames(self):
    #     compnames_arr = []
    #     try:
    #         for ori_entry in self.data['origins']:
    #             ori = ori_entry['externalId']
    #             ori_ver = ori_entry['name']
    #             ori_string = ori.replace(f"{ori_ver}", '')
    #             arr = re.split(r"[:/#]", ori_string)
    #             new_name = arr[-2].lower()
    #             if new_name not in compnames_arr:
    #                 logging.debug(
    #                     f"Comp '{self.name}/{self.version}' Compname calculate from origin '{new_name}' -
    #                     origin='{ori}'")
    #                 compnames_arr.append(new_name)
    #         if self.filter_name.find(' ') == -1:
    #             # Single word component name
    #             if self.filter_name not in compnames_arr:
    #                 compnames_arr.append(self.filter_name.lower())
    #     except (KeyError, IndexError):
    #         logging.debug(f"Comp '{self.name}/{self.version}' Compname calculate from compname only '{self.name}'")
    #         compnames_arr.append(self.filter_name.lower())
    #     return compnames_arr
    #
    # def get_sigpaths(self):
    #     data = ''
    #     count = 0
    #     for sigentry in self.sigentry_arr:
    #         data += f"{sigentry.get_sigpath()}\n"
    #         count += 1
    #     return data

    def check_kernel(self, conf):
        if self.name == conf.kernel_comp_name:
            return True
        return False
