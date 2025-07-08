# from . import global_values
from .BOMClass import BOM
# from . import config
from .KernelSourceClass import KernelSource
from .ConfigClass import Config
import sys
import logging

# logger = config.setup_logger('kernel-vulns')

program_version = 'v1.0.6'


def main():
    conf = Config()
    if not conf.get_cli_args():
        sys.exit(1)

    process(conf)
    # config.check_args(args)
    
    sys.exit(0)


def process_kernel_vulns(blackduck_url, blackduck_api_token, kernel_source_file,
                         project, version, logger=None, blackduck_trust_cert=False, folders=False,
                         kernel_comp_name='Linux Kernel', remediation_status='NOT_AFFECTED',
                         remediation_justification='NO_CODE', source_file_names_only=False):
    conf = Config()
    conf.bd_url = blackduck_url
    conf.bd_api = blackduck_api_token
    conf.bd_project = project
    conf.bd_version = version
    if logger:
        conf.logger = logger
    else:
        conf.logger = logging
    conf.bd_trustcert = blackduck_trust_cert
    conf.folders = folders
    conf.kernel_source_file = kernel_source_file
    conf.kernel_comp_name = kernel_comp_name
    conf.remediation_status = remediation_status
    conf.remediation_justification = remediation_justification
    conf.source_file_names_only = source_file_names_only

    process(conf)

    return


def process(conf):
    conf.logger.info(f"------------------------------------------------------------------------")
    conf.logger.info(f"Running bd-kernel-vulns - version {program_version}")
    conf.logger.info(f"------------------------------------------------------------------------")

    bom = BOM(conf)
    if not bom:
        conf.logger.info("Unable to connect to BD server - terminating")

    if not bom.check_bd_version(conf) and conf.remediation_status == 'NOT_AFFECTED':
        conf.logger.info("BD server version is earlier than 2025.1.0 - will use supported remediation status IGNORE")
        conf.remediation_status = 'IGNORE'

    bom.get_comps(conf)
    count = bom.count_kernel_comps(conf)
    if count == 0:
        conf.logger.warn("Linux Kernel not found in project - terminating (use --kernel_comp_name "
                         "for alternative kernel component name which is not 'Linux Kernel')")
        sys.exit(-1)
    else:
        conf.logger.info(f"Found {count} Linux Kernel components in project")

    kfiles = KernelSource(conf)
    conf.logger.info(f"Read {kfiles.count()} source entries from kernel source file "
                     f"'{conf.kernel_source_file}'")

    conf.logger.info("Processing kernel vulnerabilities:")
    bom.get_vulns(conf)
    conf.logger.info(f"- Found {bom.count_vulns()} unremediated kernel vulnerabilities within project")

    # bom.print_vulns()
    conf.logger.info("- Getting detailed data for direct kernel vulnerabilities ...")
    bom.process_directvulns_async(conf)

    conf.logger.info("- Getting detailed data for associated kernel vulnerabilities ...")
    bom.process_associatedvulns_async(conf)

    conf.logger.info("- Checking for kernel source file references in vulnerabilities")
    bom.process_kernel_vulns(conf, kfiles)

    conf.logger.info(f"- Identified {bom.count_not_in_kernel_vulns()} not in-scope kernel vulns which can be ignored "
                     f"({bom.count_in_kernel_vulns()} in-scope kernel vulns - not modified)")

    conf.logger.info(f"- Applied remediation status {conf.remediation_status} to "
                     f"{bom.ignore_vulns_async(conf)} kernel vulns")
    # bom.ignore_vulns()
    conf.logger.info("Done")


if __name__ == '__main__':
    main()
