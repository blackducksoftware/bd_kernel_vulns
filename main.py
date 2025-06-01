import global_values
from BOMClass import BOM
import config
from KernelSourceClass import KernelSource
import sys

# logger = config.setup_logger('kernel-vulns')

def main():
    config.check_args()
    
    kfiles = KernelSource(global_values.kernel_source_file, global_values.folders)
    global_values.logger.debug(f"Read {kfiles.count()} source entries from kernel source file '{global_values.kernel_source_file}'")

    bom = BOM(global_values.bd_project, global_values.bd_version)
    if bom.check_kernel_comp():
        global_values.logger.warn("Linux Kernel not found in project - terminating")
        sys.exit(-1)

    bom.get_vulns()
    global_values.logger.info(f"Found {bom.count_vulns()} kernel vulnerabilities from project")

    # bom.print_vulns()
    global_values.logger.info("Get detailed data for vulnerabilities")
    bom.process_data_async()

    global_values.logger.info("Checking for kernel source file references in vulnerabilities")
    bom.process_kernel_vulns(kfiles)

    global_values.logger.info(f"Identified {bom.count_in_kernel_vulns()} in-scope kernel vulns ({bom.count_not_in_kernel_vulns()} not in-scope)")

    global_values.logger.info(f"Ignored {bom.ignore_vulns_async()} vulns")
    # bom.ignore_vulns()
    global_values.logger.info("Done")


if __name__ == '__main__':
    main()
