import argparse
import logging
import os


class Config:
    def __init__(self):
        self.bd_api = ''
        self.bd_url = ''
        self.bd_trustcert = False

        self.bd_project = ''
        self.bd_version = ''
        self.logger = None
        self.logfile = ''
        self.kernel_source_file = ''
        self.folders = False
        self.debug = False
        self.kernel_comp_name = 'Linux Kernel'
        self.remediation_status = "NOT_AFFECTED"
        self.remediation_justification = "NO_CODE"
        self.source_file_names_only = False

    def get_cli_args(self):
        parser = argparse.ArgumentParser(description='Black Duck vulns', prog='bd_vulns')

        # parser.add_argument("projfolder", nargs="?", help="Yocto project folder to analyse", default=".")

        parser.add_argument("--blackduck_url", type=str, help="Black Duck server URL (REQUIRED)", default="")
        parser.add_argument("--blackduck_api_token", type=str, help="Black Duck API token (REQUIRED)", default="")
        parser.add_argument("--blackduck_trust_cert", help="Black Duck trust server cert", action='store_true')
        parser.add_argument("-p", "--project", help="Black Duck project to process (REQUIRED)", default="")
        parser.add_argument("-v", "--version", help="Black Duck project version to process (REQUIRED)", default="")
        parser.add_argument("--debug", help="Debug logging mode", action='store_true')
        parser.add_argument("--logfile", help="Logging output file", default="")
        parser.add_argument("-k", "--kernel_source_file", help="Kernel source files list (REQUIRED)", default="")
        parser.add_argument("--folders", help="Kernel Source file only contains folders to be used to map vulns",
                            action='store_true')
        parser.add_argument("--kernel_comp_name", help="Kernel Component Name (default 'Linux Kernel')", default="Linux Kernel")
        parser.add_argument("-s", "--remediation_status",
                            help="Vulnerability Remediation Status to apply - Default NOT_AFFECTED "
                                 "(Options REMEDIATION_COMPLETE, NOT_AFFECTED, MITIGATED, DUPLICATE, IGNORED, "
                                 "PATCHED, NEW, UNDER_INVESTIGATION, NEEDS_REVIEW, AFFECTED, "
                                 "REMEDIATION_REQUIRED)", default="NOT_AFFECTED")
        parser.add_argument("--remediation_justification",
                            help="Vulnerability Remediation Justification - Default NO_CODE "
                                 "(Options NO_COMPONENT, NO_CODE, NOT_CONTROLLED, NOT_EXECUTED, "
                                 "ALREADY_MITIGATED, MITIGATION, NO_FIX_PLANNED, "
                                 "NONE_AVAILABLE, VENDOR_FIX, WORKAROUND - only applied if NOT_AFFECTED "
                                 "or AFFECTED selected for remediation status)", default="NO_CODE")
        parser.add_argument("--source_file_names_only",
                            help="Match only source file names from vulnerabilities"
                                 "against the supplied source file list", action='store_true')
        
        args = parser.parse_args()

        terminate = False
        if args.debug:
            loglevel = logging.DEBUG
        else:
            loglevel = logging.INFO
        # global_values.logging_level = loglevel
        self.logfile = args.logfile
    
        self.logger = self.setup_logger('kernel-vulns', loglevel)
    
        self.logger.debug("ARGUMENTS:")
        for arg in vars(args):
            self.logger.debug(f"    --{arg}={getattr(args, arg)}")
        self.logger.debug('')
    
        url = os.environ.get('BLACKDUCK_URL')
        if args.blackduck_url != '':
            self.bd_url = args.blackduck_url
        elif url is not None:
            self.bd_url = url
        else:
            self.logger.error("Black Duck URL not specified")
            terminate = True
    
        if args.project != "" and args.version != "":
            self.bd_project = args.project
            self.bd_version = args.version
        else:
            self.logger.error("Black Duck project/version not specified")
            terminate = True
    
        api = os.environ.get('BLACKDUCK_API_TOKEN')
        if args.blackduck_api_token != '':
            self.bd_api = args.blackduck_api_token
        elif api is not None:
            self.bd_api = api
        else:
            self.logger.error("Black Duck API Token not specified")
            terminate = True
    
        trustcert = os.environ.get('BLACKDUCK_TRUST_CERT')
        if trustcert == 'true' or args.blackduck_trust_cert:
            self.bd_trustcert = True
    
        if args.kernel_source_file != '':
            if not os.path.exists(args.kernel_source_file):
                self.logger.error(f"Supplied kernel source list file '{args.kernel_source_file}' does not exist")
                terminate = True
            else:
                self.kernel_source_file = args.kernel_source_file
        else:
            self.logger.error(f"Kernel source list file required (--kernel_source_list)")
            terminate = True

        self.folders = args.folders
        self.kernel_comp_name = args.kernel_comp_name
        self.remediation_status = args.remediation_status
        self.remediation_justification = args.remediation_justification
        self.source_file_names_only = args.source_file_names_only

        if self.folders and self.source_file_names_only:
            self.logger.error(f"Options --folders and --source_file_names_only specified which are mutually exclusive")
            terminate = True

        if terminate:
            return False
        return True

    def setup_logger(self, name: str, level) -> logging.Logger:
        logger = logging.getLogger(name)
        logger.setLevel(level)

        if not logger.hasHandlers():  # Avoid duplicate handlers
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )

            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

            if self.logfile != '':
                file_handler = logging.FileHandler(self.logfile)
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)

        return logger
