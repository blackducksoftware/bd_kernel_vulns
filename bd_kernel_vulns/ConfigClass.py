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
            self.logger.debug(f"--{arg}={getattr(args, arg)}")
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
    
        if args.folders == 'true':
            self.folders = True
    
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
