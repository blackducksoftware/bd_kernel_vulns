import os
import argparse
import sys
import logging

# from . import global_values

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

def check_args(args):
    terminate = False
    if args.debug:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO
    # global_values.logging_level = loglevel
    global_values.logfile = args.logfile

    global_values.logger = setup_logger('kernel-vulns', loglevel)

    global_values.logger.debug("ARGUMENTS:")
    for arg in vars(args):
        global_values.logger.debug(f"--{arg}={getattr(args, arg)}")
    global_values.logger.debug('')

    url = os.environ.get('BLACKDUCK_URL')
    if args.blackduck_url != '':
        global_values.bd_url = args.blackduck_url
    elif url is not None:
        global_values.bd_url = url
    else:
        global_values.logger.error("Black Duck URL not specified")
        terminate = True

    if args.project != "" and args.version != "":
        global_values.bd_project = args.project
        global_values.bd_version = args.version
    else:
        global_values.logger.error("Black Duck project/version not specified")
        terminate = True

    api = os.environ.get('BLACKDUCK_API_TOKEN')
    if args.blackduck_api_token != '':
        global_values.bd_api = args.blackduck_api_token
    elif api is not None:
        global_values.bd_api = api
    else:
        global_values.logger.error("Black Duck API Token not specified")
        terminate = True

    trustcert = os.environ.get('BLACKDUCK_TRUST_CERT')
    if trustcert == 'true' or args.blackduck_trust_cert:
        global_values.bd_trustcert = True

    if args.kernel_source_file != '':
        if not os.path.exists(args.kernel_source_file):
            global_values.logger.error(f"Supplied kernel source list file '{args.kernel_source_file}' does not exist")
            terminate = True
        else:
            global_values.kernel_source_file = args.kernel_source_file
    else:
        global_values.logger.error(f"Kernel source list file required (--kernel_source_list)")
        terminate = True

    if args.folders == 'true':
        global_values.folders = True

    if terminate:
        sys.exit(2)
    return


def setup_logger(name: str, level) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.hasHandlers():  # Avoid duplicate handlers
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        if global_values.logfile != '':
            file_handler = logging.FileHandler(global_values.logfile)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger
