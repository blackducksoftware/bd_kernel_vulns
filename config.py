import os
import argparse
import sys
import logging

import global_values

parser = argparse.ArgumentParser(description='Black Duck vulns', prog='bd_vulns')

# parser.add_argument("projfolder", nargs="?", help="Yocto project folder to analyse", default=".")

parser.add_argument("--blackduck_url", type=str, help="Black Duck server URL (REQUIRED)", default="")
parser.add_argument("--blackduck_api_token", type=str, help="Black Duck API token (REQUIRED)", default="")
parser.add_argument("--blackduck_trust_cert", help="Black Duck trust server cert", action='store_true')
parser.add_argument("-p", "--project", help="Black Duck project to create (REQUIRED)", default="")
parser.add_argument("-v", "--version", help="Black Duck project version to create (REQUIRED)", default="")
parser.add_argument("--debug", help="Debug logging mode", action='store_true')
parser.add_argument("--logfile", help="Logging output file", default="")

args = parser.parse_args()

def check_args():
    terminate = False
    # if platform.system() != "Linux":
    #     print('''Please use this program on a Linux platform or extract data from a Yocto build then
    #     use the --bblayers_out option to scan on other platforms\nExiting''')
    #     sys.exit(2)
    if args.debug:
        global_values.debug = True
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO

    if args.logfile != '':
        if os.path.exists(args.logfile):
            logging.error(f"Specified logfile '{args.logfile}' already exists - EXITING")
            sys.exit(2)
        logging.basicConfig(encoding='utf-8',
                            handlers=[logging.FileHandler(args.logfile), logging.StreamHandler(sys.stdout)],
                            level=loglevel)
    else:
        logging.basicConfig(level=loglevel)

    logging.info("ARGUMENTS:")
    for arg in vars(args):
        logging.info(f"--{arg}={getattr(args, arg)}")
    logging.info('')

    url = os.environ.get('BLACKDUCK_URL')
    if args.blackduck_url != '':
        global_values.bd_url = args.blackduck_url
    elif url is not None:
        global_values.bd_url = url
    else:
        logging.error("Black Duck URL not specified")
        terminate = True

    if args.project != "" and args.version != "":
        global_values.bd_project = args.project
        global_values.bd_version = args.version
    else:
        logging.error("Black Duck project/version not specified")
        terminate = True

    api = os.environ.get('BLACKDUCK_API_TOKEN')
    if args.blackduck_api_token != '':
        global_values.bd_api = args.blackduck_api_token
    elif api is not None:
        global_values.bd_api = api
    else:
        logging.error("Black Duck API Token not specified")
        terminate = True

    trustcert = os.environ.get('BLACKDUCK_TRUST_CERT')
    if trustcert == 'true' or args.blackduck_trust_cert:
        global_values.bd_trustcert = True

    if terminate:
        sys.exit(2)
    return
