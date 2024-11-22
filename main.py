import global_values
from BOMClass import BOM
import config

def main():
    config.check_args()

    bom = BOM(global_values.bd_project, global_values.bd_version)

    bom.get_vulns()
    bom.print_vulns()


if __name__ == '__main__':
    main()
