# Black Duck SCA Kernel Vuln Processor - bd_kernel_vulns.py v1.0.2

# PROVISION OF THIS SCRIPT
This script is provided under the MIT license (see LICENSE file).

It does not represent any extension of licensed functionality of Black Duck Software itself and is provided as-is, without warranty or liability.

If you have comments or issues, please raise a GitHub issue here. Black Duck support is not able to respond to support tickets for this OSS utility. Users of this pilot project commit to engage properly with the authors to address any identified issues.

# INTRODUCTION
## OVERVIEW OF BD_KERNEL_VULNS

This utility accepts a file containing compiled kernel source files (or folders) to filter
the vulnerabilities associated with the Linux Kernel component in a 
Black Duck SCA project version.

Vulnerabilities which reference a kernel source file or package, but which do not match files/folders 
in the supplied kernel source file will be marked as ignored.

## INSTALLATION

1. Create virtualenv
2. Run `pip3 install bd_kernel_vulns --upgrade`

Alternatively, if you want to build and install the utility locally:

1. clone the repository
2. Create virtualenv
3. Build the utility `python3 -m build`
4. Install the package `pip3 install dist/bd_kernel_vulns-1.0.X-py3-none-any.whl --upgrade`

Alternatively, clone the repository locally:

1. Clone the repository
2. Ensure prerequisite packages are installed (see list in pyproject.toml)

## PREREQUISITES

1. Black Duck SCA server 2024.1 or newer
2. Black Duck SCA API with either Global Project Manager roles or Project BOM Manager roles for an existing project
3. Python 3.10 or newer

## HOW TO RUN

If you installed the utility as a package:

1. Invoke virtualenv where utility was installed
2. Run `bd-kernel-vulns OPTIONS`

Alternatively, if you have cloned the repository locally:

1. Invoke virtualenv where dependency packages were installed
2. Run `python3 PATH_TO_REPOSITORY/run.py OPTIONS`

## COMMAND LINE OPTIONS

      usage: bd-scan-yocto-via-sbom [-h] [--blackduck_url BLACKDUCK_URL] [--blackduck_api_token BLACKDUCK_API_TOKEN] [--blackduck_trust_cert] [-p PROJECT] [-v VERSION] <OTHER OPTIONS>

      Create BD Yocto project from license.manifest
      
     -h, --help            show this help message and exit

    REQUIRED:
     --blackduck_url BLACKDUCK_URL
            Black Duck server URL (REQUIRED - will also use BLACKDUCK_URL env var)
     --blackduck_api_token BLACKDUCK_API_TOKEN
            Black Duck API token (REQUIRED - will also use BLACKDUCK_API_TOKEN env var)
     -p PROJECT, --project PROJECT 
            Black Duck project to create (REQUIRED)
     -v VERSION, --version VERSION
            Black Duck project version to create (REQUIRED)
    -k KERNEL_SOURCE_FILE, --kernel_source_file KERNEL_SOURCE_FILE
            File containing list of source files (or folders) within the kernel (one per line).

    OPTIONAL:
     --blackduck_trust_cert
            Black Duck trust server cert (can use BLACKDUCK_TRUST_CERT env var)
     --folders
            Supplied list is kernel source folders (not source files)
     --kernel_comp_name
            Alternate kernel component name (default 'Linux Kernel')

## OBTAINING KERNEL SOURCE FILES

### FROM RUNNING LINUX IMAGE

The `lsmod` and `modinfo` commands can be used to report the compiled objects in the running kernel.

An example bash script to produce the list of kernel source files is shown below:

    lsmod | while read module otherfields
    do
        modinfo $module | grep '^filename:' | sed -e 's/filename:  *//g' -e 's/\.ko\.zst//g'
    done > kfiles.lst

### FROM YOCTO BUILD

The [bd_scan_yocto_via_sbom](https://github.com/blackducksoftware/bd_scan_yocto_via_sbom) utility is recommended to 
scan Yocto projects, and the `--process_kernel_vulns` option will call this utility to filter kernel vulnerabilities.

However, if not using this script then processing the module image archive can generate the list of compiled source
files as follows:

1. Locate the modules image archive file for the specific build (usually beneath the poky/build/tmp/deploy/images folder - for example `modules--6.12.31+git0+f2f3b6cbd9_fee8195f84-r0-qemux86-64-20250608200614.tgz`)
2. Extract the list of modules from the file using `tar tf FILE | grep '.ko$' | sed -e 's/\.ko$/.c/g' > kfiles.lst`

### FROM BUILDROOT BUILD

1. Locate the Kernel Build Directory - for example _<buildroot_root_directory>/output/build/linux-<kernel_version>/_
2. Identify Compiled Object Files (.o files) by running `find <buildroot_root_directory>/output/build/linux-<kernel_version>/ -name "*.o" | sed -e 's/\.o$/.c/g' > kfiles.lst`