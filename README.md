
# Black Duck SCA Kernel Vulnerability Processor - `bd_kernel_vulns.py` v1.0.6

## Project Status and Support

This script (`bd_kernel_vulns.py`) is provided under the [MIT license](https://www.google.com/search?q=LICENSE).

It is an **open-source utility** and does not extend the licensed functionality of Black Duck Software. It is provided "as-is," without warranty or liability.

For comments or issues, please [raise a GitHub issue here](https://github.com/blackducksoftware/bd_kernel_vulns/issues). **Black Duck Support cannot provide assistance for this OSS utility.** Users are encouraged to engage with the authors to address any identified issues.

## Overview

This script is for licensed users of Black Duck Software only. You will need access to a Black Duck SCA server and an API key to use it.

`bd_kernel_vulns` is a utility designed to **filter and remediate vulnerabilities associated with 'Linux Kernel' components** within a Black Duck SCA project version.

It works by accepting a file containing a list of your compiled kernel source files (or folders). Vulnerabilities that reference a kernel source file but **do not match** any of the files/folders in your supplied list will be automatically marked as remediated in Black Duck.

The default kernel component is `Linux Kernel`; us the argument `--kernel_comp_name NAME` to specify a different component for processing. Other components in the project will not be processed.

The default remediation status is `NOT_AFFECTED`. For Black Duck server versions older than **2025.1**, vulnerabilities will be marked as `IGNORED` instead, as the `NOT_AFFECTED` remediation status was introduced in the 2025.1 release.

## Installation

You have a few options for installing `bd_kernel_vulns`:

### Recommended: Install via pip

1.  **Create a Python virtual environment** (recommended):
    ```bash
    python3 -m venv venv_bd_kernel_vulns
    source venv_bd_kernel_vulns/bin/activate # On Windows: .\venv_bd_kernel_vulns\Scripts\activate
    ```
2.  **Install the package:**
    ```bash
    pip3 install bd_kernel_vulns --upgrade
    ```

### Install from Source (Local Build)

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/blackducksoftware/bd_kernel_vulns.git
    cd bd_kernel_vulns
    ```
2.  **Create a Python virtual environment** (recommended, see above).
3.  **Build the utility:**
    ```bash
    python3 -m build
    ```
4.  **Install the package:**
    ```bash
    pip3 install dist/bd_kernel_vulns-1.0.X-py3-none-any.whl --upgrade
    ```
    (Replace `1.0.X` with the actual version number from the built wheel file).

### Run Directly from Cloned Repository

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/blackducksoftware/bd_kernel_vulns.git
    cd bd_kernel_vulns
    ```
2.  **Ensure prerequisite packages are installed:**
    The required packages are listed in `pyproject.toml`. You can install them using:
    ```bash
    pip3 install -r requirements.txt
    ```
    (It's highly recommended to do this within a [virtual environment](https://www.google.com/search?q=%23recommended-install-via-pip)).

## Prerequisites

Before running this utility, ensure you have:

1.  **Black Duck SCA server 2024.1 or newer.**
2.  **Black Duck SCA API Access:** A user account with either `Global Project Manager` roles or `Project BOM Manager` roles for the target project.
3.  **Python 3.10 or newer.**

## How to Run

### As an Installed Package

1.  **Activate your virtual environment** where the utility was installed (if you created one).
2.  **Run the utility:**
    ```bash
    bd-kernel-vulns [OPTIONS]
    ```

### From a Cloned Repository

1.  **Activate your virtual environment** where dependency packages were installed (if you created one).
2.  **Run the utility:**
    ```bash
    python3 PATH_TO_REPOSITORY/run.py [OPTIONS]
    ```
    (Replace `PATH_TO_REPOSITORY` with the actual path to your cloned `bd_kernel_vulns` directory).

### As a Python Function

You can also integrate this utility into another Python program:

```python
from bd_kernel_vulns import main as bdkv_main

bdkv_main.process_kernel_vulns(
    blackduck_url="YOUR_BLACKDUCK_URL",
    blackduck_api_token="YOUR_API_TOKEN",
    kernel_source_file="PATH_TO_KERNEL_SOURCE_LIST.txt",
    project="YOUR_BLACKDUCK_PROJECT_NAME",
    version="YOUR_BLACKDUCK_PROJECT_VERSION_NAME",
    # Optional parameters:
    logger=None, # e.g., logging.getLogger(__name__)
    blackduck_trust_cert=True,
    remediation_status='NOT_AFFECTED',
    remediation_justification='NO_CODE',
    source_file_names_only=False
)
```

## Command Line Arguments

```
usage: bd-kernel-vulns [-h] [--blackduck_url BLACKDUCK_URL] [--blackduck_api_token BLACKDUCK_API_TOKEN]
                       [--blackduck_trust_cert] -p PROJECT -v VERSION -k KERNEL_SOURCE_FILE
                       [--folders] [--kernel_comp_name KERNEL_COMP_NAME]
                       [--remediation_status {REMEDIATION_COMPLETE,NOT_AFFECTED,MITIGATED,DUPLICATE,IGNORED,PATCHED,NEW,UNDER_INVESTIGATION,NEEDS_REVIEW,AFFECTED,REMEDIATION_REQUIRED}]
                       [--remediation_justification {NO_COMPONENT,NO_CODE,NOT_CONTROLLED,NOT_EXECUTED,ALREADY_MITIGATED,MITIGATION,NO_FIX_PLANNED,NONE_AVAILABLE,VENDOR_FIX,WORKAROUND}]
                       [--source_file_names_only]

Mark kernel vulnerabilities not within a custom kernel as remediated.

optional arguments:
  -h, --help            show this help message and exit

REQUIRED arguments:
  --blackduck_url BLACKDUCK_URL
                        Black Duck server URL (REQUIRED, can also use BLACKDUCK_URL env var)
  --blackduck_api_token BLACKDUCK_API_TOKEN
                        Black Duck API token (REQUIRED, can also use BLACKDUCK_API_TOKEN env var)
  -p PROJECT, --project PROJECT
                        Black Duck project name (REQUIRED)
  -v VERSION, --version VERSION
                        Black Duck project version name (REQUIRED)
  -k KERNEL_SOURCE_FILE, --kernel_source_file KERNEL_SOURCE_FILE
                        Path to a file containing a list of source files (or folders) within your kernel, one per line.

OPTIONAL arguments:
  --blackduck_trust_cert
                        Trust the Black Duck server certificate without validation (can use BLACKDUCK_TRUST_CERT env var)
  --folders             Treat the supplied list in --kernel_source_file as kernel source folders (default is source files).
  --kernel_comp_name KERNEL_COMP_NAME
                        Alternate name for the kernel component (default: 'Linux Kernel').
  --remediation_status {REMEDIATION_COMPLETE,NOT_AFFECTED,MITIGATED,DUPLICATE,IGNORED,PATCHED,NEW,UNDER_INVESTIGATION,NEEDS_REVIEW,AFFECTED,REMEDIATION_REQUIRED}
                        Vulnerability Remediation Status to apply (Default: NOT_AFFECTED).
  --remediation_justification {NO_COMPONENT,NO_CODE,NOT_CONTROLLED,NOT_EXECUTED,ALREADY_MITIGATED,MITIGATION,NO_FIX_PLANNED,NONE_AVAILABLE,VENDOR_FIX,WORKAROUND}
                        Vulnerability Remediation Justification (Default: NO_CODE). Only applied if remediation_status
                        is 'NOT_AFFECTED' or 'AFFECTED'.
  --source_file_names_only
                        Match only source file names from vulnerabilities against the supplied list, ignoring folder paths.
                        (Default is to match full folder paths, e.g., 'scripts/mod/file2alias.c'. Use with caution
                        as this can lead to incorrect matches if files with the same name exist in different modules).
```

## Remediation Status Logic

The utility automatically applies the default remediation status `NOT_AFFECTED` (with justification `NO_CODE`). However, if the connected Black Duck server version is **prior to 2025.1.0**, the script will automatically change the remediation status to `IGNORED` because `NOT_AFFECTED` is not available in older versions.

## Defining Kernel Source Files and Folders

The `--kernel_source_file` argument requires a text file where each line specifies a kernel source file or folder.

  * **For Source Files (default behavior):**

      * Each line should include the full path of the source file, ending with the correct extension (e.g., `scripts/mod/file2alias.c`).
      * Use forward slashes (`/`) as folder separators.
      * Use the `--source_file_names_only` option to match only the base file name, ignoring the full path. **Use this option with caution**, as it can lead to false positives if different kernel modules contain files with the same name.

  * **For Source Folders (`--folders` option):**

      * Each line should contain a kernel source folder (e.g., `scripts`, `mod`, or `scripts/mod`).
      * Leading and trailing `/` separators are not required.
      * A vulnerability referencing a file like `scripts/mod/file2alias.c` will match against the folders `scripts`, `mod`, or `scripts/mod` if they are in your supplied list.

## Obtaining Kernel Source File Lists

Here are methods to generate the `kernel_source_file` list for your specific kernel build:

### From a Running Linux Image

You can use `lsmod` and `modinfo` to report compiled objects in your running kernel:

```bash
lsmod | while read module otherfields
do
    modinfo $module | grep '^filename:' | sed -e 's/filename:  *//g' -e 's/\.ko\.zst//g'
done > kfiles.lst
```

### From a Yocto Build

The [bd\_scan\_yocto\_via\_sbom](https://github.com/blackducksoftware/bd_scan_yocto_via_sbom) utility is the recommended way to scan Yocto projects. Its `--process_kernel_vulns` option directly calls this utility to filter kernel vulnerabilities.

If you prefer to use `bd_kernel_vulns` directly on a Yocto project:

1.  **Locate the modules image archive file** for your specific build (usually under `poky/build/tmp/deploy/images/`).
      * Example filename: `modules--6.12.31+git0+f2f3b6cbd9_fee8195f84-r0-qemux86-64-20250608200614.tgz`
2.  **Extract the list of modules** from the archive:
    ```bash
    tar tf YOUR_MODULES_ARCHIVE_FILE.tgz | grep '.ko$' | sed -e 's/\.ko$/.c/g' > kfiles.lst
    ```

### From a Buildroot Build

1.  **Locate the Kernel Build Directory:**
      * Example: `<buildroot_root_directory>/output/build/linux-<kernel_version>/`
2.  **Identify Compiled Object Files (`.o` files):**
    ```bash
    find <buildroot_root_directory>/output/build/linux-<kernel_version>/ -name "*.o" | sed -e 's/\.o$/.c/g' > kfiles.lst
    ```
