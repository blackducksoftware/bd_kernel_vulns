# bd-kernel-vulns - v1.0.1
Script using a list of compiled kernel sources in a file to process vulns within 
the Linux Kernel component in a BD project version, identify vulns which reference kernel source files
whicih are not in the supplied file 

## PROVISION OF THIS SCRIPT
This script is provided under the MIT OSS license (see LICENSE file).
It does not represent any extension of licensed functionality of Synopsys software itself and is provided as-is, without warranty or liability.
If you have comments or issues, please raise a GitHub issue here. Synopsys support is not able to respond to support tickets for this OSS utility. Users of this pilot project commit to engage properly with the authors to address any identified issues.

## INTRODUCTION
Black Duck Signature matching is a unique and powerful way to find OSS and 3rd party code within your applications and
environments.

Signature matching uses hierarchical folder analysis to find matches with depth, identifying the most likely components
matching the project by examining all files in all folders as a whole.
Many competitive SCA solutions use individual file matching for files in the project, but this is not absolutely suitable 
to identify component matches because the majority of files in components do not change between versions, 
so multiple version matches will be identified for every file. It is therefore impossible to infer an overall component
version by looking at the individual files.

However, Signature matching can still produce false positive matches, especially where template code hierarchies 
exist in custom and OSS code.

Furthermore, Signature matches can be identified in folders created by Synopsys tools, or in cache/config
locations or test folders; these folders can be ignored at scan time, but can exist in the Black Duck project and need to 
be removed after scan completion. Additionally, when scanning
modified OSS, Signature scanning can identify the same component with multiple versions from a single project
location, with the need to curate the BOM to ignore duplicate components.

This script uses several techniques to examine the Signature match paths for components, searching for the component
name and version in the path to determine matches which are likely correct and optionally marking them as reviewed.

It can also ignore components only matched from paths which should be excluded (Synopsys tools, cache/config folders 
and test folders), and components which are duplicates across versions where the version string is not found
in the signature match path, one match is a dependency or where they are simply duplicates (same component name and version
but shown in the BOM as separate entries).

Options are available to enable ignore and review actions, and other features.

## PREREQUISITES
Python 3.8+ must be installed prior to using this script.

## INSTALLATION
The package can be installed using the command:

    python3 -m pip install bd-sig-filter

Upgrade from a previous version using:

    python3 -m pip install bd-sig-filter --upgrade

Alternatively, the repository can be cloned and the script run directly using the command:

    python3 bd_sig_filter/bd_sig_filter.py OPTIONS

## USAGE
If installed as a package, run the utility using the command `bd-sig-filter`.

Alternatively if you have cloned the repo, use a command similar to:

    python3 bd_sig_filter/bd_sig_filter.py OPTIONS

The package can be invoked as follows:

    usage: bd-sig-filter [-h] [--blackduck_url BLACKDUCK_URL] [--blackduck_api_token BLACKDUCK_API_TOKEN] [--blackduck_trust_cert] [-p PROJECT] [-v VERSION] [--debug] [--logfile LOGFILE]
                         [--report_file REPORT_FILE] [--version_match_reqd] [--ignore] [--review] [--no_ignore_test] [--no_ignore_synopsys] [--no_ignore_defaults]
                         [--ignore_no_path_matches] [--ignore_archive_submatches]

    options:
      -h, --help            show this help message and exit 
      --blackduck_url BLACKDUCK_URL
                            Black Duck server URL (REQUIRED)
      --blackduck_api_token BLACKDUCK_API_TOKEN
                            Black Duck API token (REQUIRED)
      --blackduck_trust_cert
                            Black Duck trust server cert
      -p PROJECT, --project PROJECT
                            Black Duck project to create (REQUIRED)
      -v VERSION, --version VERSION
                            Black Duck project version to create (REQUIRED)
      --debug               Debug logging mode
      --logfile LOGFILE     Logging output file
      --report_file REPORT_FILE
                            Report output file
      --version_match_reqd  Component matches require version string in path
      --ignore              Ignore components in synopsys, default or test folders and duplicates with wrong version
      --review              Mark components reviewed
      --no_ignore_test      Do not ignore components in test folders
      --no_ignore_synopsys  Do not ignore components in synopsys tool folders
      --no_ignore_defaults  Do not ignore components in default folders
      --ignore_no_path_matches
                            Also ignore components with no component/version match in signature path
                            (Use with caution)
      --report_unmatched    Report the list of components which will be left Unreviewed and why - these may need
                            to be manually reviewed.
      --ignore_archive_submatches
                            Process components to determine sub-matches within archives.

The minimum required options are:
    
    --blackduck_url https://BLACKDUCK_SERVER_URL
    --blackduck_api_token BLACKDUCK_API_TOKEN
    --project PROJECT
    --version VERSION

Environment variables BLACKDUCK_URL, BLACKDUCK_API_TOKEN and BLACKDUCK_TRUST_CERT may also be used.

## SCRIPT BEHAVIOUR
The default behaviour of the script is to create a table of BOM components with details about what actions can be taken.
By default, no actions will be taken, with only the tables being created to explain what would happen if `--ignore` and `--review`
options were specified.

An example of the output table is shown below:

    SUMMARY:
              Components    Ignored    Reviewed    Neither
    ------  ------------  ---------  ----------  ---------
    Before           641          0           0        641
    After            641         24         615          2
    
    Component                             Match Type    Ignored    Reviewed    To be Ignored    To be Reviewed    Action
    ------------------------------------  ------------  ---------  ----------  ---------------  ----------------  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    aggs-matrix-stats/1.3.14              Dep+Sig       False      False       False            True              Mark REVIEWED - Dependency
    aggs-matrix-stats/2.11.1              Sig           False      False       False            True              Mark REVIEWED - Compname & version in path '/Plugins/ActOnePluginInstaller/image/actone-plugins-installer 10.0.0.67/RCM_Plugins/actOne-opensearch-2.x-connector/lib/aggs-matrix-stats-client-2.11.1.jar', Match result 200
    aircompressor/0.10                    Dep+Sig       False      False       False            True              Mark REVIEWED - Dependency
    Amazon MSK Library for AW/2.0.2       Dep+Sig       False      False       False            True              Mark REVIEWED - Dependency
    Apache HttpComponents Cor/5.2.4       Sig           False      False       True             False             Mark IGNORED - compname or version not found in paths & --ignore_no_path_matches set
    WSDL4J/1.5.1                          Sig           False      False       False            False             No Action
    Xalan Java Serializer/2.7.2           Sig           False      False       False            False             No Action - Is a duplicate of dependency 'Xalan Java Serializer/2.7.3', has different component id/version but version found in sigpaths
    Xalan Java Serializer/2.7.3           Dep           False      False       False            True              Mark REVIEWED - Dependency

Note component names are truncated at 25 characters.

The `Before` and `After` rows in the SUMMARY list the total number of components, and how many components would be ignored or
marked reviewed by the script (if the `--ignore` and `--review` options are supplied).

The list of components shows the name, matchtypes and current ignore/review statuses, with the future status
(after running the script with the `--ignore` and `--review` options) in the `To Be Ignored` and `To Be Reviewed` 
columns with an explanation in the `Action` column.

The `Match Score` value shows the result of fuzzy match searching for component name and version strings (note that
origin component ID is used where available as opposed to the textual name of the component). A score of 200 shows
an exact match of both component name and version in Signature paths; a lower value shows the possibility of less
accurate matching.

Options can be used to modify the behaviour of the script as follows:

`--no_ignore_test`:
        Stops components matched only by Signature scanning and containing test folders (test, tests,
        testsuite or testsuites - case insensitive) being marked for ignore (which happens by default).

`--no_ignore_synopsys`:
        Stops components matched only by Signature scanning and containing Synopsys tools folders (.synopsys,
        synopsys-detect, .coverity, synopsys-detect.\*.jar, scan.cli.impl-standalone.jar, seeker-agent.\*,
        Black_Duck_Scan_Installation - case insensitive) being marked for ignore (which happens by default).

`--no_ignore_defaults`:
        Stops components matched only by Signature scanning and containing default folders (.cache, 
        .m2, .local, .config, .docker, .npm, .npmrc, .pyenv, .Trash, .git, node_modules - case insensitive)
        being marked for ignore (which happens by default).

`--version_match_required`:
        Enforce search for component version string in signature paths for marking components reviewed
        (Paths containing only the component name will be used for matching otherwise)

`--ignore_no_path_matches`:
        Components with no match in the signature path are left unreviewed by default, allowing
        manual review. Use this option to ignore these components instead but use with caution
        as it may exclude components which are legitimate (the Signature match path does not
        have to include the component name or version).

`--report_unmatched`:
        Create a list of Signature components which will be left UNreviewed 

`--ignore_archive_submatches`:
        Process components in the project version looking for those matched within
        archive files, and report which can be ignored because they are sub-matches (from folders within the archive).
        All other operations are replaced by this action.

The options `--report_file` and `--logfile` can be used to output the tabular report and logging data to
specified files.

## PROPOSED WORKFLOW
The script can be used to classify Signature scan results.

It can mark components as reviewed which are either Dependencies, or which have Signature match paths containing
the component name (and optionally component version) and which are therefore highly likely to be correctly identified
by Signature matching.

It can also ignore components only Signature matched within extraneous folders (for example created by Synopsys tools, 
config/cache folders or test folders).

Components shown with `No action` are Signature matches where the component name or version 
could not be identified in the signature paths, so they are potential false matches and require manual review.

After running the script and ignoring/reviewing components (using options `--ignore --review`), review the reported
list of components from the script focussing on those marked with `No Action`. Optionally use the option `--report_unmatched`
to list the `No Action` components with the full list of Signature match paths to enable assessment whether they should
be included in the BOM.

If, after inspection, all `No Action` components can be removed from the BOM, the `--ignore_no_path_matches` option can be used to
ignore these components automatically, however this should be used with caution as these components may be valid 
and should be manually reviewed.

## PROCESSING DUPLICATE COMPONENTS
The script processes multiple versions of the same component in the BOM in several ways as described below:

### SCENARIO 1
- Comp1 and Comp2 are different versions of the same component
- Comp1 and Comp2 are BOTH dependencies

Outcome:
- Comp1 will be marked REVIEWED
- Comp2 will be marked REVIEWED

### SCENARIO 2
- Comp1 and Comp2 are different versions of the same component
- Comp1 is a dependency and Comp2 is a signature match
- Comp2 name IS found but version string is NOT found in the Signature match paths

Outcome:
- Comp1 will be marked REVIEWED
- Comp2 will be marked IGNORED

### SCENARIO 3
- Comp1 and Comp2 are different versions of the same component
- Comp1 is a dependency and Comp2 is a signature match
- Comp2 name and version strings ARE found in the Signature match paths

Outcome:
- Comp1 will be marked REVIEWED
- Comp2 will be marked REVIEWED

### SCENARIO 4
- Comp1 and Comp2 are different versions of the same component
- Comp1 and Comp2 are both signature matches
- Comp1 name and version strings ARE both found in the Signature match paths
- Comp2 name IS found but version string is NOT found in the Signature match paths

Outcome:
- Comp1 will be marked REVIEWED
- Comp2 will be IGNORED

### SCENARIO 5
- Comp1 and Comp2 are different versions of the same component
- Comp1 and Comp2 are both signature matches
- Comp1 name string IS found but version string is NOT found in the Signature match paths
- Comp2 name string IS found but version string is NOT found in the Signature match paths

Outcome:
- Comp1 will be marked REVIEWED
- Comp2 will be left unignored and not reviewed - for manual review
