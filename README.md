# CVE SearchSploit Extended
> Extended Version of CVE SearchSploit written by Andrea Fioraldi https://github.com/andreafioraldi/cve_searchsploit

> version 1.6a

Search an exploit in the local exploitdb database by its CVE.

Here you can get a free cve to exploit-db mapping in json format.

**NEW** Added support to load debcvescan scan report in json format.

**NEW** Added support to load dependencycheck report in json format.


## Install

#### from PyPI

```
$ pip3 install cve_searchsploit
```

#### from GitHub

```
$ git clone https://github.com/rmtec/cve_searchsploit
$ cd cve_searchsploit
$ python3 setup.py install
```

#### Requirements

+ python3
+ requests
+ progressbar2
+ git

## Usage
```
$ cve_searchsploit [parameters...]
```

#### Parameters
+  ```<cve>```                      search exploits by a cve
+  ```-u```                         update the cve-edbid mapping
+  ```-f <file with cve list>```    search exploits by a cve list file
+  ```-n <nessus csv scan file>```  search exploits by the cve matching with a nessus scan in csv format
+  ```-j <debcvescan json report>```  search exploits by debcvescan json report *NEW*

### As a library

```python
>>> import cve_searchsploit as CS
>>> 
>>> CS.update_db()
Refreshing exploit-database repo with lastest exploits
From https://github.com/offensive-security/exploit-database
 * branch                master     -> FETCH_HEAD
Already up to date.
Refreshing EDBID-CVE mapping
100% (41823 of 41823) |##############| Elapsed Time: 0:00:00 Time:  0:00:00
>>> 
>>> CS.edbid_from_cve("CVE-2019-0708")
[46946, 47120, 47416]
>>> CS.cve_from_edbid(47120)
['CVE-2019-0708']
```

### Check Debian for known vulnerabilities **NEW**
Check the installed packages of your Debian Linux distribution against known vulnerabilities of the Debian Security Bug Tracker https://security-tracker.debian.org/tracker

1. Install https://github.com/devmatic-it/debcvescan
2. Export scan report to json: ```debcvescan scan --format=json```

### OWASP Dependency check for known vulnerabilties **NEW**
Check you project's dependencies for known vulnerabilties

1. Install https://github.com/jeremylong/DependencyCheck
2. Export scan report to json ```sh dependency-check.sh -f json --project check -s [path to jar files to be scanned]```

## Cite

If you use this tool in your academic work you can cite it using

```bibtex
@Misc{cve_searchsploit,
  author       = {Andrea Fioraldi},
  howpublished = {GitHub},
  month        = jun,
  title        = {{CVE SearchSploit}},
  year         = {2017},
  url          = {https://github.com/andreafioraldi/cve_searchsploit},
}
```
