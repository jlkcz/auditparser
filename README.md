#Dateparser
Dateparser is simple parser for auditd log files which is only interested in AppArmor lines. It outputs nice sysadmin friendly summaries:

```
===== profile apache2//DEFAULT_URI ======
|   count | operation   | content                        | apparmor   |       time |
|---------|-------------|--------------------------------|------------|------------|
|       1 | file_perm   | /var/log/custom.access.log (w) | ALLOWED    | 1616222101 |
|       1 | file_perm   | /var/log/custom.error.log (w)  | ALLOWED    | 1616196074 |

===== profile php-fpm5.6//myapp ======
|   count | operation   | content                       | apparmor   |       time |
|---------|-------------|-------------------------------|------------|------------|
|      18 | open        | /home/www/myapp/index.php (r) | ALLOWED    | 1616190632 |
```


## How to use
Launching auditparser without arguments offers sane defaults (prints all lines in the last 24 hours). This was the original use-case, cronjob that tells admin what has happened in the last 24 hours.

It can however be used in more ways:

### Filtering
```
auditparser --profile profilename
```
shows all the lines for profile named profilename. 

Also, you can filter by Python regexes:
```
auditparser --regex 'apache2//(.+)\.(.+)'
```
This command will print all apache2 hat profiles that are structured at least a bit as a domain name (have dot inside)

### Profile development
Sometimes, you are developing a new profile and want to see what else you need to add to your profile. `aa-logprof` is certainly a better option, but using this is nice as well (this syntax needs dateparser, see Dependencies)
```
auditparser --since 10m --profile my-new-app
```
this will show all lines for my-new-app profile in the last 10 minutes

### Very simple fixing machine
option `--fix` offers a simple suggestion which line will fix current errors. However, this is very naive and using your own thinking before adding those lines to you AppArmor profile is highly suggested.

### More
See `auditparser --help`

## Why?
Reading audit.log sucks and filtering it sucks even more. Especially, if you are using AppArmor because `ausearch` or `aureport` because old bugs no-one appears to be solving. See for example https://bugs.launchpad.net/ubuntu/+source/audit/+bug/1117804 

## Installation
Simply download or clone this repo, auditparser should start working. See section Dependencies if you want nicer behaviour

## Dependencies
Auditparser can live without any dependencies outside Python stdlib. However, for easy of use there are two external deps that are nice to have:

* [Tabulate](https://github.com/astanin/python-tabulate) for tabular output of data
* [Dateparser](https://github.com/scrapinghub/dateparser) for much more user friendly data parsing

If those dependencies are not available, script will fallback to other less nice but working behaviour. You can add both in Debian by simply installing them with apt
```
apt install python3-tabulate python3-dateparser
```

Auditparser is primarily developed for Python 3.9 (Debian bullseye) but works with Python3.8 as well

##Shortcomings
Currently does not manage to read all lines possibly emitted by AppArmor. If you want more, send patches or use parser provided by AppArmor itself. It is also in Python, see https://gitlab.com/apparmor/apparmor/-/blob/master/utils/apparmor/logparser.py


