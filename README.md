# cloudflare-dns

CLI and Python tool for managing Cloudflare DNS

https://github.com/ZigZagT/cloudflare-dns

[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/cloudflare-dns)](https://pypi.org/project/cloudflare-dns/)

## Installation
```bash
pip install cloudflare-dns
```

## Usage
```
usage: cloudflare-dns [-h] [--ignore-api-error] [-z ZONE] [-e EMAIL] [-k KEY] [-t TOKEN] (-lz | -lr | -sr | -dr) [--filter-content REGEX] [--proxied] [{A,AAAA,CNAME,TXT,ANY}] [domain] [content] [ttl]

options:
  -h, --help            show this help message and exit
  --ignore-api-error    treat 5xx API responses as success
  -lz, --list-zone      [action] list zones, record frags and filters are ignored for this action
  -lr, --list-record    [action] list DNS records in a zone, record frags are used as filters when provided
  -sr, --set-record     [action] create or update DNS record to match record frags, removes any existing records that matches the [type, domain] tuple; use the filters to limit the removing to matching records only
  -dr, --delete-record  [action] delete DNS record base on provided record frags and filters

authentication arguments:
  -z ZONE, --zone ZONE  specify the zone by its domain name, usually can be inferred from the domain parameter
  -e EMAIL, --email EMAIL
                        default to environment variable CF_API_EMAIL
  -k KEY, --key KEY     default to environment variable CF_API_KEY
  -t TOKEN, --token TOKEN
                        default to environment variable CF_API_TOKEN. Note the use of api token is exclusive, --email and --key must not be used when --token is used.

filtering arguments:
  scope operations of changing / removing records by the filters

  --filter-content REGEX
                        filter records by matching their content against the provided regex.

record frags:
  use record frags to describes a single DNS record, may freely provide from 0 to all 5 frags, as long as it makes sense to the chosen action

  {A,AAAA,CNAME,TXT,ANY}
                        record type, ANY is only valid for filtering
  domain                full qualified domain name
  content               the content of the record
  ttl                   ttl value of 1 means auto on Cloudflare; ignored for -lr and -dr
  --proxied             set cloudflare proxy on/off state; ignored for -lr and -dr
```

## Examples of typical Usages

### Dynamic DNS (DDNS)

```bash
IP=$(curl -sL https://ipinfo.io/ip)

cloudflare-dns -sr A dev.example.com $IP
cloudflare-dns -sr A www.example.com $IP --proxied
cloudflare-dns -sr A long-dns-ttl.example.com $IP 36000 --proxied
```

### Show all TXT records at root domain

```bash
cloudflare-dns -lr TXT example.com

# records:
# -------------------------------------------------------------------------------
#     id: aaaa
#     type: TXT
#     name: example.com
#     content: google-site-verification=aaaa
#     ttl: 1
#     proxiable: False
#     proxied: False
#     locked: False
# -------------------------------------------------------------------------------
#     id: bbbb
#     type: TXT
#     name: example.com
#     content: v=spf1 include:_spf.google.com ~all
#     ttl: 1
#     proxiable: False
#     proxied: False
#     locked: False
# -------------------------------------------------------------------------------
```

### Show SPF TXT record at root domain

```bash
cloudflare-dns -lr TXT example.com --filter-content v=spf1

# records:
# -------------------------------------------------------------------------------
#     id: bbbb
#     type: TXT
#     name: example.com
#     content: v=spf1 include:_spf.google.com ~all
#     ttl: 1
#     proxiable: False
#     proxied: False
#     locked: False
# -------------------------------------------------------------------------------
```

### Update a SPF TXT records at root domain
```bash
cloudflare-dns -sr TXT example.com 'v=spf1 include:_spf.google.com ~all' --filter-content v=spf1

# UNCHANGED: example.com v=spf1 include:_spf.google.com ~all
```

### Batch update DMARC records for multiple sites
```bash
  for domain in $(cat my_domains.txt); do
    cloudflare-dns -sr --filter-content v=DMARC1 \
        TXT \
        _dmarc.$domain \
        "v=DMARC1; p=quarantine; fo=0:1:d:s; rua=mailto:dmarc@$domain; ruf=mailto:dmarc@$domain; aspf=r; adkim=s;" \
        3600
  done
```


## How to authenticate with the Cloudflare API:

```bash
# option 1: by using environment variables
export CF_API_EMAIL="<my cloudflare email>"
export CF_API_KEY="<my cloudflare api key>"
cloudflare-dns -sr A dev.example.com $IP
```

```bash
# option 2: via command line parameters
cloudflare-dns -e $MY_EMAIL -k $MY_KEY -sr A dev.example.com $IP
```
