import os
import re
from sys import stderr

from CloudFlare import CloudFlare
from . import get_zones, infer_zone, get_records


def list_zones(cf, args):  # cli entrance
    print('zones:')
    delimiter = "-" * 79
    print(delimiter)
    for zone in get_zones(cf):
        for key in [
            'id', 'name', 'status', 'paused', 'type'
        ]:
            print('    {}: {}'.format(key, zone.get(key, 'N/A')))
        print(delimiter)
    return 0


def list_records(cf, args):  # cli entrance
    zone = None
    if args.domain:
        zone = infer_zone(cf, args.domain)
    elif args.zone:
        zones = get_zones(cf, args.zone)
        try:
            zone = next(zones)
        except StopIteration:
            raise LookupError('invalid zone {}'.format(args.zone)) from None
        try:
            next(zones)
        except StopIteration:
            pass
        else:
            raise LookupError('unable to determine zones for {}'.format(args.zone))
    if not zone:
        print('a valid zone or domain must be provided for listing records', file=stderr)
        return 1

    print('records:')
    delimiter = "-" * 79
    print(delimiter)
    for record in get_records(
            cf, zone['id'],
            args.type,
            args.domain,
            args.content,
            args.filter_content
    ):
        for key in [
            'id', 'type', 'name', 'content', 'ttl', 'proxiable', 'proxied', 'locked'
        ]:
            print('    {}: {}'.format(key, record.get(key, 'N/A')))
        print(delimiter)
    return 0


def set_record(cf, args):  # cli entrance
    domain = args.domain
    content = args.content
    r_type = args.type
    ttl = args.ttl or 1  # 1 is a special value for auto / default on CF
    if args.zone:
        zones = get_zones(cf, args.zone)
        zone = next(zones)
        try:
            next(zones)
        except StopIteration:
            pass
        else:
            raise LookupError('expecting one but found multiple zones for {}'.format(args.zone))
    else:
        zone = infer_zone(cf, domain)

    records_to_remove = []
    record_to_update = None
    for dns_record in get_records(cf, zone['id'], r_type, domain, filter_content=args.filter_content):
        if not record_to_update and dns_record['name'] == domain:
            record_to_update = dns_record
            continue
        records_to_remove.append(dns_record)

    for record in records_to_remove:
        print('REMOVED: %s %s' % (record['name'], record['content']))
        cf.zones.dns_records.delete(zone['id'], record['id'])

    if record_to_update:
        if (
                record_to_update['content'] == content
                and record_to_update['type'] == r_type
                and record_to_update['ttl'] == ttl
                and record_to_update['proxied'] == args.proxied
        ):
            print('UNCHANGED: %s %s' % (domain, content))
        else:
            data = {
                k: v
                for k, v in record_to_update.items()
                if k in ('meta', 'data', 'proxied')
            }
            data.update({
                'name': domain,
                'type': r_type,
                'content': content,
                'ttl': ttl,
                'proxied': args.proxied,
            })
            cf.zones.dns_records.put(zone['id'], record_to_update['id'], data=data)
            print('UPDATED: %s %s -> %s' % (domain, record_to_update['content'], content))
    else:
        cf.zones.dns_records.post(zone['id'], data={
            'name': domain,
            'type': r_type,
            'content': content,
            'ttl': ttl,
            'proxied': args.proxied,
        })
        print('CREATED: %s %s' % (domain, content))


def delete_record(cf, args):  # cli entrance
    zone = None
    if args.domain:
        zone = infer_zone(cf, args.domain)
    elif args.zone:
        zones = get_zones(cf, args.zone)
        try:
            zone = next(zones)
        except StopIteration:
            raise LookupError('invalid zone {}'.format(args.zone)) from None
        try:
            next(zones)
        except StopIteration:
            pass
        else:
            raise LookupError('unable to determine zones for {}'.format(args.zone))
    if not zone:
        print('a valid zone or domain must be provided for listing records', file=stderr)
        return 1

    has_removes = False
    for record in get_records(
            cf, zone['id'],
            args.type,
            args.domain,
            args.content,
            args.filter_content
    ):
        has_removes = True
        print('REMOVED: %s %s' % (record['name'], record['content']))
        cf.zones.dns_records.delete(zone['id'], record['id'])

    if not has_removes:
        print('No record to remove')


def regex_type(s):
    return re.compile(s, re.IGNORECASE)


def main():
    from argparse import ArgumentParser, RawDescriptionHelpFormatter
    parser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter)

    authn_args_group = parser.add_argument_group('authentication arguments')
    authn_args_group.add_argument(
        '-z', '--zone', type=str,
        help='optionally specify the zone, auto inferred from the domain parameter if not provided')
    authn_args_group.add_argument(
        '-e', '--email', type=str, default=os.environ.get('CF_API_EMAIL'),
        help='default to environment variable CF_API_EMAIL')
    authn_args_group.add_argument(
        '-k', '--key', type=str, default=os.environ.get('CF_API_KEY'),
        help='default to environment variable CF_API_KEY')

    actions_group = parser.add_mutually_exclusive_group(required=True)
    actions_group.add_argument(
        '-lz', '--list-zone', action='store_const', const=list_zones, dest='entrance',
        help='[action] list zones, record frags and filters are ignored for this action'
    )
    actions_group.add_argument(
        '-lr', '--list-record', action='store_const', const=list_records, dest='entrance',
        help='[action] list DNS records in a zone, record frags are used as filters when provided'
    )
    actions_group.add_argument(
        '-sr', '--set-record', action='store_const', const=set_record, dest='entrance',
        help='[action] create or update DNS record to match record frags, '
             'removes any existing records that matches the [type, domain] tuple; '
             'use the filters to limit the removing to matching records only'
    )
    actions_group.add_argument(
        '-dr', '--delete-record', action='store_const', const=delete_record, dest='entrance',
        help='[action] delete DNS record base on provided record frags and filters'
    )

    filter_args_group = parser.add_argument_group(
        'filters',
        'limit any operations to only records matches the filters'
    )
    filter_args_group.add_argument(
        '--filter-content', type=regex_type, metavar="REGEX",
        help='filter records by matching their content against the provided regex.'
    )

    record_frags_group = parser.add_argument_group(
        'record frags',
        'use record frags to describes a single DNS record, you may freely provide from 0 to all 5 frags, '
        'as long as it makes sense to the chosen action'
    )
    record_frags_group.add_argument('type', choices=['A', 'AAAA', 'CNAME', 'TXT', 'ANY'], nargs='?', help='record type')
    record_frags_group.add_argument('domain', type=str, nargs='?', help='full qualified domain name')
    record_frags_group.add_argument('content', type=str, nargs='?', help='the content of the record')
    record_frags_group.add_argument('ttl', type=int, nargs='?',
                                    help='ttl value of 1 means auto on Cloudflare; ignored for -lr and -dr')
    record_frags_group.add_argument('--proxied', action='store_true',
                                    help='set cloudflare proxy on/off state; ignored for -lr and -dr')

    args = parser.parse_args()

    if args.email is None or args.key is None:
        print('email and api key are needed', file=stderr)
        return 1

    cf = CloudFlare(email=args.email, token=args.key, raw=True)

    return args.entrance(cf, args)


if __name__ == '__main__':
    exit(main())
