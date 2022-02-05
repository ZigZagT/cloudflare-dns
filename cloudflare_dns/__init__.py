import typing
from itertools import chain
from CloudFlare import CloudFlare


class ZoneInfo(typing.TypedDict):
    id: str
    name: str
    status: str
    type: str
    name_servers: typing.List[str]
    modified_on: str
    created_on: str
    activated_on: str


class RecordInfo(typing.TypedDict):
    id: str
    zone_id: str
    zone_name: str
    name: str
    type: str
    content: str
    proxiable: bool
    proxied: bool
    ttl: int
    locked: bool
    created_on: str
    modified_on: str


def get_zones(cf: CloudFlare, domain: str = None) -> typing.Iterable[ZoneInfo]:
    params = {
        'page': 1,
        'per_page': 50,
    }
    if domain:
        params['name'] = domain

    def pages():
        end = False
        while not end:
            response = cf.zones.get(params=params)
            yield response['result']
            if response['result_info']['total_pages'] <= params['page']:
                end = True
            params['page'] += 1

    yield from chain.from_iterable(pages())


def infer_zone(cf: CloudFlare, domain: str) -> ZoneInfo:
    zone_name_len = 0
    ret_zone = None
    for zone in get_zones(cf):
        if domain.endswith(zone['name']) and len(zone['name']) > zone_name_len:
            zone_name_len = len(zone['name'])
            ret_zone = zone
    if ret_zone is None:
        raise LookupError('unable to infer zone from domain {}'.format(domain))
    return ret_zone


def get_records(
        cf: CloudFlare,
        zone_id: str,
        type: str = None,
        domain: str = None,
        content: str = None,
        filter_content: typing.Pattern[str] = None
) -> typing.Iterable[RecordInfo]:
    params = {
        'page': 1,
        'per_page': 100,
        'match': 'all',
    }
    if type and not type == 'ANY':
        params['type'] = type
    if domain:
        params['name'] = domain
    if content:
        params['content'] = content

    def pages():
        end = False
        while not end:
            response = cf.zones.dns_records.get(zone_id, params=params)
            if filter_content:
                yield filter(lambda record: filter_content.match(record['content']), response['result'])
            else:
                yield response['result']
            if response['result_info']['total_pages'] <= params['page']:
                return
            params['page'] += 1

    yield from chain.from_iterable(pages())
