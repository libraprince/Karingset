#!/usr/bin/env python3
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'source'
SRS = ROOT / 'srs'
SRC.mkdir(exist_ok=True)
SRS.mkdir(exist_ok=True)

LAZY = 'https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/release/lazy.conf'
UA = 'Karingset/2.3 (+https://github.com/libraprince/Karingset)'
POLICIES = {'PROXY', 'DIRECT', 'REJECT'}
EXTRA = {
    'OpenAI': ('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/OpenAI/OpenAI.list', 'PROXY'),
    'Gemini': ('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Gemini/Gemini.list', 'PROXY'),
    'Claude': ('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Claude/Claude.list', 'PROXY'),
    'Copilot': ('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Copilot/Copilot.list', 'PROXY'),
}
ALIASES = {'Twitter': 'X', 'Lan': 'LAN'}
KEYS = ('domain', 'domain_suffix', 'domain_keyword', 'domain_regex', 'ip_cidr')
ANOMALY_MIN = 20
ANOMALY_DROP = 0.80
ANOMALY_GROWTH = 5.00


def empty():
    return {k: set() for k in KEYS}


def get(url, retries=3):
    request = urllib.request.Request(url, headers={'User-Agent': UA})
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read().decode('utf-8', 'ignore')
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(attempt * 2)
    raise RuntimeError(f'download failed after {retries} attempts: {url}: {last_error}')


def add(line, bucket):
    s = line.strip()
    if not s or s.startswith(('#', '//', ';')):
        return False

    if ',' not in s:
        if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?', s):
            bucket['ip_cidr'].add(s)
            return True
        if ':' in s and re.fullmatch(r'[0-9A-Fa-f:]+(?:/\d{1,3})?', s):
            bucket['ip_cidr'].add(s)
            return True
        if re.fullmatch(r'[A-Za-z0-9*_.-]+\.[A-Za-z]{2,}', s):
            bucket['domain_suffix'].add(s.lstrip('*.').lower())
            return True
        return False

    parts = [x.strip() for x in s.split(',')]
    typ = parts[0].upper()
    if len(parts) < 2:
        return False
    value = parts[1]

    if typ in ('DOMAIN', 'HOST'):
        bucket['domain'].add(value.lower())
        return True
    if typ in ('DOMAIN-SUFFIX', 'HOST-SUFFIX'):
        bucket['domain_suffix'].add(value.lstrip('.').lower())
        return True
    if typ in ('DOMAIN-KEYWORD', 'HOST-KEYWORD'):
        bucket['domain_keyword'].add(value.lower())
        return True
    if typ == 'DOMAIN-REGEX':
        bucket['domain_regex'].add(value)
        return True
    if typ in ('DOMAIN-WILDCARD', 'HOST-WILDCARD'):
        bucket['domain_regex'].add('^' + re.escape(value).replace(r'\*', '.*').replace(r'\?', '.') + '$')
        return True
    if typ in ('IP-CIDR', 'IP-CIDR6', 'IP6-CIDR'):
        bucket['ip_cidr'].add(value)
        return True
    return False


def merge(target, source):
    for key in KEYS:
        target[key].update(source[key])


def flatten(bucket):
    return {item for values in bucket.values() for item in values}


def name(url):
    stem = Path(urlparse(url).path.rstrip('/')).stem or 'Unknown'
    return ALIASES.get(stem, re.sub(r'[^A-Za-z0-9_-]', '', stem))


def parse(text):
    bucket = empty()
    skipped = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(('#', '//', ';')):
            continue
        if not add(line, bucket):
            typ = s.split(',', 1)[0].strip().upper()
            skipped[typ] = skipped.get(typ, 0) + 1
    return bucket, skipped


def write(name_, bucket):
    rules = {key: sorted(value) for key, value in bucket.items() if value}
    output = {'version': 3, 'rules': [rules] if rules else []}
    (SRC / f'{name_}.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )


def find_policy(parts):
    for token in parts[2:]:
        policy = token.strip().upper()
        if policy in POLICIES:
            return policy
    return None


def load_previous_manifest():
    path = SRC / 'manifest.json'
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return None


def main():
    previous = load_previous_manifest()

    for path in SRC.glob('*.json'):
        path.unlink()
    SRS.mkdir(exist_ok=True)

    lazy = get(LAZY)
    (SRC / 'lazy.conf').write_text(lazy, encoding='utf-8')

    aggregate = {policy: empty() for policy in POLICIES}
    services = {}
    seen = set()
    stats = []
    errors = []

    def load(service_name, url, policy):
        if url in seen:
            return
        seen.add(url)
        try:
            bucket, skipped = parse(get(url))
            service = services.setdefault(
                service_name,
                {'policy': policy, 'bucket': empty(), 'sources': [], 'skipped': {}},
            )
            if service['policy'] != policy:
                raise RuntimeError(
                    f'policy collision for {service_name}: '
                    f'{service["policy"]} vs {policy}'
                )
            merge(service['bucket'], bucket)
            for key, value in skipped.items():
                service['skipped'][key] = service['skipped'].get(key, 0) + value
            service['sources'].append(url)
            merge(aggregate[policy], bucket)
            stats.append({
                'name': service_name,
                'url': url,
                'policy': policy,
                'rules': sum(map(len, bucket.values())),
                'skipped': skipped,
            })
        except Exception as exc:
            errors.append(f'{service_name}: {url}: {exc}')
            stats.append({
                'name': service_name,
                'url': url,
                'policy': policy,
                'error': str(exc),
            })

    in_rules = False
    for raw in lazy.splitlines():
        line = raw.strip()
        if line.startswith('['):
            in_rules = line.lower() == '[rule]'
            continue
        if not in_rules or not line or line.startswith('#'):
            continue

        parts = [x.strip() for x in line.split(',')]
        if len(parts) < 2:
            continue
        typ = parts[0].upper()

        if typ == 'RULE-SET' and len(parts) >= 3:
            policy = find_policy(parts)
            if policy:
                load(name(parts[1]), parts[1], policy)
        elif typ == 'DOMAIN-SET' and len(parts) >= 3:
            policy = find_policy(parts)
            if policy and parts[1] not in seen:
                seen.add(parts[1])
                bucket = empty()
                service_name = name(parts[1])
                try:
                    for domain in get(parts[1]).splitlines():
                        domain = domain.strip()
                        if domain and not domain.startswith('#'):
                            bucket['domain_suffix'].add(domain.lstrip('.').lower())
                    services[service_name] = {
                        'policy': policy,
                        'bucket': bucket,
                        'sources': [parts[1]],
                        'skipped': {},
                    }
                    merge(aggregate[policy], bucket)
                except Exception as exc:
                    errors.append(f'{service_name}: {parts[1]}: {exc}')
                    stats.append({
                        'name': service_name,
                        'url': parts[1],
                        'policy': policy,
                        'error': str(exc),
                    })
        else:
            policy = find_policy(parts)
            if policy and add(line, aggregate[policy]):
                lowered = line.lower()
                if policy == 'PROXY' and any(x in lowered for x in (
                    'x.ai', 'grok.com', 'gemini.google.com', 'ai.google.dev',
                    'bard.google.com', 'apple-relay', 'guzzoni.apple.com',
                    'cp4.cloudflare.com', 'apps.mzstatic.com', 'smoot.apple.com',
                )):
                    ai = services.setdefault(
                        'AI', {'policy': 'PROXY', 'bucket': empty(), 'sources': [], 'skipped': {}}
                    )
                    add(line, ai['bucket'])
                elif policy == 'PROXY' and any(x in lowered for x in (
                    'litix.io', 'discomax.com', 'brightline.tv'
                )):
                    streaming = services.setdefault(
                        'Streaming', {'policy': 'PROXY', 'bucket': empty(), 'sources': [], 'skipped': {}}
                    )
                    add(line, streaming['bucket'])

    for service_name, (url, policy) in EXTRA.items():
        load(service_name, url, policy)

    if errors:
        raise RuntimeError('upstream rule download/parse errors:\n- ' + '\n- '.join(errors))

    conflicts = {}
    for left, right in (('DIRECT', 'PROXY'), ('DIRECT', 'REJECT'), ('PROXY', 'REJECT')):
        overlap = flatten(aggregate[left]) & flatten(aggregate[right])
        if overlap:
            conflicts[f'{left.lower()}_vs_{right.lower()}'] = sorted(overlap)

    (SRC / 'conflicts.json').write_text(
        json.dumps({
            'generator': 'Karingset 2.3',
            'summary': {key: len(value) for key, value in conflicts.items()},
            'conflicts': conflicts,
        }, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )

    previous_services = (previous or {}).get('services', {})
    anomalies = []
    for service_name, service in sorted(services.items()):
        current = sum(map(len, service['bucket'].values()))
        old_counts = previous_services.get(service_name, {}).get('counts', {})
        previous_count = sum(old_counts.values())
        if previous_count >= ANOMALY_MIN:
            ratio = current / previous_count if previous_count else 0
            if current == 0 or ratio < (1 - ANOMALY_DROP) or ratio > ANOMALY_GROWTH:
                anomalies.append({
                    'name': service_name,
                    'previous': previous_count,
                    'current': current,
                    'ratio': round(ratio, 4),
                })

    for service_name, service in services.items():
        if service['bucket']:
            write(service_name, service['bucket'])

    for policy, bucket in aggregate.items():
        write(policy.lower(), bucket)

    manifest = {
        'generator': 'Karingset 2.3',
        'source': LAZY,
        'source_version': 3,
        'services': {
            service_name: {
                'policy': service['policy'],
                'sources': service['sources'],
                'counts': {
                    key: len(value)
                    for key, value in service['bucket'].items()
                    if value
                },
                'total': sum(map(len, service['bucket'].values())),
                'skipped': service['skipped'],
            }
            for service_name, service in sorted(services.items())
        },
        'rule_sets': stats,
        'quality': {
            'conflicts': {key: len(value) for key, value in conflicts.items()},
            'anomalies': anomalies,
        },
    }
    (SRC / 'manifest.json').write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )

    print(json.dumps({
        'services': len(services),
        'proxy': sum(map(len, aggregate['PROXY'].values())),
        'direct': sum(map(len, aggregate['DIRECT'].values())),
        'reject': sum(map(len, aggregate['REJECT'].values())),
        'conflicts': {key: len(value) for key, value in conflicts.items()},
        'anomalies': anomalies,
    }, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
