#!/usr/bin/env python3
import json, re, urllib.request
from pathlib import Path
from urllib.parse import urlparse

LAZY_URL='https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/release/lazy.conf'
ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/'source'; SRS=ROOT/'srs'
SRC.mkdir(exist_ok=True); SRS.mkdir(exist_ok=True)

UA='Karingset/1.0 (+https://github.com/libraprince/Karingset)'
def get(url):
    req=urllib.request.Request(url,headers={'User-Agent':UA})
    with urllib.request.urlopen(req,timeout=30) as r: return r.read().decode('utf-8','ignore')

def add(rule, bucket):
    rule=rule.strip()
    if not rule or rule.startswith(('#','//',';')): return
    parts=[x.strip() for x in rule.split(',')]
    typ=parts[0].upper()
    if typ in ('DOMAIN','DOMAIN-SUFFIX','DOMAIN-KEYWORD','DOMAIN-REGEX') and len(parts)>=2:
        key={'DOMAIN':'domain','DOMAIN-SUFFIX':'domain_suffix','DOMAIN-KEYWORD':'domain_keyword','DOMAIN-REGEX':'domain_regex'}[typ]
        bucket[key].add(parts[1].lower())
    elif typ in ('IP-CIDR','IP-CIDR6') and len(parts)>=2:
        key='ip_cidr' if typ=='IP-CIDR' else 'ip_cidr6'
        # Shadowrocket no-resolve is irrelevant to a compiled IP rule set.
        bucket[key].add(parts[1])

def empty(): return {k:set() for k in ('domain','domain_suffix','domain_keyword','domain_regex','ip_cidr','ip_cidr6')}

def main():
    lazy=get(LAZY_URL)
    (SRC/'lazy.conf').write_text(lazy,encoding='utf-8')
    buckets={'PROXY':empty(),'DIRECT':empty(),'REJECT':empty()}
    seen=set(); stats=[]
    in_rules=False
    for raw in lazy.splitlines():
        line=raw.strip()
        if line.startswith('['): in_rules=line.lower()=='[rule]'; continue
        if not in_rules or not line or line.startswith('#'): continue
        p=[x.strip() for x in line.split(',')]
        if len(p)<2: continue
        typ=p[0].upper()
        if typ=='RULE-SET' and len(p)>=3:
            url=p[1]; policy=p[2].upper()
            # Policy names can contain parameters; use the first token.
            policy=policy.split(',')[0]
            if policy not in buckets: continue
            if url in seen: continue
            seen.add(url)
            try:
                text=get(url)
                b=buckets[policy]; count=0
                for r in text.splitlines():
                    before=sum(len(v) for v in b.values()); add(r,b); after=sum(len(v) for v in b.values()); count += max(0,after-before)
                stats.append({'url':url,'policy':policy,'rules_added':count})
            except Exception as e:
                stats.append({'url':url,'policy':policy,'error':str(e)})
        else:
            # Preserve ordinary domain/IP rules with their policy.
            policy=p[-1].upper().split(',')[0]
            if policy in buckets: add(line,buckets[policy])

    for policy,b in buckets.items():
        out={'version':3,'rules':[]}
        # One rule object keeps the generated source compact and compatible with sing-box rule-set compile.
        r={}
        for k,v in b.items():
            if v: r[k]=sorted(v)
        if r: out['rules'].append(r)
        (SRC/f'{policy.lower()}.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (SRC/'manifest.json').write_text(json.dumps({'source':LAZY_URL,'rule_sets':stats},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'source_rule_sets':len(stats),'proxy':sum(map(len,buckets['PROXY'].values())),'direct':sum(map(len,buckets['DIRECT'].values())),'reject':sum(map(len,buckets['REJECT'].values()))},indent=2))

if __name__=='__main__': main()
