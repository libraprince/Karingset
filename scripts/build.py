#!/usr/bin/env python3
import json,re,urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT=Path(__file__).resolve().parents[1]; SRC=ROOT/'source'; SRS=ROOT/'srs'
SRC.mkdir(exist_ok=True); SRS.mkdir(exist_ok=True)
LAZY='https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/release/lazy.conf'
UA='Karingset/2.1 (+https://github.com/libraprince/Karingset)'
EXTRA={
'OpenAI':('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/OpenAI/OpenAI.list','PROXY'),
'Gemini':('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Gemini/Gemini.list','PROXY'),
'Claude':('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Claude/Claude.list','PROXY'),
'Copilot':('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Copilot/Copilot.list','PROXY')}
ALIASES={'Twitter':'X','Lan':'LAN'}
KEYS=('domain','domain_suffix','domain_keyword','domain_regex','ip_cidr','ip_cidr6')
def empty(): return {k:set() for k in KEYS}
def get(u):
 r=urllib.request.Request(u,headers={'User-Agent':UA})
 with urllib.request.urlopen(r,timeout=60) as x:return x.read().decode('utf-8','ignore')
def add(line,b):
 s=line.strip()
 if not s or s.startswith(('#','//',';')):return False
 if ',' not in s:
  if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?',s):b['ip_cidr'].add(s);return True
  if ':' in s and re.fullmatch(r'[0-9A-Fa-f:]+(?:/\d{1,3})?',s):b['ip_cidr6'].add(s);return True
  if re.fullmatch(r'[A-Za-z0-9*_.-]+\.[A-Za-z]{2,}',s):b['domain_suffix'].add(s.lstrip('*.').lower());return True
  return False
 p=[x.strip() for x in s.split(',')]; typ=p[0].upper()
 if len(p)<2:return False
 v=p[1]
 # Shadowrocket / QuantumultX / Clash style host rules.
 if typ in ('DOMAIN','HOST'):
  b['domain'].add(v.lower());return True
 if typ in ('DOMAIN-SUFFIX','HOST-SUFFIX'):
  b['domain_suffix'].add(v.lower());return True
 if typ in ('DOMAIN-KEYWORD','HOST-KEYWORD'):
  b['domain_keyword'].add(v.lower());return True
 if typ=='DOMAIN-REGEX':
  b['domain_regex'].add(v);return True
 if typ=='DOMAIN-WILDCARD':
  b['domain_regex'].add('^'+re.escape(v).replace(r'\*','.*').replace(r'\?','.')+'$');return True
 if typ in ('IP-CIDR','IP-CIDR6'):
  b['ip_cidr' if typ=='IP-CIDR' else 'ip_cidr6'].add(v);return True
 return False
def merge(a,b):
 for k in KEYS:a[k].update(b[k])
def name(u):
 n=Path(urlparse(u).path.rstrip('/')).stem or 'Unknown';return ALIASES.get(n,re.sub(r'[^A-Za-z0-9_-]','',n))
def parse(t):
 b=empty();skip=0
 for l in t.splitlines():
  if not add(l,b) and l.strip() and not l.strip().startswith(('#','//',';')):skip+=1
 return b,skip
def write(n,b):
 r={k:sorted(v) for k,v in b.items() if v};out={'version':5,'rules':[r] if r else []}
 (SRC/f'{n}.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def main():
 lazy=get(LAZY);(SRC/'lazy.conf').write_text(lazy,encoding='utf-8')
 agg={x:empty() for x in ('PROXY','DIRECT','REJECT')}; services={};seen=set();stats=[]
 def load(n,u,p):
  if u in seen:return
  seen.add(u)
  try:
   b,skip=parse(get(u));services.setdefault(n,{'policy':p,'bucket':empty(),'sources':[]});merge(services[n]['bucket'],b);services[n]['sources'].append(u);merge(agg[p],b);stats.append({'name':n,'url':u,'policy':p,'rules':sum(map(len,b.values())),'skipped':skip})
  except Exception as e:stats.append({'name':n,'url':u,'policy':p,'error':str(e)})
 in_rules=False
 for raw in lazy.splitlines():
  l=raw.strip()
  if l.startswith('['):in_rules=l.lower()=='[rule]';continue
  if not in_rules or not l or l.startswith('#'):continue
  p=[x.strip() for x in l.split(',')]
  if len(p)<2:continue
  typ=p[0].upper()
  if typ=='RULE-SET' and len(p)>=3:
   pol=p[2].upper().split(',')[0]
   if pol in agg:load(name(p[1]),p[1],pol)
  elif typ=='DOMAIN-SET' and len(p)>=3:
   pol=p[2].upper().split(',')[0]
   if pol in agg and p[1] not in seen:
    seen.add(p[1]);b=empty()
    try:
     for d in get(p[1]).splitlines():
      d=d.strip()
      if d and not d.startswith('#'):b['domain_suffix'].add(d.lstrip('.').lower())
     n=name(p[1]);services[n]={'policy':pol,'bucket':b,'sources':[p[1]]};merge(agg[pol],b)
    except Exception as e:stats.append({'name':name(p[1]),'url':p[1],'policy':pol,'error':str(e)})
  else:
   pol=p[-1].upper().split(',')[0]
   if pol in agg and add(l,agg[pol]):
    if pol=='PROXY' and any(x in l.lower() for x in ('x.ai','grok.com','gemini.google.com','ai.google.dev','bard.google.com','apple-relay','guzzoni.apple.com','cp4.cloudflare.com','apps.mzstatic.com','smoot.apple.com')):
     ai=services.setdefault('AI',{'policy':'PROXY','bucket':empty(),'sources':[]});add(l,ai['bucket'])
    elif pol=='PROXY' and any(x in l.lower() for x in ('litix.io','discomax.com','brightline.tv')):
     st=services.setdefault('Streaming',{'policy':'PROXY','bucket':empty(),'sources':[]});add(l,st['bucket'])
 for n,(u,p) in EXTRA.items():load(n,u,p)
 for n,v in services.items():
  if v['bucket']:write(n,v['bucket'])
 for p,b in agg.items():write(p.lower(),b)
 manifest={'generator':'Karingset 2.1','source':LAZY,'source_version':5,'services':{n:{'policy':v['policy'],'sources':v['sources'],'counts':{k:len(x) for k,x in v['bucket'].items() if x}} for n,v in sorted(services.items())},'rule_sets':stats}
 (SRC/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({'services':len(services),'proxy':sum(map(len,agg['PROXY'].values())),'direct':sum(map(len,agg['DIRECT'].values())),'reject':sum(map(len,agg['REJECT'].values()))},ensure_ascii=False,indent=2))
if __name__=='__main__':main()
