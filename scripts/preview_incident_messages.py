"""Render deterministic phone-width examples. No network, jobs or Matrix sends."""
import argparse
import html
import json
import sys
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ansible/roles/vulnerability_incidents/files'))
from incident_store import IncidentStore
from incident_service import message_html
from test_vulnerability_incidents import snapshot,finding


def examples():
    with tempfile.TemporaryDirectory() as directory:
        now=[1000]
        store=IncidentStore(Path(directory)/'db',clock=lambda:now[0])
        f=finding('CVE-2026-42040',installation='deployment:seerr',scope='proxy',package='axios',ecosystem='npm',installed='1.15.0',fixed='1.15.1, 0.31.1',severity='LOW')
        store.ingest(snapshot(source='media-automation',findings=[f]))
        incident=store.get_incident(f['id'])
        root=store.notification_body(f['id'])
        before=store.notification_evidence(incident)
        store.ingest(snapshot(source='media-automation',sequence=2,findings=[{**f,'fixed':'1.15.2, 0.31.1'}]))
        incident=store.get_incident(f['id'])
        update=store.notification_update(incident,before,store.notification_evidence(incident))
        cases=[('New finding',root),('Fix metadata changed',update)]
        for i in range(6):
            store.ingest(snapshot(source=f'host-{i}',findings=[{**f,'installation':f'deployment:service-{i}','package':f'package-{i}'}]))
        cases.append(('Several services',store.notification_body(f['id'])))
        store.close()
        return cases


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,default=ROOT/'tmp/ops-message-redesign/preview.html')
    args=parser.parse_args()
    cases=examples()
    cards=''.join('<section><h2>'+html.escape(name)+'</h2><div class="phone"><div class="room">Homelab vulnerabilities</div><div class="sender">beszel</div><div class="message">'+message_html(body)+'</div></div><small>'+str(len(body))+' characters</small></section>' for name,body in cases)
    document='''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Vulnerability message previews</title><style>
    *{box-sizing:border-box}body{margin:0;padding:32px;background:#101316;color:#e6e7e9;font:16px/1.45 system-ui,sans-serif}h1{font-size:26px;margin:0 0 8px}p{color:#a7adb4;margin:0 0 32px}.grid{display:grid;grid-template-columns:repeat(auto-fit, minmax(350px,1fr));gap:32px}h2{font-size:16px;font-weight:500}section{max-width:390px}.phone{width:350px;min-height:600px;background:#12161b;border:1px solid #34383e;border-radius:24px;padding:18px 12px}.room{font-size:16px;border-bottom:1px solid #34383e;padding:0 0 15px;margin-bottom:22px}.sender{color:#31b3c9;font-size:16px;margin:0 8px 5px}.message{font-size:17px;line-height:1.4;overflow-wrap:anywhere;background:#272b31;padding:12px;border-radius:12px}strong{font-weight:650}a{color:#82b8fa}small{color:#9299a3;display:block;margin-top:10px}</style><h1>Vulnerability messages</h1><p>350 px previews of deterministic Beszel alerts. Metadata-only changes produce no message.</p><main class="grid">'''+cards+'</main></html>'
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(document)
    args.output.with_suffix('.json').write_text(json.dumps(dict(cases),indent=2))
    print(args.output)
    for name,body in cases: print(name+': '+str(len(body))+' characters')


if __name__=='__main__': main()
