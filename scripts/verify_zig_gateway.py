"""Execute the installed gateway's onboarding branches without sending messages.

Uses the actual branch source, including its profile configuration reads. All
session state and notice delivery are disposable. Run with the Hermes Python.
"""
import argparse
import ast
import asyncio
import logging
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock


def verify(path):
    tree=ast.parse(path.read_text())
    nodes=[node for node in ast.walk(tree) if isinstance(node,ast.If)
           and "_load_gateway_config().get('onboarding', {}).get('enabled', True)" in ast.unparse(node.test)]
    assert len(nodes)==2, 'Expected both installed onboarding guards'
    fn=ast.AsyncFunctionDef(name='onboarding',args=ast.arguments(posonlyargs=[],args=[],kwonlyargs=[],kw_defaults=[],defaults=[]),
                           body=sorted(nodes,key=lambda n:n.lineno),decorator_list=[])
    code=compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),str(path),'exec')
    from gateway.config import Platform
    for config, expected in (({'onboarding':{'enabled':False,'profile_build':'off'}},0),
                             ({'onboarding':{'profile_build':'off'}},1)):
        for kind,history in (('group',[]),('dm',[]),('group',[{'role':'user','content':'earlier turn'}])):
            with tempfile.TemporaryDirectory() as directory:
                runner=SimpleNamespace(async_session_store=SimpleNamespace(has_any_sessions=AsyncMock(return_value=False)),
                    config=SimpleNamespace(get_home_channel=lambda p:None),_deliver_platform_notice=AsyncMock())
                notes=[]
                env=dict(_load_gateway_config=lambda:config,history=history,self=runner,
                         source=SimpleNamespace(platform=Platform.MATRIX,chat_type=kind,profile=''),
                         Platform=Platform,turn_sidecar_notes=notes,_hermes_home=Path(directory),
                         _home_target_env_var=lambda p:None,os=os,logger=logging.getLogger('gateway-test'))
                exec(code,env)
                asyncio.run(env['onboarding']())
                count=0 if history else expected
                assert len(notes)==count,(kind,config,notes)
                assert runner._deliver_platform_notice.await_count==count
                if count:
                    assert '/help' in notes[0]
                print('PASS onboarding:',kind,'existing' if history else 'fresh','enabled' if expected else 'disabled')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('source',type=Path,nargs='?',default=Path('/usr/local/lib/hermes-agent/gateway/run.py'))
    verify(parser.parse_args().source)
