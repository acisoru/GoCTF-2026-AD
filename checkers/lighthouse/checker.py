#!/usr/bin/env python3
"""Skipper checker: checker.py info / check IP / put|get IP FLAG_ID FLAG VULN."""
import json
import base64
import os
import secrets
import sys
import time
import uuid
import urllib.error
import urllib.request
from feal import uncrypt

OK, CORRUPT, MUMBLE, DOWN, FAILED = 101, 102, 103, 104, 110

def request(ip, path, method='GET', payload=None, headers=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(f'http://{ip}:{os.environ.get("LIGHTHOUSE_PORT", "8085")}{path}', data=data, method=method,
                                  headers={'Content-Type': 'application/json',
                                           'User-Agent': secrets.choice((
                                               'Mozilla/5.0', 'curl/8.7.1', 'Lighthouse/1.0')),
                                           'X-Request-Id': secrets.token_hex(8), **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read())

def length_filters(length, shift, hi, lo, mark):
    return (
        f'int filter(int size) {{ int value = 0; int pieces[] = {{{hi}, {lo}}}; '
        'for (int i = 0; i < 2; ++i) value = (value << 4) | pieces[i]; '
        'return value == size; }',
        f'int filter(int size) {{ int value = {length + shift}; '
        f'for (int i = 0; i < {shift}; ++i) --value; '
        'return (size ^ value) == 0; }',
        f'#include <stdint.h>\n#line {mark}\n'
        f'int filter(int size) {{ int32_t value = 0; int32_t pieces[] = {{{hi}, {lo}}}; '
        'for (int i = 0; i < 2; ++i) value = (value << 4) | pieces[i]; '
        'return value == size; }',
        f'#include <stddef.h>\n#include <stdint.h>\n#define FOLD(h, l) (((h) << 4) | (l))\n'
        f'#line {mark}\nstatic int32_t rebuild(void) {{\n'
        f'  int32_t parts[] = {{{hi}, {lo}}};\n  int32_t value = 0;\n'
        '  for (size_t i = 0; i < 2; ++i) value = FOLD(value, parts[i]);\n'
        '  return value;\n}\nint filter(int size) { return size == rebuild(); }\n',
        f'#include <stdbool.h>\n#include <limits.h>\n#line {mark}\n'
        f'static _Bool match(int size) {{ return size == {length} && CHAR_BIT == 8; }}\n'
        'int filter(int size) { return match(size); }\n',
        '#if 1\n#define PASS(x) x\n#else\n#define PASS(x) 0\n#endif\n#undef PASS\n#define PASS(x) x\n'
        f'#line {mark}\nint filter(int size) {{ return PASS(size == {length}); }}\n',
        f'#include <iso646.h>\n#line {mark}\n'
        f'int filter(int size) {{ return (size == {length}) and (size > 0); }}\n',
        f'#include <stdalign.h>\nint filter(int size) {{\n'
        f'  _Alignas(4) int goal = {length};\n'
        '  return size == goal && alignof(int) >= 4;\n}\n',
        f'#include <float.h>\nint filter(int size) {{ return size == {length} && FLT_RADIX >= 2; }}\n',
        f'enum piece {{ hi = {hi}, lo = {lo} }};\n'
        'typedef struct { int hi, lo; } pair;\n'
        'static int join(pair parts) { return (parts.hi << 4) | parts.lo; }\n'
        'int filter(int size) {\n  pair parts = {hi, lo};\n  return join(parts) == size;\n}\n',
        f'static int yes(int n) {{ return n == {length}; }}\n'
        'static int no(int n) { return 0 * n; }\n'
        f'static int (*pick(int size))(int) {{ return size == {length} ? yes : no; }}\n'
        'int filter(int size) { return pick(size)(size); }\n',
        'static int drop(int value, int times) {\n  while (times-- > 0) --value;\n  return value;\n}\n'
        f'#line {mark}\nint filter(int size) {{\n  int value = {length + shift};\n'
        f'  return (size ^ drop(value, {shift})) == 0;\n}}\n',
        f'int filter(int size) {{\n  int seen = 0;\n  switch (size & 15) {{\n'
        f'    case {lo}: seen = size >> 4; break;\n    default: seen = 0; break;\n  }}\n'
        f'  return seen == {hi} && size < {length + 16};\n}}\n',
        f'#define ACCEPT(n) ((n) == {length})\n#ifdef ACCEPT\n'
        'int filter(int size) { return ACCEPT(size); }\n#else\n'
        'int filter(int size) { return 0; }\n#endif\n',
    )


def popcount_filters():
    mark = secrets.randbelow(40) + 2
    return (
        'int filter(int n) { int total = 0; for (int bit = 1; bit < 64; bit <<= 1) '
        'total += (n & bit) != 0; return total > 1 && n < 200; }',
        f'#include <stdint.h>\n#line {mark}\nint filter(int n) {{\n  int32_t total = 0;\n'
        '  for (int32_t bit = 1; bit < 64; bit <<= 1) total += (n & bit) != 0;\n'
        '  return total > 1 && n < 200;\n}\n',
        'static int bits(int n) { return n ? 1 + bits(n & (n - 1)) : 0; }\n'
        'int filter(int n) { return bits(n) > 1 && n < 200; }\n',
        f'#line {mark}\nstatic int bits(int n) {{ return n ? 1 + bits(n & (n - 1)) : 0; }}\n'
        'int filter(int n) { return bits(n) > 1 && n < 200; }\n',
    )


def compile_filter(ip, queue, source):
    path = f"/api/queues/{queue['id']}/filter"
    for attempt in range(6):
        try:
            result = request(ip, path, 'POST', {'source': source, 'label': secrets.token_hex(4)})
            if not result['ok'] or 'Disassembly of section CODE' not in result['listing']:
                raise ValueError('filter compilation or listing failed')
            return result
        except urllib.error.HTTPError as exc:
            if exc.code != 429 or attempt == 5: raise
            time.sleep(0.4 * (attempt + 1))

def probe(ip):
    label = secrets.token_hex(6)
    queue = request(ip, '/api/queues', 'POST', {
        'label': label, 'retention_seconds': 180
    })
    uid = queue['id']
    if uuid.UUID(uid).version != 4 or uuid.UUID(uid).variant != uuid.RFC_4122:
        raise ValueError('bad mailbox id')
    if len(queue['read_key']) != 48 or any(c not in '0123456789abcdef' for c in queue['read_key']):
        raise ValueError('bad read secret')
    info = request(ip, f'/api/queues/{uid}')
    if info['label'] != label or info['retention_seconds'] != 180 or info['stored_count'] != 0:
        raise ValueError('queue settings not retained')
    key = {'X-Queue-Key': queue['read_key']}
    try:
        request(ip, f'/api/queues/{uid}/messages', headers={'X-Queue-Key': secrets.token_hex(24)})
        raise ValueError('messages available without read secret')
    except urllib.error.HTTPError as exc:
        if exc.code != 403: raise
    accepted = 'probe-' + secrets.token_hex(8)
    topic = 't' + secrets.token_hex(3)
    length = ((len(accepted.encode()) + 7) // 8) * 16
    shift = secrets.randbelow(6) + 2
    hi, lo = length >> 4, length & 15
    mark = secrets.randbelow(40) + 2
    source = secrets.choice(length_filters(length, shift, hi, lo, mark))
    revision = compile_filter(ip, queue, source)['revision']
    detail = request(ip, f'/api/queues/{uid}/filters/{revision}', headers=key)
    if detail['source'] != source or detail['state'] != 'ready' or detail['active']:
        raise ValueError('draft details not retained')
    try:
        request(ip, f'/api/queues/{uid}/filters/{revision}/activate', 'POST', {},
                {'X-Queue-Key': secrets.token_hex(24)})
        raise ValueError('filter activated without read secret')
    except urllib.error.HTTPError as exc:
        if exc.code != 403: raise
    request(ip, f'/api/queues/{uid}/filters/{revision}/activate', 'POST', {}, key)
    if not any(item['revision'] == revision and item['active'] for item in
               request(ip, f'/api/queues/{uid}/filters')['filters']):
        raise ValueError('active revision missing from history')
    rejected = False
    try:
        request(ip, f'/api/queues/{uid}/messages', 'POST', {'message': base64.b64encode(b'x').decode()})
    except urllib.error.HTTPError as exc:
        rejected = exc.code == 403
    if not rejected: raise ValueError('filter did not reject nonmatching message')
    posted = request(ip, f'/api/queues/{uid}/messages', 'POST', {
        'message': base64.b64encode(accepted.encode()).decode(), 'topic': topic, 'delay_ms': 2500
    })
    if posted.get('release_at', 0) <= int(time.time()):
        raise ValueError('delay was not scheduled')
    if request(ip, f'/api/queues/{uid}/messages', headers=key)['messages']:
        raise ValueError('delayed message arrived early')
    deadline = posted['release_at'] + 2
    messages = []
    while time.time() < deadline:
        time.sleep(0.2)
        messages = request(ip, f'/api/queues/{uid}/messages', headers=key)['messages']
        if messages:
            break
    if len(messages) != 1 or messages[0]['topic'] != topic or \
            uncrypt(queue['read_key'], messages[0]['ciphertext']) != accepted.encode():
        raise ValueError('delayed message missing')
    if messages[0]['ciphertext'] == accepted.encode().hex():
        raise ValueError('message was not sealed')
    if request(ip, f'/api/queues/{uid}/messages', headers=key)['messages']:
        raise ValueError('read messages remained unread')
    history = request(ip, f'/api/queues/{uid}/messages?show_read=true', headers=key)['messages']
    if history != messages:
        raise ValueError('read history missing')
    revision = compile_filter(ip, queue, secrets.choice(popcount_filters()))['revision']
    request(ip, f'/api/queues/{uid}/filters/{revision}/activate', 'POST', {}, key)
    request(ip, f'/api/queues/{uid}/messages', 'POST', {
        'message': base64.b64encode(accepted[::-1].encode()).decode(), 'topic': topic
    })
    messages = request(ip, f'/api/queues/{uid}/messages?show_read=true', headers=key)['messages']
    if {uncrypt(queue['read_key'], item['ciphertext']) for item in messages} != \
            {accepted.encode(), accepted[::-1].encode()}:
        raise ValueError('messages not retained across filter revisions')
    raw = bytes.fromhex('007f80ff' + secrets.token_hex(12))
    request(ip, f'/api/queues/{uid}/messages', 'POST', {
        'message': base64.b64encode(raw).decode(), 'topic': topic
    })
    if raw not in {uncrypt(queue['read_key'], item['ciphertext']) for item in
                   request(ip, f'/api/queues/{uid}/messages?show_read=true', headers=key)['messages']}:
        raise ValueError('raw-byte message changed')
    for attempt in range(6):
        try:
            request(ip, f'/api/queues/{uid}/filter', 'POST',
                    {'source': 'int filter(int n) { return ; ' + secrets.token_hex(2) + ' }'})
            raise ValueError('invalid draft compiled')
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < 5:
                time.sleep(0.4 * (attempt + 1))
                continue
            if exc.code != 422: raise
            invalid = json.loads(exc.read())
            break
    if invalid['state'] != 'rejected' or invalid['ok']:
        raise ValueError('invalid draft not rejected')
    try:
        request(ip, f"/api/queues/{uid}/filters/{invalid['revision']}/activate", 'POST', {}, key)
        raise ValueError('rejected filter activated')
    except urllib.error.HTTPError as exc:
        if exc.code != 404: raise

def quit(status, public='OK', private=''):
    print(public)
    if private: print(private, file=sys.stderr)
    raise SystemExit(status)

def main():
    args = sys.argv[1:]
    if args == ['info']:
        quit(OK, json.dumps({'vulns': 1, 'timeout': 30, 'attack_data': True, 'puts': 1, 'gets': 1}))
    if not args or args[0] not in {'check', 'put', 'get'}:
        quit(FAILED, 'unknown action')
    action = args[0]
    if (action == 'check' and len(args) != 2) or \
            (action in {'put', 'get'} and (len(args) != 5 or args[4] != '1')):
        quit(FAILED, 'checker arguments invalid')
    ip = args[1]
    try:
        if action == 'check':
            if request(ip, '/api/health')['status'] != 'ok': quit(MUMBLE, 'bad health response')
            probe(ip)
            quit(OK)
        flag_id, flag = args[2:4]
        if action == 'put':
            queue = request(ip, '/api/queues', 'POST', {
                'retention_seconds': 604800, 'label': secrets.token_hex(6)
            })
            request(ip, f"/api/queues/{queue['id']}/messages", 'POST', {
                'message': base64.b64encode(flag.encode()).decode(),
                'topic': 't' + secrets.token_hex(3)
            })
            quit(OK, f"{queue['id']} {queue['created_at']}", f"{queue['id']}:{queue['read_key']}")
        if action == 'get':
            queue_id, read_key = flag_id.split(':', 1)
            got = request(ip, f'/api/queues/{queue_id}/messages?show_read=true',
                          headers={'X-Queue-Key': read_key})['messages']
            found = False
            for item in got:
                try:
                    found |= uncrypt(read_key, item['ciphertext']) == flag.encode()
                except (ValueError, KeyError, TypeError):
                    continue
            if not found:
                quit(CORRUPT, 'flag disappeared')
            quit(OK)
    except urllib.error.URLError as exc:
        quit(DOWN, 'http failure', str(exc))
    except Exception as exc:
        quit(MUMBLE, 'checker failure', repr(exc))

if __name__ == '__main__': main()
