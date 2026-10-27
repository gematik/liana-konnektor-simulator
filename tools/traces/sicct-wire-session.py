#
# Copyright 2026 gematik GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# *******
#
# For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
#

# Produces support/traces/sicct/kartos-wire.jsonl (LIANA-75): SICCT session via openssl s_client against a running
# kartos terminal (--port 47440 --trace, TERMINAL_CONTROL_ADDR=127.0.0.1:47441, TERMINAL_KEEP_ALIVE_INTERVAL=1),
# run from the repo root; afterwards take the trace from <state>/traces/ (support/traces/sicct/README.md).
import subprocess, time, urllib.request, sys
def env(t, fu, seq, apdu):
    a = bytes.fromhex(apdu)
    return bytes([t]) + fu.to_bytes(2,'big') + seq.to_bytes(2,'big') + b'\x00' + len(a).to_bytes(4,'big') + a
p = subprocess.Popen(['openssl','s_client','-connect','127.0.0.1:47440','-tls1_2','-groups','brainpoolP256r1',
                      '-cipher','ECDHE-ECDSA-AES128-GCM-SHA256','-quiet','-ign_eof'],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
time.sleep(1)
def send(*e):
    p.stdin.write(env(*e)); p.stdin.flush(); time.sleep(0.3)
def ctl(path, data=None, ctype='application/json', method=None):
    req = urllib.request.Request('http://127.0.0.1:47441'+path, data=data, method=method or ('POST' if data is not None else 'GET'),
                                 headers={'Content-Type': ctype})
    body = urllib.request.urlopen(req).read().decode()
    print(path, body[:80], file=sys.stderr)
    return body
send(0x6B, 0x0000, 0x0001, '80280000')            # INIT CT SESSION
send(0x6B, 0x0000, 0x0002, '8013006300')          # GET STATUS CTS DO
send(0x6B, 0x0000, 0x0003, '8012010100')          # REQUEST ICC slot 1, ATR
send(0x6B, 0x0001, 0x0004, '00A4040C07D2760001448000')  # SELECT eGK root app slot 1
iccsn = __import__('json').loads(ctl('/api/v1/slots/3'))['iccsn']
ctl('/api/v1/slots/3/card', method='DELETE')       # 85 slot 3
time.sleep(0.3)
ctl('/api/v1/slots/3/card', b'{"iccsn": "%s"}' % iccsn.encode(), method='PUT')  # 84 slot 3
time.sleep(1.6)                                    # KEEP ALIVE (interval 1 s)
send(0x6B, 0x0000, 0x0005, '80290000')            # CLOSE CT SESSION
time.sleep(0.5)
p.stdin.close(); p.terminate()
out = p.stdout.read()
print(len(out), 'bytes received', file=sys.stderr)
