# TEMPORARY: measure how often Seatbelt refuses an explicitly allowed loopback port. Removed before review.
import socket, subprocess, collections, os, tempfile, sys
N = int(sys.argv[1]) if len(sys.argv) > 1 else 300
stats = collections.Counter()
fails = []
for i in range(N):
    a = socket.socket(); a.bind(("127.0.0.1", 0)); a.listen(8)
    d = socket.socket(); d.bind(("127.0.0.1", 0)); d.listen(8)
    ap, dp = a.getsockname()[1], d.getsockname()[1]
    variant = i % 3
    if variant == 0:
        rule = f'(allow network-outbound (remote ip "localhost:{ap}"))'
    elif variant == 1:
        rule = f'(allow network-outbound (remote ip "localhost:{ap}"))(allow network-outbound (remote ip "localhost:{ap}"))'
    else:
        rule = f'(allow network-outbound (remote tcp "localhost:{ap}"))'
    prof = '(version 1)(allow default)(deny network*)' + rule
    probe = f"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(0.5); s.connect(('127.0.0.1',{ap}))"
    r = subprocess.run(["/usr/bin/sandbox-exec", "-p", prof, "/usr/bin/python3", "-c", probe], capture_output=True, env={"PYTHONDONTWRITEBYTECODE": "1"})
    ok = r.returncode == 0
    retry = None
    if not ok:
        r2 = subprocess.run(["/usr/bin/sandbox-exec", "-p", prof, "/usr/bin/python3", "-c", probe], capture_output=True, env={"PYTHONDONTWRITEBYTECODE": "1"})
        retry = r2.returncode == 0
        fails.append((variant, ap, dp, r.stderr.decode().strip().splitlines()[-1:] , retry))
    stats[(variant, ok)] += 1
    a.close(); d.close()
print("STATS", dict(stats))
for f in fails: print("FAIL variant=%d allowed=%d denied=%d err=%s retry_ok=%s" % f)
