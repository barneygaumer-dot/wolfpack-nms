import concurrent.futures,ipaddress,platform,re,socket,subprocess,time,urllib.request
from datetime import datetime,timezone
from .db import get_db
from .alerts import handle_device_transition
def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def ping(host,timeout=1):
    try:
        args=["ping","-n","1","-w",str(timeout*1000),host] if platform.system().lower()=="windows" else ["ping","-c","1","-W",str(timeout),host]
        p=subprocess.run(args,capture_output=True,text=True,timeout=timeout+1)
        m=re.search(r"time[=<]([\\d.]+)\\s*ms",p.stdout+p.stderr,re.I)
        return p.returncode==0,float(m.group(1)) if m else None
    except Exception:return False,None
def resolve(ip):
    try:return socket.gethostbyaddr(ip)[0]
    except Exception:return ""
def discover(cidr):
    net=ipaddress.ip_network(cidr,strict=False)
    if net.num_addresses>1024: raise ValueError("v1 safety limit: use /22 or smaller")
    def probe(ip):
        ip=str(ip); ok,ms=ping(ip); return ip,ok,ms,resolve(ip) if ok else ""
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex: rows=list(ex.map(probe,net.hosts()))
    db=get_db(); n=0
    for ip,ok,ms,host in rows:
        if not ok: continue
        n+=1; db.execute("""INSERT INTO devices(ip,hostname,status,latency_ms,last_seen) VALUES(?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET hostname=excluded.hostname,status='UP',latency_ms=excluded.latency_ms,last_seen=excluded.last_seen""",(ip,host,"UP",ms,now()))
    db.commit(); return n
def check_device(d):
    """Poll one device using its configured primary method.

    ARP may also be used as a Layer-2 fallback for directly attached
    devices.  ARP fallback establishes presence, not application health.
    """
    ip=d["ip"]
    method=(d["poll_method"] or "ICMP").upper()
    port=d["poll_port"]
    arp_fallback=bool(d["arp_fallback"])
    arp_interface=(d["arp_interface"] or "").strip()

    ok=False
    ms=None
    detail=""

    if method=="ICMP":
        t0=time.time()
        r=subprocess.run(
            ["ping","-c","1","-W","1",ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        ms=round((time.time()-t0)*1000,1)
        ok=(r.returncode==0)
        detail=f"ICMP {'PASS' if ok else 'FAIL'}"

    elif method=="TCP":
        if not port:
            detail="TCP FAIL: no poll port configured"
        else:
            t0=time.time()
            try:
                with socket.create_connection((ip,int(port)),timeout=2):
                    pass
                ms=round((time.time()-t0)*1000,1)
                ok=True
                detail=f"TCP/{port} PASS"
            except Exception as e:
                ms=round((time.time()-t0)*1000,1)
                detail=f"TCP/{port} FAIL: {e}"

    elif method=="ARP":
        if not arp_interface:
            detail="ARP FAIL: no interface configured"
        else:
            t0=time.time()
            r=subprocess.run(
                ["/usr/bin/arping","-I",arp_interface,"-c","3","-w","3",ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            ms=round((time.time()-t0)*1000,1)
            ok=(r.returncode==0)
            detail=f"ARP/{arp_interface} {'PASS' if ok else 'FAIL'}"

    elif method=="UDP":
        detail=f"UDP/{port or '?'} unsupported without protocol-specific response criteria"

    else:
        detail=f"Unknown poll method: {method}"

    # Optional Layer-2 fallback.
    if not ok and arp_fallback and method!="ARP":
        if arp_interface:
            r=subprocess.run(
                ["/usr/bin/arping","-I",arp_interface,"-c","3","-w","3",ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if r.returncode==0:
                ok=True
                detail += f"; ARP/{arp_interface} PASS (L2 fallback)"
            else:
                detail += f"; ARP/{arp_interface} FAIL"
        else:
            detail += "; ARP fallback unavailable: no interface configured"

    st="UP" if ok else "DOWN"
    old_status=(d["status"] or "UNKNOWN").upper()

    db=get_db()
    db.execute(
        "UPDATE devices SET status=?,latency_ms=?,last_seen=? WHERE id=?",
        (st,ms,now(),d["id"])
    )
    db.execute(
        "INSERT INTO evidence(device_id,check_type,status,value,detail) VALUES(?,?,?,?,?)",
        (d["id"],f"POLL-{method}","PASS" if ok else "FAIL",
         str(ms) if ms is not None else None,detail)
    )
    db.commit()

    # Edge-triggered notifications only: one UP->DOWN and one DOWN->UP.
    # Unchanged state is intentionally silent.
    handle_device_transition(d,old_status,st,detail)

    return ok

def run_synthetic(s):
    kind=s["kind"].upper(); target=s["target"]; started=time.perf_counter(); st="FAIL"; val=""; detail=""
    try:
        if kind=="ICMP":
            ok,ms=ping(target,2); st="PASS" if ok else "FAIL"; val=f"{ms:.1f} ms" if ms is not None else ""
        elif kind=="DNS":
            socket.getaddrinfo(target,None); st="PASS"; val=f"{(time.perf_counter()-started)*1000:.1f} ms"
        elif kind=="TCP":
            with socket.create_connection((target,int(s["port"] or 443)),timeout=3): pass
            st="PASS"; val=f"{(time.perf_counter()-started)*1000:.1f} ms"
        elif kind in ("HTTP","HTTPS"):
            url=target if "://" in target else f"{kind.lower()}://{target}"
            with urllib.request.urlopen(url,timeout=5) as r: code=r.status
            st="PASS" if code<500 else "FAIL"; val=f"HTTP {code} / {(time.perf_counter()-started)*1000:.1f} ms"
    except Exception as e: detail=str(e)[:240]
    db=get_db(); db.execute("UPDATE synthetics SET last_status=?,last_value=?,last_run=? WHERE id=?",(st,val or detail,now(),s["id"]))
    db.execute("INSERT INTO evidence(check_type,status,value,detail) VALUES(?,?,?,?)",(f"SYNTH:{s['name']}",st,val,detail)); db.commit()
