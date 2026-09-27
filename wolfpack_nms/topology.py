import re, socket
from .db import get_db

def classify(d, descr=""):
    x=(" ".join(str(d[k] or "") for k in ("hostname","display_name","vendor","model","device_type") if k in d.keys())+" "+descr).lower()
    if any(k in x for k in ("palo alto","firewall","pan-os","fortigate","asa ")): return "firewall"
    if any(k in x for k in ("air-ap","c1140","access point","wireless")): return "ap"
    if any(k in x for k in ("c1900","cisco 19","1921","router","isr")): return "router"
    if any(k in x for k in ("switch","catalyst","sg110")): return "switch"
    if any(k in x for k in ("camera","tablo","iot","thermostat")): return "iot"
    return d["device_type"] or "host"

def _recv_some(chan):
    return chan.recv(65535).decode(errors="replace") if chan.recv_ready() else ""

def _open_cli(chan, timeout=10):
    import time,re
    buf=""; deadline=time.time()+timeout
    # Wake the shell so we get a clean prompt even on old IOS.
    chan.send("\n")
    while time.time()<deadline:
        if chan.recv_ready():
            buf += _recv_some(chan)
            clean=buf.replace("\r","")
            lines=[x.strip() for x in clean.splitlines() if x.strip()]
            if lines:
                candidate=lines[-1]
                if re.match(r"^[^\s]+[>#]$",candidate):
                    return candidate,buf
        time.sleep(0.08)
    raise RuntimeError("Timed out waiting for initial IOS prompt; raw="+repr(buf[-500:]))

def _run_cli(chan, prompt, cmd, timeout=20):
    import time
    # Drain anything left from the prior transaction.
    while chan.recv_ready(): _recv_some(chan)
    chan.send(cmd+"\n")
    buf=""; deadline=time.time()+timeout; saw_echo=False
    while time.time()<deadline:
        if chan.recv_ready():
            buf += _recv_some(chan)
            clean=buf.replace("\r","")
            if cmd in clean: saw_echo=True
            # IMPORTANT: command echo is not completion. Require the learned prompt
            # to return as the final nonblank line.
            lines=[x.strip() for x in clean.splitlines() if x.strip()]
            if saw_echo and lines and lines[-1] == prompt:
                break
        time.sleep(0.08)
    else:
        raise RuntimeError(f"Timeout waiting for prompt after {cmd!r}; raw={buf[-1000:]!r}")

    clean=buf.replace("\r","")
    lines=clean.splitlines()
    # Remove command echo and the returned prompt only for parsing; RAW stays intact.
    if lines and lines[0].strip()==cmd: lines=lines[1:]
    if lines and lines[-1].strip()==prompt: lines=lines[:-1]
    body="\n".join(lines).strip()
    unsupported=any(x in body for x in ("% Invalid input","% Unrecognized command",
                                        "% Unknown command","% Ambiguous command"))
    return {"command":cmd,"raw":buf,"body":body,
            "status":"UNSUPPORTED" if unsupported else ("PASS" if body else "EMPTY")}

def ssh_collect(d):
    import paramiko
    out={}; c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(d["ip"],port=int(d["ssh_port"] or 22),username=d["ssh_username"],
              password=d["ssh_password"] or None,timeout=7,auth_timeout=7,banner_timeout=7,
              look_for_keys=True,allow_agent=True)
    ch=c.invoke_shell(width=200,height=1000)
    prompt,banner=_open_cli(ch,10)
    results={"SESSION":{"command":"open shell","raw":banner,"body":prompt,"status":"PASS"}}
    results["pager"]=_run_cli(ch,prompt,"terminal length 0",10)
    for name,cmd in [("version","show version"),("interfaces","show ip interface brief"),
                     ("interface_desc","show interfaces description"),("arp","show ip arp"),
                     ("cdp","show cdp neighbors detail"),("lldp","show lldp neighbors detail"),
                     ("routes","show ip route"),("mac_table","show mac address-table"),
                     ("wifi_assoc","show dot11 associations all-client")]:
        r=_run_cli(ch,prompt,cmd,25); results[name]=r; out[name]=r["body"]
    out["_results"]=results; out["_prompt"]=prompt
    c.close(); return out

def parse_neighbors(text):
    ips=set()
    for pat in (r'IP address:\s*(\d+\.\d+\.\d+\.\d+)',r'Management Address:\s*(\d+\.\d+\.\d+\.\d+)'):
        ips.update(re.findall(pat,text,re.I))
    return sorted(ips)


def norm_mac(mac):
    h=re.sub(r'[^0-9a-fA-F]','',mac or '').lower()
    return ':'.join(h[i:i+2] for i in range(0,12,2)) if len(h)==12 else (mac or '').lower()

def parse_arp(text):
    rows=[]
    seen=set()
    # Cisco: Internet  10.23.10.89  2  aabb.ccdd.eeff  ARPA  GigabitEthernet0/0
    cisco=re.compile(r'Internet\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+([0-9a-fA-F.:-]{12,17})\s+\S+\s*(\S+)?',re.I)
    # Generic/PAN-ish: 10.23.10.89  aa:bb:cc:dd:ee:ff  ethernet1/2 ...
    generic=re.compile(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:[:.-][0-9a-fA-F]{2}){5}|[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2})(?:\s+(\S+))?',re.I)
    for m in cisco.finditer(text or ''):
        ip,age,mac,intf=m.group(1),m.group(2),norm_mac(m.group(3)),m.group(4) or ""
        key=(ip,mac)
        if key not in seen: rows.append((ip,mac,intf,age)); seen.add(key)
    for m in generic.finditer(text or ''):
        ip,mac,intf=m.group(1),norm_mac(m.group(2)),m.group(3) or ""
        key=(ip,mac)
        if key not in seen: rows.append((ip,mac,intf,"")); seen.add(key)
    return rows

def store_arp(observer, text):
    db=get_db(); count=0
    for ip,mac,intf,age in parse_arp(text):
        count+=1
        db.execute("""INSERT INTO arp_observations(observer_device_id,ip,mac,interface,age)
          VALUES(?,?,?,?,?)
          ON CONFLICT(observer_device_id,ip,mac) DO UPDATE SET
          interface=excluded.interface,age=excluded.age,last_seen=CURRENT_TIMESTAMP""",
          (observer["id"],ip,mac,intf,age))
        # ARP is evidence of existence even if ICMP is filtered.
        db.execute("""INSERT INTO devices(ip,hostname,status,device_type)
          VALUES(?,'','OBSERVED','host')
          ON CONFLICT(ip) DO NOTHING""",(ip,))
    db.execute("INSERT INTO evidence(device_id,check_type,status,value,detail) VALUES(?,?,?,?,?)",
               (observer["id"],"ARP","PASS",str(count),f"{count} ARP neighbors observed"))
    db.commit()
    return count

def build_topology():
    db=get_db()
    db.execute("""CREATE TABLE IF NOT EXISTS topology_edges(
      id INTEGER PRIMARY KEY,src_device_id INTEGER,dst_device_id INTEGER,kind TEXT,detail TEXT,
      UNIQUE(src_device_id,dst_device_id,kind))""")
    ds=db.execute("SELECT * FROM devices").fetchall()
    byip={d["ip"]:d for d in ds}
    for d in ds:
        try:
            evidence=ssh_collect(d)
            version=evidence.get("version","")
            dtype=classify(d,version)
            db.execute("UPDATE devices SET device_type=? WHERE id=?",(dtype,d["id"]))
            store_arp(d,evidence.get("arp","")+"\n"+evidence.get("arp_alt",""))
            for ip in parse_neighbors(evidence.get("cdp","")+"\n"+evidence.get("lldp","")):
                if ip in byip and ip != d["ip"]:
                    db.execute("""INSERT OR IGNORE INTO topology_edges(src_device_id,dst_device_id,kind,detail)
                    VALUES(?,?,?,?)""",(d["id"],byip[ip]["id"],"L2","CDP/LLDP discovered"))
        except Exception as e:
            db.execute("INSERT INTO evidence(device_id,check_type,status,detail) VALUES(?,?,?,?)",(d["id"],"TOPOLOGY","FAIL",str(e)[:240]))
    db.commit()

def test_ssh(d):
    import paramiko
    c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(d["ip"],port=int(d["ssh_port"] or 22),username=d["ssh_username"],
                  password=d["ssh_password"] or None,timeout=6,auth_timeout=6,
                  banner_timeout=6,look_for_keys=True,allow_agent=True)
        return True,"SSH authentication successful"
    except Exception as e:
        return False,str(e)[:240]
    finally:
        try:c.close()
        except Exception:pass

def collect_one(device_id):
    from datetime import datetime,timezone
    db=get_db(); d=db.execute("SELECT * FROM devices WHERE id=?",(device_id,)).fetchone()
    if not d: return False,{"error":"device not found"}
    ok,detail=test_ssh(d)
    db.execute("UPDATE devices SET auth_status=?,auth_detail=? WHERE id=?",
               ("PASS" if ok else "FAIL",detail,d["id"]))
    db.execute("INSERT INTO evidence(device_id,check_type,status,detail) VALUES(?,?,?,?)",
               (d["id"],"SSH-AUTH","PASS" if ok else "FAIL",detail))
    if not ok: db.commit(); return False,{"auth":detail}
    try:
        ev=ssh_collect(d)
        version=ev.get("version","")
        dtype=classify(d,version)
        for cname,res in ev.get("_results",{}).items():
            st=res.get("status","EMPTY")
            est="PASS" if st=="PASS" else ("N/A" if st=="UNSUPPORTED" else "WARN")
            raw=res.get("raw","")
            db.execute("INSERT INTO evidence(device_id,check_type,status,value,detail) VALUES(?,?,?,?,?)",
                       (d["id"],"CLI-"+cname.upper(),est,str(len(raw))+" bytes",raw[:8000]))
        iface_rows=sync_interface_inventory(db,d["id"],ev.get("interfaces",""),ev.get("interface_desc",""),source="CLI")
        arp_count=store_arp(d,ev.get("arp","")+"\\n"+ev.get("arp_alt",""))
        neighbors=parse_neighbors(ev.get("cdp","")+"\\n"+ev.get("lldp",""))
        byip={x["ip"]:x for x in db.execute("SELECT * FROM devices")}
        db.execute("""CREATE TABLE IF NOT EXISTS topology_edges(
          id INTEGER PRIMARY KEY,src_device_id INTEGER,dst_device_id INTEGER,kind TEXT,detail TEXT,
          UNIQUE(src_device_id,dst_device_id,kind))""")
        edge_count=0
        for ip in neighbors:
            if ip in byip and ip != d["ip"]:
                db.execute("""INSERT OR IGNORE INTO topology_edges(src_device_id,dst_device_id,kind,detail)
                    VALUES(?,?,?,?)""",(d["id"],byip[ip]["id"],"L2","CDP/LLDP discovered"))
                edge_count+=1
        ts=datetime.now(timezone.utc).isoformat(timespec="seconds")
        summary=(version[:500] if version else "Authenticated; show version returned no data")
        db.execute("UPDATE devices SET device_type=?,auth_status='PASS',auth_detail=?,last_collection=?,platform_info=? WHERE id=?",
                   (dtype,"Collection completed",ts,summary,d["id"]))
        db.execute("INSERT INTO evidence(device_id,check_type,status,value,detail) VALUES(?,?,?,?,?)",
                   (d["id"],"COLLECT","PASS",f"IFACES={len(iface_rows)}; ARP={arp_count}; neighbors={len(neighbors)}",
                    "interactive IOS collection completed; raw CLI evidence preserved"))
        db.commit()
        return True,{"interfaces":len(iface_rows),"arp":arp_count,"neighbors":len(neighbors),"edges":edge_count,"device_type":dtype}
    except Exception as e:
        db.execute("UPDATE devices SET auth_status='PASS',auth_detail=? WHERE id=?",("Auth passed; collection failed: "+str(e)[:200],d["id"]))
        db.execute("INSERT INTO evidence(device_id,check_type,status,detail) VALUES(?,?,?,?)",(d["id"],"COLLECT","FAIL",str(e)[:240]))
        db.commit(); return False,{"error":str(e)[:240]}


def _v134_norm_mac(mac):
    import re
    h=re.sub(r"[^0-9A-Fa-f]","",mac or "").lower()
    return ":".join(h[i:i+2] for i in range(0,12,2)) if len(h)==12 else (mac or "").lower()

def _v134_arp(text):
    import re
    rx=re.compile(r"^Internet\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+([0-9a-fA-F.:-]+)\s+\S+\s+(\S+)",re.M)
    return [{"ip":ip,"mac":_v134_norm_mac(mac),"interface":intf} for ip,age,mac,intf in rx.findall(text or "")]

def _v135_cdp(text, observer):
    import re
    out=[]
    for b in re.split(r"-{5,}", text or ""):
        dev=re.search(r"Device ID:\s*(\S+)",b); ip=re.search(r"IP address:\s*(\d+\.\d+\.\d+\.\d+)",b)
        plat=re.search(r"Platform:\s*([^,\n]+)",b)
        ports=re.search(r"Interface:\s*([^,\n]+),\s*Port ID \(outgoing port\):\s*([^\n]+)",b)
        if dev and ip:
            out.append({"source":observer,"target":ip.group(1),"name":dev.group(1).split(".")[0],
                        "platform":plat.group(1).strip() if plat else "",
                        "local_port":ports.group(1).strip() if ports else "",
                        "remote_port":ports.group(2).strip() if ports else "",
                        "evidence":"CDP","confidence":"VERIFIED"})
    return out

def _v135_cam(text):
    import re
    rx=re.compile(r"^\s*(\d+)\s+([0-9a-fA-F.:-]{12,17})\s+(?:DYNAMIC|STATIC|SELF)\s+(\S+)",re.M|re.I)
    return {_v134_norm_mac(mac):port for vlan,mac,port in rx.findall(text or "")}

def _v135_wifi_macs(text):
    """Extract associated station MACs from several autonomous-IOS dot11 formats."""
    import re
    found=set()
    for m in re.findall(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![0-9A-Fa-f])",text or ""):
        found.add(_v134_norm_mac(m))
    for m in re.findall(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])",text or ""):
        found.add(_v134_norm_mac(m))
    return found

def _v135_desc(text):
    """Return interface -> description without depending on fixed IOS column widths."""
    import re
    out={}
    for line in (text or "").replace("\r","").splitlines():
        if not re.match(r"^(Gi|GigabitEthernet|Fa|FastEthernet|Te|TenGigabitEthernet|Eth|Ethernet|Se|Serial|Vl|Vlan|BV|BVI)",line,re.I):
            continue
        p=line.split()
        if len(p)>=4:
            # Interface Status Protocol Description... ; description may be absent.
            out[p[0]]=" ".join(p[3:])
    return out

def _v135_short_if(name):
    import re
    x=(name or "").strip()
    reps=((r"^GigabitEthernet","Gi"),(r"^FastEthernet","Fa"),(r"^TenGigabitEthernet","Te"),(r"^Ethernet","Eth"))
    for pat,r in reps: x=re.sub(pat,r,x,flags=re.I)
    return x.lower()


def _parse_interface_inventory(brief_text, desc_text):
    """Parse Cisco-style interface brief/description evidence without assuming fixed widths."""
    import re
    inv={}

    # show ip interface brief
    for raw in (brief_text or "").replace("\r","").splitlines():
        line=raw.strip()
        if not line:
            continue
        low=line.lower()
        if low.startswith(("interface ", "show ip interface", "protocol")):
            continue
        # Interface IP-Address OK? Method Status Protocol
        # Status can be "administratively down", so anchor from both ends.
        m=re.match(r"^(\S+)\s+(\S+)\s+\S+\s+\S+\s+(.+?)\s+(up|down)$", line, re.I)
        if not m:
            continue
        name,ip,status,proto=m.group(1),m.group(2),m.group(3).strip(),m.group(4).lower()
        if ip!="unassigned" and not re.match(r"^\d+\.\d+\.\d+\.\d+$",ip):
            continue
        inv[name]={"name":name,"ip":"" if ip=="unassigned" else ip,
                   "status":status,"protocol":proto,"description":""}

    # show interfaces description
    for raw in (desc_text or "").replace("\r","").splitlines():
        line=raw.rstrip()
        if not line.strip() or line.lstrip().lower().startswith(("interface ", "show interfaces")):
            continue
        # IOS: Interface  Status  Protocol  Description
        m=re.match(r"^(\S+)\s+(.+?)\s+(up|down)\s*(.*)$", line.strip(), re.I)
        if not m:
            continue
        name,status,proto,description=m.group(1),m.group(2).strip(),m.group(3).lower(),m.group(4).strip()
        match=next((k for k in inv if _v135_short_if(k)==_v135_short_if(name)),None)
        key=match or name
        if key not in inv:
            inv[key]={"name":name,"ip":"","status":status,"protocol":proto,"description":description}
        else:
            inv[key]["status"]=inv[key]["status"] or status
            inv[key]["protocol"]=inv[key]["protocol"] or proto
            inv[key]["description"]=description

    return sorted(inv.values(),key=lambda x:x["name"].lower())


def sync_interface_inventory(db, device_id, brief_text, desc_text, source="CLI"):
    """Persist learned interfaces so topology/editor does not depend on reparsing evidence on every request."""
    rows=_parse_interface_inventory(brief_text,desc_text)
    for x in rows:
        db.execute("""INSERT INTO device_interfaces(device_id,name,ip_address,status,protocol,description,source,last_seen)
                      VALUES(?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
                      ON CONFLICT(device_id,name) DO UPDATE SET
                        ip_address=excluded.ip_address,status=excluded.status,protocol=excluded.protocol,
                        description=excluded.description,source=excluded.source,last_seen=CURRENT_TIMESTAMP""",
                   (device_id,x["name"],x.get("ip",""),x.get("status",""),x.get("protocol",""),
                    x.get("description",""),source))
    return rows


def interface_inventory(db, device_id):
    """Return all known interfaces. Backfill persistent inventory from latest raw CLI evidence when needed."""
    persisted=[dict(r) for r in db.execute(
        """SELECT name,COALESCE(ip_address,'') ip,COALESCE(status,'') status,
                  COALESCE(protocol,'') protocol,COALESCE(description,'') description
           FROM device_interfaces WHERE device_id=? ORDER BY lower(name)""",(device_id,)).fetchall()]
    if persisted:
        return persisted

    rows=db.execute("""SELECT check_type,detail FROM evidence
                       WHERE device_id=? AND check_type IN ('CLI-INTERFACES','CLI-INTERFACE_DESC')
                       ORDER BY id DESC""",(device_id,)).fetchall()
    latest={}
    for r in rows:
        if r["check_type"] not in latest:
            latest[r["check_type"]]=r["detail"] or ""
    parsed=sync_interface_inventory(db,device_id,
                                    latest.get("CLI-INTERFACES",""),
                                    latest.get("CLI-INTERFACE_DESC",""),
                                    source="EVIDENCE-BACKFILL")
    if parsed:
        db.commit()
    return parsed


def topology_model(db):
    """Evidence-first topology model.

    CDP/LLDP is a verified adjacency, but a CDP adjacency does not prove a direct
    cable.  If the same local router interface also sees multiple ARP endpoints,
    insert an inferred transparent L2 segment between the router and its CDP peer.
    Wireless association evidence then hangs stations below the AP.  Remaining
    ARP observations stay grouped on the inferred switch/segment rather than being
    rendered as fake point-to-point cables.
    """
    ds=[dict(x) for x in db.execute("SELECT * FROM devices ORDER BY ip").fetchall()]
    nodes={d["ip"]:{"key":d["ip"],"ip":d["ip"],"device_id":d["id"],
      "name":d.get("display_name") or d.get("hostname") or d["ip"],
      "role":(d.get("device_type") or "host").lower(),"status":d.get("status") or "unknown"} for d in ds}
    cli={}; arps={}; cdps={}; wifi={}; desc={}
    for d in ds:
        ev={}
        rows=db.execute("""SELECT check_type,detail FROM evidence WHERE device_id=? AND check_type LIKE 'CLI-%'
                           ORDER BY id DESC""",(d["id"],)).fetchall()
        for r in rows:
            if r["check_type"] not in ev: ev[r["check_type"]]=r["detail"] or ""
        cli[d["ip"]]=ev
        arps[d["ip"]]=_v134_arp(ev.get("CLI-ARP",""))
        cdps[d["ip"]]=_v135_cdp(ev.get("CLI-CDP","")+"\n"+ev.get("CLI-LLDP",""),d["ip"])
        wifi[d["ip"]]=_v135_wifi_macs(ev.get("CLI-WIFI_ASSOC",""))
        desc[d["ip"]]=_v135_desc(ev.get("CLI-INTERFACE_DESC",""))

    links=[]; groups=[]; linked=set()
    # Ensure CDP targets exist before building hierarchy.
    for src, peers in cdps.items():
        for p in peers:
            if p["target"] not in nodes:
                role="ap" if any(x in p["platform"].upper() for x in ("AIR-AP","C1140")) else "network"
                nodes[p["target"]]={"key":p["target"],"ip":p["target"],"device_id":None,"name":p["name"],"role":role,"status":"observed"}

    # MAC -> IP correlation from all ARP evidence; used for wireless stations.
    mac_ip={}
    for rows in arps.values():
        for a in rows:
            if a["mac"]: mac_ip[a["mac"]]=a["ip"]

    for src, peers in cdps.items():
        for p in peers:
            local=_v135_short_if(p.get("local_port"))
            same=[a for a in arps.get(src,[]) if _v135_short_if(a.get("interface"))==local and a["ip"]!=src]
            # Transparent-switch signature: verified CDP peer plus other L3 endpoints
            # observed through the exact same router interface.
            other=[a for a in same if a["ip"]!=p["target"]]
            if other:
                skey=f"segment:{src}:{local}"
                if skey not in nodes:
                    dtext=""
                    for k,v in desc.get(src,{}).items():
                        if _v135_short_if(k)==local: dtext=v; break
                    nodes[skey]={"key":skey,"ip":"","device_id":None,
                      "name":dtext if dtext and not dtext.lower().startswith("to inside") else "Unmanaged L2 Switch",
                      "role":"switch","status":"inferred"}
                links.append({"source":src,"target":skey,"label":p.get("local_port","")+ (" · "+desc[src].get(p.get("local_port",""),"") if desc.get(src,{}).get(p.get("local_port","")) else ""),
                              "evidence":"CDP+ARP","confidence":"INFERRED"})
                links.append({"source":skey,"target":p["target"],"label":p.get("remote_port",""),
                              "evidence":"CDP","confidence":"VERIFIED"})
                linked.add(p["target"])
                # Associated stations belong below the AP; everything else remains
                # an observation of the transparent L2 segment.
                assoc=[]
                for mac in wifi.get(p["target"],set()):
                    ip=mac_ip.get(mac)
                    if ip and ip not in (src,p["target"]):
                        if ip not in nodes: nodes[ip]={"key":ip,"ip":ip,"device_id":None,"name":ip,"role":"host","status":"observed"}
                        assoc.append(ip)
                # An AP bridges its wireless clients into BVI1.  When the
                # CDP peer on this shared L2 segment is an AP, treat endpoints
                # observed through that segment as members of the AP bridge
                # domain instead of inventing point-to-point AP links or a
                # separate "Unmanaged L2 Switch" observation cloud.
                peer_role=(nodes.get(p["target"],{}).get("role") or "").lower()

                if peer_role == "ap":
                    bvi_members=set(assoc)

                    # The router ARP table sees bridged wireless stations on
                    # the same L2 segment.  Fold those observations into BVI1.
                    for a in other:
                        ip=a.get("ip")
                        if ip and ip not in (src,p["target"]):
                            bvi_members.add(ip)

                    if bvi_members:
                        groups.append({
                            "source":p["target"],
                            "interface":"BVI1",
                            "members":sorted(bvi_members)
                        })

                        # Prevent generic ARP grouping from rebuilding these
                        # stations elsewhere later in topology_model().
                        for ip in bvi_members:
                            linked.add(ip)

                else:
                    # Non-AP peers retain the normal transparent-L2 behavior.
                    wired=[a["ip"] for a in other if a["ip"] not in assoc]
                    if wired:
                        groups.append({
                            "source":skey,
                            "interface":"Wired / L2 observed",
                            "members":sorted(set(wired))
                        })
            else:
                links.append({"source":src,"target":p["target"],"label":((p.get("local_port","")+" ↔ "+p.get("remote_port",""))).strip(" ↔"),
                              "evidence":p["evidence"],"confidence":p["confidence"]})
                linked.add(p["target"])

    # ARP evidence on interfaces not consumed above remains grouped. This includes
    # routed/upstream segments such as a firewall-facing transit network.
    consumed={(g["source"],ip) for g in groups for ip in g["members"]}
    for src, rows in arps.items():
        byif={}
        for a in rows:
            if a["ip"]==src or a["ip"] in linked or (src,a["ip"]) in consumed: continue
            if a["ip"] not in nodes: nodes[a["ip"]]={"key":a["ip"],"ip":a["ip"],"device_id":None,"name":a["ip"],"role":"host","status":"observed"}
            byif.setdefault(a.get("interface") or "unknown",[]).append(a["ip"])
        for intf,members in byif.items():
            groups.append({"source":src,"interface":intf,"members":sorted(set(members))})

    # Operator truth wins over inference. A configured adjacency removes the node
    # from observation clouds and replaces any inferred/automatic parent edge.
    manual={d["ip"]:d.get("adjacent_to") for d in ds if d.get("adjacent_to")}
    manual_rows={d["ip"]:d for d in ds if d.get("adjacent_to")}
    for child,parent in manual.items():
        if child not in nodes or parent not in nodes or child == parent:
            continue
        # Operator truth wins. Remove every automatic edge for this
        # child. Also suppress an existing inferred edge between the same
        # two nodes regardless of direction. This prevents a MANUAL edge
        # from being drawn on top of an older CDP+ARP inferred edge.
        links=[
            l for l in links
            if l.get("target") != child
            and not (
                {l.get("source"), l.get("target")} == {parent, child}
                and l.get("confidence") == "INFERRED"
            )
        ]
        for g in groups:
            g["members"]=[m for m in g["members"] if m != child]
        md=manual_rows.get(child,{})
        remote_if=md.get("adjacent_interface") or ""
        local_if=md.get("local_interface") or ""
        if local_if and remote_if:
            label=f"{remote_if} ↔ {local_if}"
        elif remote_if:
            label=remote_if
        elif local_if:
            label=local_if
        else:
            label="Operator configured"
        links.append({"source":parent,"target":child,"label":label,
                      "evidence":"MANUAL","confidence":"CONFIGURED"})
        linked.add(child)

    # Suppress redundant ARP observation groups when operator topology
    # already describes that exact physical interface.
    #
    # Example:
    #   SkyNet-FW -> SkyNet-Core-rtr Gi0/0
    #
    # Once that adjacency is explicitly configured, a separate cloud
    # containing the transit-interface ARP entries adds no topology value.
    manual_parent_interfaces=set()

    for child,parent in manual.items():
        md=manual_rows.get(child,{})
        remote_if=md.get("adjacent_interface") or ""

        if parent and remote_if:
            manual_parent_interfaces.add(
                (parent,_v135_short_if(remote_if))
            )

    filtered_groups=[]

    for g in groups:
        gsrc=g.get("source")
        gint=_v135_short_if(g.get("interface") or "")

        if (gsrc,gint) in manual_parent_interfaces:
            continue

        filtered_groups.append(g)

    groups=filtered_groups

    # De-duplicate cloud membership. Prefer the first evidence bucket so a host
    # observed by both the router and AP does not appear twice on the map.
    claimed=set(); clean=[]
    for g in groups:
        members=[]
        for m in g["members"]:
            if m in claimed or m in manual: continue
            claimed.add(m); members.append(m)
        if members:
            g=dict(g); g["members"]=members; clean.append(g)
    return {"nodes":list(nodes.values()),"links":links,"groups":clean}
