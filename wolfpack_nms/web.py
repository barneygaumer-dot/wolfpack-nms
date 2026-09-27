import os,subprocess,tempfile
from pathlib import Path
from flask import Blueprint,jsonify,redirect,render_template,request,url_for,flash,abort
from .db import get_db
from .engine import discover,check_device,run_synthetic
from .topology import build_topology,test_ssh,collect_one
bp=Blueprint("web",__name__)
def devices(): return get_db().execute("SELECT * FROM devices ORDER BY ip").fetchall()
@bp.get("/")
def index():
    db=get_db()
    ds=[dict(x) for x in devices()]

    def classify(d):
        # Explicit operator classification is authoritative.
        # Auto-detection is only used when Platform / Class is unset.
        platform_class=str(d.get("platform_class") or "").strip().lower()

        if platform_class in ("windows","nix","network","iot"):
            return platform_class

        dtype=str(d.get("device_type") or "").strip().lower()

        text=" ".join(str(d.get(x) or "") for x in (
            "hostname","display_name","description",
            "vendor","model","platform_info"
        )).lower()

        if dtype in ("router","firewall","switch","ap","network"):
            return "network"

        if dtype=="iot":
            return "iot"

        if "windows" in text or "microsoft" in text:
            return "windows"

        if any(x in text for x in (
            "linux","ubuntu","debian","fedora","red hat",
            "rhel","centos","rocky","alma","unix","freebsd"
        )):
            return "nix"

        return "other"

    groups={
        "windows":[],
        "nix":[],
        "network":[],
        "iot":[],
        "other":[]
    }

    for d in ds:
        d["dashboard_group"]=classify(d)
        groups[d["dashboard_group"]].append(d)

    def group_stats(items):
        up=sum(1 for d in items if str(d.get("status") or "").upper()=="UP")
        down=sum(1 for d in items if str(d.get("status") or "").upper()=="DOWN")
        other=len(items)-up-down

        return {
            "total":len(items),
            "up":up,
            "down":down,
            "other":other,
            "health":round((up/len(items))*100,1) if items else None
        }

    group_stats_map={k:group_stats(v) for k,v in groups.items()}

    total=len(ds)
    up=sum(1 for d in ds if str(d.get("status") or "").upper()=="UP")
    down=sum(1 for d in ds if str(d.get("status") or "").upper()=="DOWN")
    other=total-up-down

    health={
        "total":total,
        "up":up,
        "down":down,
        "other":other,
        "percent":round((up/total)*100,1) if total else 0
    }

    # Poll evidence for the trailing 24 hours plus the most recent
    # pre-window result for each device.  The pre-window observation
    # establishes the device state at the beginning of the chart.
    history=[
        dict(r) for r in db.execute("""
            SELECT ts,device_id,status,value
            FROM evidence
            WHERE check_type LIKE 'POLL-%'
              AND ts >= datetime('now','-24 hours')

            UNION ALL

            SELECT e.ts,e.device_id,e.status,e.value
            FROM evidence e
            WHERE e.id=(
                SELECT e2.id
                FROM evidence e2
                WHERE e2.device_id=e.device_id
                  AND e2.check_type LIKE 'POLL-%'
                  AND e2.ts < datetime('now','-24 hours')
                ORDER BY e2.ts DESC,e2.id DESC
                LIMIT 1
            )

            ORDER BY ts
        """).fetchall()
    ]

    return render_template(
        "index.html",
        devices=ds,
        groups=groups,
        group_stats=group_stats_map,
        health=health,
        history=history,
        tab="dashboard"
    )
@bp.get("/devices")
def device_list():
    ds=[dict(x) for x in devices()]
    return render_template(
        "devices.html",
        devices=ds,
        tab="devices"
    )

@bp.post("/discover")
def disc():
    try: flash(f"Discovery complete: {discover(request.form['cidr'])} responding devices.")
    except Exception as e: flash(f"Discovery failed: {e}")
    return redirect(url_for("web.index"))
@bp.post("/poll")
def poll():
    db=get_db()
    for d in devices(): check_device(d)
    for s in db.execute("SELECT * FROM synthetics WHERE enabled=1").fetchall(): run_synthetic(s)
    flash("Poll complete; evidence recorded."); return redirect(url_for("web.index"))
@bp.post("/synthetic")
def synthetic():
    db=get_db(); db.execute("INSERT INTO synthetics(name,kind,target,port) VALUES(?,?,?,?)",(request.form["name"],request.form["kind"],request.form["target"],request.form.get("port") or None)); db.commit()
    flash("Synthetic added."); return redirect(url_for("web.index"))
@bp.route("/device/<int:i>",methods=["GET","POST"])
def device(i):
    db=get_db(); d=db.execute("SELECT * FROM devices WHERE id=?",(i,)).fetchone()
    if not d: abort(404)
    if request.method=="POST":
        fields=["hostname","display_name","description","device_type","platform_class","location","vendor","model","snmp_version","snmp_community","snmp_port","notes","ssh_enabled","ssh_username","ssh_password","ssh_port","mgmt_role","adjacent_to","adjacent_interface","local_interface","poll_method","poll_port","arp_fallback","arp_interface","alert_group_id"]
        checkbox_fields={"ssh_enabled","arp_fallback"}
        vals=[(1 if request.form.get(x)=="on" else 0) if x in checkbox_fields else (request.form.get(x) or None) for x in fields]
        db.execute("UPDATE devices SET "+",".join(f"{x}=?" for x in fields)+" WHERE id=?",vals+[i]); db.commit()
        flash("Node configuration saved."); return redirect(url_for("web.device",i=i))
    ev=db.execute("SELECT * FROM evidence WHERE device_id=? ORDER BY id DESC LIMIT 20",(i,)).fetchall()
    
    from .topology import topology_model,interface_inventory
    topo=topology_model(db)
    adjacency_choices=[n for n in topo["nodes"] if (n.get("key") != d["ip"] and n.get("role") in ("router","switch","firewall","ap","network"))]
    adjacent_interfaces=[]
    if d["adjacent_to"]:
        parent=db.execute("SELECT id FROM devices WHERE ip=?",(d["adjacent_to"],)).fetchone()
        if parent: adjacent_interfaces=interface_inventory(db,parent["id"])
    local_interfaces=interface_inventory(db,d["id"])
    alert_groups=db.execute("SELECT * FROM alert_groups WHERE enabled=1 ORDER BY name").fetchall()
    return render_template("device.html",d=d,evidence=ev,adjacency_choices=adjacency_choices,
                           adjacent_interfaces=adjacent_interfaces,local_interfaces=local_interfaces,
                           alert_groups=alert_groups,tab="devices")
@bp.post("/device/<int:i>/test-auth")
def test_auth(i):
    db=get_db(); d=db.execute("SELECT * FROM devices WHERE id=?",(i,)).fetchone()
    if not d: abort(404)
    ok,detail=test_ssh(d)
    db.execute("UPDATE devices SET auth_status=?,auth_detail=? WHERE id=?",("PASS" if ok else "FAIL",detail,i))
    db.execute("INSERT INTO evidence(device_id,check_type,status,detail) VALUES(?,?,?,?)",(i,"SSH-AUTH","PASS" if ok else "FAIL",detail)); db.commit()
    flash(("✓ " if ok else "✗ ")+detail); return redirect(url_for("web.device",i=i))

@bp.post("/device/<int:i>/collect")
def collect_device(i):
    ok,result=collect_one(i)
    flash(("✓ Collection complete: " if ok else "✗ Collection failed: ")+str(result))
    return redirect(url_for("web.device",i=i))

@bp.route("/map",methods=["GET","POST"])
def network_map():
    from .topology import topology_model
    db=get_db()
    if request.method=="POST":
        build_topology(); flash("Topology discovery completed.")
        return redirect(url_for("web.network_map"))
    return render_template("map.html",topology=topology_model(db),tab="map")

@bp.route("/admin",methods=["GET","POST"])
def admin():
    db=get_db()
    if request.method=="POST":
        # Text / numeric settings
        for k in ("site_name","default_cidr","poll_seconds","smtp_host","smtp_port","smtp_username","smtp_password","smtp_from_name","smtp_from","alert_group_name","alert_recipients"):
            db.execute(
                "INSERT INTO settings(k,v) VALUES(?,?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (k,request.form.get(k,""))
            )

        # Polling feature switches. Unchecked HTML checkboxes are absent
        # from request.form, so persist them explicitly as 1/0.
        for k in ("poll_enabled","poll_icmp","poll_snmp","poll_synthetics"):
            v="1" if request.form.get(k)=="1" else "0"
            db.execute(
                "INSERT INTO settings(k,v) VALUES(?,?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (k,v)
            )

        # v1 alert group: one configurable group. Keep its stable ID so
        # device assignments survive renames.
        group_name=(request.form.get("alert_group_name") or "NOC").strip()
        recipients=(request.form.get("alert_recipients") or "").strip()
        group_enabled=1 if request.form.get("alert_group_enabled")=="1" else 0
        db.execute("UPDATE alert_groups SET name=?,enabled=?,recipients=? WHERE id=1",(group_name,group_enabled,recipients))
        db.execute("INSERT INTO settings(k,v) VALUES('smtp_starttls',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",("1" if request.form.get("smtp_starttls")=="1" else "0",))
        db.commit()
        flash("Admin settings saved.")
    settings={r["k"]:r["v"] for r in db.execute("SELECT * FROM settings")}
    ag=db.execute("SELECT * FROM alert_groups WHERE id=1").fetchone()
    if ag:
        settings["alert_group_name"]=ag["name"]
        settings["alert_recipients"]=ag["recipients"]
        settings["alert_group_enabled"]=str(ag["enabled"])
    return render_template("admin.html",settings=settings,tab="admin")

@bp.post("/admin/test-email")
def admin_test_email():
    from .alerts import send_mail
    db=get_db(); group=db.execute("SELECT * FROM alert_groups WHERE id=1").fetchone()
    try:
        send_mail("WolfPack NMS — Test Email","WolfPack NMS SMTP test succeeded.\n\nSemper Stateful Alerts.",group["recipients"] if group else None)
        flash("✓ Test email sent.")
    except Exception as e:
        flash("✗ Test email failed: "+str(e))
    return redirect(url_for("web.admin"))

@bp.get("/arp")
def arp_table():
    db=get_db()
    rows=db.execute("""SELECT a.*,d.ip observer_ip,
      COALESCE(NULLIF(d.display_name,''),NULLIF(d.hostname,''),d.ip) observer_name
      FROM arp_observations a JOIN devices d ON d.id=a.observer_device_id
      ORDER BY a.observer_device_id,a.ip""").fetchall()
    return render_template("arp.html",rows=rows,tab="arp")
@bp.post("/admin/update")
def admin_update():
    import time
    f=request.files.get("update_zip")
    if not f or not f.filename.lower().endswith(".zip"):
        flash("Select a WolfPack NMS ZIP package."); return redirect(url_for("web.admin"))
    staging=Path("/opt/wolfpack/update-staging"); staging.mkdir(parents=True,exist_ok=True)
    dest=staging/Path(f.filename).name; f.save(dest)
    updater=Path("/opt/wolfpack/updater/wolfpack-update")
    if not updater.exists():
        flash("Lifecycle installer missing at /opt/wolfpack/updater/wolfpack-update.")
        return redirect(url_for("web.admin"))

    # CRITICAL: do not spawn updater as a child of wolfpack-nms.service.
    # When the updater stops wolfpack-nms, systemd kills every process in that cgroup,
    # including a normal Popen child. A transient unit survives the application stop.
    unit="wolfpack-nms-update-"+time.strftime("%Y%m%d%H%M%S")
    cmd=["systemd-run","--unit",unit,"--collect","--property=Type=exec",
         str(updater),str(dest)]
    r=subprocess.run(cmd,capture_output=True,text=True)
    if r.returncode:
        flash("Could not launch updater: "+(r.stderr or r.stdout))
        return redirect(url_for("web.admin"))
    return f"""<!doctype html><title>WolfPack Update</title>
    <body style="background:#111;color:#eee;font-family:system-ui;padding:40px">
    <h2>🐺 WolfPack update launched</h2>
    <p>Package: <b>{dest.name}</b></p>
    <p>Updater unit: <code>{unit}</code></p>
    <p>The updater now runs outside the NMS service cgroup, so it survives the NMS restart.</p>
    <p>Wait 10–20 seconds, then <a style="color:#8ab4f8" href="/admin">return to Admin / Setup</a>.</p>
    <p>CLI evidence: <code>sudo journalctl -u {unit} --no-pager</code></p></body>"""

@bp.get("/api/device/<int:i>/interfaces")
def api_device_interfaces(i):
    from .topology import interface_inventory
    db=get_db()
    d=db.execute("SELECT id FROM devices WHERE id=?",(i,)).fetchone()
    if not d: abort(404)
    return jsonify(interface_inventory(db,i))

@bp.get("/api/device-by-key/interfaces")
def api_device_interfaces_by_key():
    from .topology import interface_inventory
    db=get_db(); key=request.args.get("key","")
    d=db.execute("SELECT id FROM devices WHERE ip=?",(key,)).fetchone()
    if not d: return jsonify([])
    return jsonify(interface_inventory(db,d["id"]))

@bp.get("/api/device/<int:i>/interface-debug")
def api_device_interface_debug(i):
    from .topology import interface_inventory
    db=get_db()
    d=db.execute("SELECT id,ip,display_name,hostname FROM devices WHERE id=?",(i,)).fetchone()
    if not d: abort(404)
    ev=[dict(r) for r in db.execute("""SELECT check_type,status,value,substr(detail,1,1200) detail
                                      FROM evidence WHERE device_id=? AND
                                      check_type IN ('CLI-INTERFACES','CLI-INTERFACE_DESC')
                                      ORDER BY id DESC LIMIT 4""",(i,)).fetchall()]
    return jsonify(device=dict(d),interfaces=interface_inventory(db,i),evidence=ev)

@bp.get("/api/health")
def health(): return jsonify(status="healthy",version="1.3.11")
@bp.get("/api/devices")
def api_devices(): return jsonify([dict(x) for x in devices()])
