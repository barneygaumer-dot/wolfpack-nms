import smtplib
from email.message import EmailMessage
from email.utils import formataddr
from .db import get_db


def _settings(db):
    return {r["k"]: r["v"] for r in db.execute("SELECT k,v FROM settings")}


def _recipients(raw):
    raw=(raw or "").replace(";",",")
    return [x.strip() for x in raw.split(",") if x.strip()]


def send_mail(subject, body, recipients=None):
    db=get_db(); cfg=_settings(db)
    host=(cfg.get("smtp_host") or "").strip()
    port=int(cfg.get("smtp_port") or 587)
    username=(cfg.get("smtp_username") or "").strip()
    password=cfg.get("smtp_password") or ""
    from_addr=(cfg.get("smtp_from") or "").strip()
    from_name=(cfg.get("smtp_from_name") or "WolfPack NMS").strip()
    use_starttls=cfg.get("smtp_starttls","1")=="1"
    if recipients is None:
        recipients=_recipients(cfg.get("alert_recipients",""))
    elif isinstance(recipients,str):
        recipients=_recipients(recipients)
    if not host or not from_addr or not recipients:
        raise RuntimeError("SMTP host, From address, and at least one recipient are required")
    msg=EmailMessage(); msg["Subject"]=subject; msg["From"]=formataddr((from_name,from_addr)); msg["To"]=', '.join(recipients); msg.set_content(body)
    with smtplib.SMTP(host,port,timeout=15) as smtp:
        smtp.ehlo()
        if use_starttls:
            smtp.starttls(); smtp.ehlo()
        if username:
            smtp.login(username,password)
        smtp.send_message(msg)


def handle_device_transition(device, old_status, new_status, detail):
    old=(old_status or "UNKNOWN").upper(); new=(new_status or "UNKNOWN").upper()
    if old==new or (old,new) not in (("UP","DOWN"),("DOWN","UP")):
        return
    group_id=device["alert_group_id"] if "alert_group_id" in device.keys() else None
    if not group_id:
        return
    db=get_db()
    group=db.execute("SELECT * FROM alert_groups WHERE id=? AND enabled=1",(group_id,)).fetchone()
    if not group or not _recipients(group["recipients"]):
        return
    name=device["display_name"] or device["hostname"] or device["ip"]
    if new=="DOWN":
        opened=db.execute("SELECT id FROM active_alerts WHERE device_id=? AND alert_type='DEVICE_DOWN' AND status='OPEN' ORDER BY id DESC LIMIT 1",(device["id"],)).fetchone()
        if opened: return
        cur=db.execute("INSERT INTO active_alerts(device_id,alert_group_id,opened_at,down_detail) VALUES(?,?,datetime('now'),?)",(device["id"],group_id,detail))
        aid=cur.lastrowid; db.commit()
        subject=f"WolfPack NMS — DOWN — {name}"
        body=f"Device: {name}\nIP: {device['ip']}\nState: DOWN\nAlert Group: {group['name']}\nEvidence: {detail}\n\nWolfPack NMS will remain silent until the state changes."
        try:
            send_mail(subject,body,group["recipients"])
            db.execute("INSERT INTO evidence(device_id,check_type,status,detail) VALUES(?,?,?,?)",(device["id"],"ALERT-EMAIL-DOWN","PASS",f"Alert {aid} sent to {group['recipients']}"))
        except Exception as e:
            db.execute("INSERT INTO evidence(device_id,check_type,status,detail) VALUES(?,?,?,?)",(device["id"],"ALERT-EMAIL-DOWN","FAIL",str(e)[:500]))
        db.commit()
    else:
        alert=db.execute("SELECT * FROM active_alerts WHERE device_id=? AND alert_type='DEVICE_DOWN' AND status='OPEN' ORDER BY id DESC LIMIT 1",(device["id"],)).fetchone()
        if not alert: return
        db.execute("UPDATE active_alerts SET status='CLEARED',cleared_at=datetime('now'),clear_detail=? WHERE id=?",(detail,alert["id"])); db.commit()
        subject=f"WolfPack NMS — CLEARED — {name}"
        body=f"Device: {name}\nIP: {device['ip']}\nState: UP / ALERT CLEARED\nAlert Group: {group['name']}\nOpened: {alert['opened_at']} UTC\nEvidence: {detail}\n"
        try:
            send_mail(subject,body,group["recipients"])
            db.execute("INSERT INTO evidence(device_id,check_type,status,detail) VALUES(?,?,?,?)",(device["id"],"ALERT-EMAIL-CLEAR","PASS",f"Alert {alert['id']} clear sent to {group['recipients']}"))
        except Exception as e:
            db.execute("INSERT INTO evidence(device_id,check_type,status,detail) VALUES(?,?,?,?)",(device["id"],"ALERT-EMAIL-CLEAR","FAIL",str(e)[:500]))
        db.commit()
