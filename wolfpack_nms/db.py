import os,sqlite3
from flask import g
DB=os.environ.get("WOLFPACK_NMS_DB",os.path.join(os.path.dirname(os.path.dirname(__file__)),"wolfpack.db"))
SCHEMA="""
CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY,ip TEXT UNIQUE NOT NULL,hostname TEXT,status TEXT DEFAULT 'UNKNOWN',latency_ms REAL,first_seen TEXT DEFAULT CURRENT_TIMESTAMP,last_seen TEXT);
CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY,ts TEXT DEFAULT CURRENT_TIMESTAMP,device_id INTEGER,check_type TEXT,status TEXT,value TEXT,detail TEXT);
CREATE TABLE IF NOT EXISTS synthetics(id INTEGER PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,target TEXT NOT NULL,port INTEGER,enabled INTEGER DEFAULT 1,last_status TEXT DEFAULT 'UNKNOWN',last_value TEXT,last_run TEXT);
CREATE TABLE IF NOT EXISTS arp_observations(
 id INTEGER PRIMARY KEY, observer_device_id INTEGER NOT NULL, ip TEXT NOT NULL, mac TEXT,
 interface TEXT, age TEXT, first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
 last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(observer_device_id,ip,mac));
CREATE TABLE IF NOT EXISTS device_interfaces(
 id INTEGER PRIMARY KEY,
 device_id INTEGER NOT NULL,
 name TEXT NOT NULL,
 ip TEXT,
 status TEXT,
 protocol TEXT,
 description TEXT,
 source TEXT DEFAULT 'CLI',
 last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(device_id,name));
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT);
CREATE TABLE IF NOT EXISTS alert_groups(
 id INTEGER PRIMARY KEY,
 name TEXT UNIQUE NOT NULL,
 enabled INTEGER DEFAULT 1,
 recipients TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS active_alerts(
 id INTEGER PRIMARY KEY,
 device_id INTEGER NOT NULL,
 alert_group_id INTEGER NOT NULL,
 alert_type TEXT NOT NULL DEFAULT 'DEVICE_DOWN',
 opened_at TEXT NOT NULL,
 cleared_at TEXT,
 status TEXT NOT NULL DEFAULT 'OPEN',
 down_detail TEXT,
 clear_detail TEXT
);
INSERT OR IGNORE INTO alert_groups(id,name,enabled,recipients) VALUES(1,'NOC',1,'');
INSERT OR IGNORE INTO settings(k,v) VALUES('version','1.1.0');
"""
DEVICE_COLUMNS={"display_name":"TEXT","description":"TEXT","device_type":"TEXT","location":"TEXT","vendor":"TEXT","model":"TEXT","snmp_version":"TEXT DEFAULT 'v2c'","snmp_community":"TEXT","snmp_port":"INTEGER DEFAULT 161","notes":"TEXT","ssh_enabled":"INTEGER DEFAULT 0","ssh_username":"TEXT","ssh_password":"TEXT","ssh_port":"INTEGER DEFAULT 22","mgmt_role":"TEXT","auth_status":"TEXT","auth_detail":"TEXT",
"last_collection":"TEXT","platform_info":"TEXT","platform_class":"TEXT","adjacent_to":"TEXT","adjacent_interface":"TEXT","local_interface":"TEXT",
"poll_method":"TEXT DEFAULT 'ICMP'","poll_port":"INTEGER","arp_fallback":"INTEGER DEFAULT 0","arp_interface":"TEXT","alert_group_id":"INTEGER"}
def get_db():
    if "db" not in g:
        g.db=sqlite3.connect(DB,timeout=30)
        g.db.row_factory=sqlite3.Row

        # WolfPack NMS may have concurrent readers/writers under Waitress.
        # WAL permits readers while a writer is active; busy_timeout gives
        # short-lived write contention time to clear instead of failing.
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA busy_timeout=10000")
        g.db.execute("PRAGMA foreign_keys=ON")

    return g.db

def close_db(e=None):
    db=g.pop("db",None)
    if db is not None:
        db.close()
def init_db():
    db=get_db(); db.executescript(SCHEMA)
    cols={r["name"] for r in db.execute("PRAGMA table_info(devices)")}
    for name,decl in DEVICE_COLUMNS.items():
        if name not in cols: db.execute(f"ALTER TABLE devices ADD COLUMN {name} {decl}")
    db.execute("UPDATE settings SET v='1.3.11' WHERE k='version'"); db.commit()
