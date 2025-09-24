<will be replaced>

def require_admin(request: Request):
    if not ADMIN_TOKEN:
        return
    provided = request.headers.get("X-Admin-Token") or request.query_params.get("token")
    if provided != ADMIN_TOKEN:
        raise HTTPException(401, "admin token required")

def db_file_info():
    url = str(engine.url)
    if engine.dialect.name == "sqlite":
        path = engine.url.database
        if path and path != ":memory:" and os.path.exists(path):
            try:
                size = os.path.getsize(path)
            except Exception:
                size = None
            return {"type":"sqlite","path":path,"size_bytes":size}
        return {"type":"sqlite","path":engine.url.database,"size_bytes":None}
    if engine.dialect.name.startswith("postgres"):
        with engine.begin() as conn:
            try:
                sz = conn.execute(text("SELECT pg_database_size(current_database())")).scalar()
            except Exception:
                sz = None
        return {"type":"postgres","size_bytes":int(sz) if sz is not None else None}
    if engine.dialect.name.startswith("mysql"):
        with engine.begin() as conn:
            try:
                sz = conn.execute(text("SELECT SUM(data_length + index_length) FROM information_schema.tables WHERE table_schema = DATABASE()")).scalar()
            except Exception:
                sz = None
        return {"type":"mysql","size_bytes":int(sz) if sz is not None else None}
    return {"type":engine.dialect.name,"size_bytes":None}

def get_db_version_conn(conn) -> int:
    try:
        cur = conn.execute(text("SELECT value FROM meta WHERE key='db_version'"))
        row = cur.first()
        if row and row[0]:
            return int(row[0])
    except Exception:
        pass
    try:
        cols = {c['name'] for c in inspect(conn).get_columns('tasks')}
        if 'last_done_at' in cols and 'created_at' in cols and 'updated_at' in cols:
            return 2
    except Exception:
        pass
    return 1

def set_db_version_conn(conn, v: int):
    try:
        cur = conn.execute(text("SELECT 1 FROM meta WHERE key='db_version'"))
        if cur.first():
            conn.execute(text("UPDATE meta SET value=:v WHERE key='db_version'"), {"v": str(v)})
        else:
            conn.execute(text("INSERT INTO meta(key,value) VALUES('db_version', :v)"), {"v": str(v)})
    except Exception:
        pass

def migrate_to_required():
    with engine.begin() as conn:
        current = get_db_version_conn(conn)
        if current >= REQUIRED_DB_VERSION:
            return {"migrated": False, "from": current, "to": current}
        if current < 2:
            dialect = conn.dialect.name
            def coltype():
                return "TEXT" if dialect == "sqlite" else "TIMESTAMPTZ"
            try:
                conn.execute(text(f"ALTER TABLE tasks ADD COLUMN IF NOT EXISTS last_done_at {coltype()}"))
            except Exception:
                conn.execute(text(f"ALTER TABLE tasks ADD COLUMN last_done_at {coltype()}"))
            default_sql = "DEFAULT (CURRENT_TIMESTAMP)" if dialect == "sqlite" else "DEFAULT NOW()"
            try:
                conn.execute(text(f"ALTER TABLE tasks ADD COLUMN IF NOT EXISTS created_at {coltype()} {default_sql}"))
            except Exception:
                conn.execute(text(f"ALTER TABLE tasks ADD COLUMN created_at {coltype()} {default_sql}"))
            try:
                conn.execute(text(f"ALTER TABLE tasks ADD COLUMN IF NOT EXISTS updated_at {coltype()}"))
            except Exception:
                conn.execute(text(f"ALTER TABLE tasks ADD COLUMN updated_at {coltype()}"))
            set_db_version_conn(conn, 2)
            current = 2
        return {"migrated": True, "from": current, "to": REQUIRED_DB_VERSION}


@app.get("/admin", response_class=FileResponse)
def admin_page():
    return FileResponse(STATIC_DIR / "admin.html")

@app.get("/api/admin/info")
def admin_info(request: Request):
    require_admin(request)
    info = db_file_info()
    with engine.begin() as conn:
        cur = get_db_version_conn(conn)
    obsolete = cur < REQUIRED_DB_VERSION
    return {
        "dialect": engine.dialect.name,
        "db_url": str(engine.url).split('@')[-1],
        "size_bytes": info.get("size_bytes"),
        "sqlite_file": info.get("path") if info.get("type") == "sqlite" else None,
        "current_version": cur,
        "required_version": REQUIRED_DB_VERSION,
        "obsolete": obsolete
    }

@app.post("/api/admin/upgrade")
def admin_upgrade(request: Request):
    require_admin(request)
    return migrate_to_required()

@app.get("/api/admin/export/json")
def export_json(request: Request):
    require_admin(request)
    with engine.begin() as conn:
        rows = list(conn.execute(text("SELECT id,name,type,subtype,url,description,tags,recurrence_mode,recurrence_params,due_at,next_due_at,last_done_at,created_at,updated_at FROM tasks")))
        tasks = []
        for r in rows:
            tasks.append({k: r[i].isoformat() if hasattr(r[i], 'isoformat') and r[i] is not None else r[i]
                          for i, k in enumerate(["id","name","type","subtype","url","description","tags","recurrence_mode","recurrence_params","due_at","next_due_at","last_done_at","created_at","updated_at"])})
        try:
            meta = list(conn.execute(text("SELECT key,value FROM meta")))
            meta = [{"key": k, "value": v} for (k, v) in meta]
        except Exception:
            meta = []
        payload = {
            "exported_at": datetime.utcnow().isoformat()+"Z",
            "dialect": engine.dialect.name,
            "current_version": get_db_version_conn(conn),
            "required_version": REQUIRED_DB_VERSION,
            "tasks": tasks,
            "meta": meta
        }
    buf = io.BytesIO(json.dumps(payload, separators=(",",":")).encode("utf-8"))
    return StreamingResponse(buf, media_type="application/json", headers={"Content-Disposition":"attachment; filename=timeboard-export.json"})

@app.get("/api/admin/export/sqlite")
def export_sqlite(request: Request):
    require_admin(request)
    info = db_file_info()
    if info.get("type") != "sqlite" or not info.get("path") or not os.path.exists(info["path"]):
        raise HTTPException(400, "Not a file-based SQLite database")
    return FileResponse(info["path"], filename="timeboard.db")

@app.post("/api/admin/import/json")
async def import_json(request: Request):
    require_admin(request)
    replace = request.query_params.get("replace") in {"1","true","yes"}
    try:
        body = await request.body()
        data = json.loads(body.decode("utf-8"))
    except Exception:
        raise HTTPException(400, "Invalid JSON")
    if not isinstance(data, dict) or "tasks" not in data:
        raise HTTPException(400, "Invalid export format")
    tasks = data.get("tasks") or []
    meta = data.get("meta") or []
    with engine.begin() as conn:
        if replace:
            try:
                conn.execute(text("DELETE FROM tasks"))
            except Exception:
                pass
            try:
                conn.execute(text("DELETE FROM meta"))
            except Exception:
                pass
        for m in meta:
            k = m.get("key"); v = m.get("value")
            if not k: continue
            try:
                conn.execute(text("INSERT INTO meta(key,value) VALUES(:k,:v) ON CONFLICT(key) DO UPDATE SET value=excluded.value")), {"k":k,"v":v}
            except Exception:
                try:
                    exists = conn.execute(text("SELECT 1 FROM meta WHERE key=:k"), {"k":k}).first()
                    if exists:
                        conn.execute(text("UPDATE meta SET value=:v WHERE key=:k"), {"k":k,"v":v})
                    else:
                        conn.execute(text("INSERT INTO meta(key,value) VALUES(:k,:v)"), {"k":k,"v":v})
                except Exception:
                    pass
        for t in tasks:
            fields = ["id","name","type","subtype","url","description","tags","recurrence_mode","recurrence_params","due_at","next_due_at","last_done_at","created_at","updated_at"]
            vals = {k: t.get(k) for k in fields}
            for k in ["due_at","next_due_at","last_done_at","created_at","updated_at"]:
                if vals.get(k):
                    try:
                        vals[k] = datetime.fromisoformat(vals[k].replace("Z","+00:00"))
                    except Exception:
                        vals[k] = None
            cols = ",".join([k for k in fields if vals.get(k) is not None and k != "id"])
            params = {k: v for k,v in vals.items() if v is not None and k != "id"}
            if replace and vals.get("id") is not None:
                cols = "id," + cols
                params["id"] = vals["id"]
            placeholders = ",".join([f":{k}" for k in params.keys()])
            try:
                conn.execute(text(f"INSERT INTO tasks ({cols}) VALUES ({placeholders})"), params)
            except Exception:
                conn.execute(text("INSERT INTO tasks (name,recurrence_mode) VALUES (:name,:mode)"), {"name": vals.get("name") or "Imported", "mode": vals.get("recurrence_mode") or "none"})
    return {"status":"ok"}

@app.get("/admin/docs", response_class=FileResponse)
def admin_docs_page_alias():
    return FileResponse(STATIC_DIR / "admin_docs.html")

@app.get("/admin/db", response_class=FileResponse)
def admin_db_page():
    return FileResponse(STATIC_DIR / "admin_db.html")
