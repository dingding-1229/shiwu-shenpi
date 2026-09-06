#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""事务审批系统"""
import os
import re
import hmac
import sqlite3
import secrets
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Flask, g, request, session, redirect, url_for, render_template,
    flash, abort,
)
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "app.db")
SECRET_FILE = os.path.join(BASE_DIR, "secret.key")
TZ = timezone(timedelta(hours=8))

TYPE_EAT = "eat"
TYPE_SPEND = "spend"
TYPE_LABELS = {TYPE_EAT: "进食申请", TYPE_SPEND: "花费申请"}
ITEM_LABELS = {TYPE_EAT: "想吃什么", TYPE_SPEND: "想买什么"}

ST_PENDING = "pending"
ST_APPROVED = "approved"
ST_REJECTED = "rejected"
STATUS_LABELS = {
    ST_PENDING: "审批中",
    ST_APPROVED: "已通过",
    ST_REJECTED: "已驳回",
}

STEP_WAITING = "waiting"
STEP_CURRENT = "current"
STEP_APPROVED = "approved"
STEP_REJECTED = "rejected"

app = Flask(__name__)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
app.config["TEMPLATES_AUTO_RELOAD"] = True


def _load_secret():
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    os.makedirs(os.path.dirname(SECRET_FILE) or ".", exist_ok=True)
    fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key)
    return key


app.secret_key = _load_secret()


def now_dt():
    return datetime.now(TZ)


def now_iso():
    return now_dt().strftime("%Y-%m-%d %H:%M:%S")


def fmt_time(value):
    if not value:
        return "—"
    return str(value).replace("T", " ")


def fmt_amount(value):
    if not value:
        return "—"
    try:
        n = float(value)
        return f"{n:,.2f} 元"
    except (TypeError, ValueError):
        return str(value)


def parse_amount(raw):
    s = (raw or "").strip().replace(",", "").replace("￥", "").replace("¥", "").replace("元", "")
    if not s:
        return None
    try:
        n = float(s)
    except ValueError:
        return False
    if n <= 0 or n > 10_000_000:
        return False
    return f"{n:.2f}"


def parse_eat_time(raw):
    s = (raw or "").strip().replace("T", " ")
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            datetime.strptime(s, fmt)
            if fmt == "%Y-%m-%d":
                return s + " 00:00"
            return s[:16]
        except ValueError:
            continue
    return False


def get_db():
    if "db" not in g:
        os.makedirs(DATA_DIR, exist_ok=True)
        db = sqlite3.connect(DB_PATH, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=5000")
        g.db = db
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doc_no TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL,
            item TEXT NOT NULL,
            reason TEXT NOT NULL,
            applicant_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            finished_at TEXT,
            FOREIGN KEY (applicant_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS steps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            seq INTEGER NOT NULL,
            status TEXT NOT NULL,
            comment TEXT,
            acted_at TEXT,
            FOREIGN KEY (request_id) REFERENCES requests(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_requests_applicant ON requests(applicant_id);
        CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);
        CREATE INDEX IF NOT EXISTS idx_steps_request ON steps(request_id);
        CREATE INDEX IF NOT EXISTS idx_steps_user_status ON steps(user_id, status);
        """
    )
    cols = {r[1] for r in db.execute("PRAGMA table_info(requests)").fetchall()}
    if "amount" not in cols:
        db.execute("ALTER TABLE requests ADD COLUMN amount TEXT")
    if "eat_time" not in cols:
        db.execute("ALTER TABLE requests ADD COLUMN eat_time TEXT")
    db.commit()


def next_doc_no(db):
    year = now_dt().year
    prefix = f"事审[{year}]"
    row = db.execute(
        "SELECT doc_no FROM requests WHERE doc_no LIKE ? ORDER BY id DESC LIMIT 1",
        (prefix + "%",),
    ).fetchone()
    n = 1
    if row:
        m = re.search(r"(\d+)号$", row["doc_no"])
        if m:
            n = int(m.group(1)) + 1
    return f"{prefix}{n:03d}号"


def csrf_token():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_hex(32)
        session["_csrf"] = token
    return token


def validate_csrf():
    sent = request.form.get("csrf_token", "")
    stored = session.get("_csrf", "")
    if not sent or not stored or not hmac.compare_digest(sent, stored):
        abort(400)


@app.context_processor
def inject_globals():
    return {
        "csrf_token": csrf_token,
        "current_user": g.get("user"),
        "TYPE_LABELS": TYPE_LABELS,
        "ITEM_LABELS": ITEM_LABELS,
        "STATUS_LABELS": STATUS_LABELS,
        "fmt_time": fmt_time,
        "fmt_amount": fmt_amount,
        "TYPE_EAT": TYPE_EAT,
        "TYPE_SPEND": TYPE_SPEND,
    }


@app.before_request
def load_user():
    init_db()
    g.user = None
    uid = session.get("user_id")
    if uid:
        g.user = get_db().execute(
            "SELECT id, username, created_at FROM users WHERE id = ?", (uid,)
        ).fetchone()
        if g.user is None:
            session.clear()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if g.user is None:
            flash("请先登录后再办理业务。", "error")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper


def get_user_by_name(db, name):
    return db.execute(
        "SELECT id, username FROM users WHERE username = ? COLLATE NOCASE",
        (name,),
    ).fetchone()


def parse_approvers(raw):
    parts = re.split(r"[,，;；\n]+", raw or "")
    names = []
    seen = set()
    for p in parts:
        n = p.strip()
        if not n:
            continue
        key = n.lower()
        if key in seen:
            continue
        seen.add(key)
        names.append(n)
    return names


def load_request(db, rid):
    row = db.execute(
        """
        SELECT r.*, u.username AS applicant_name
        FROM requests r JOIN users u ON u.id = r.applicant_id
        WHERE r.id = ?
        """,
        (rid,),
    ).fetchone()
    return row


def load_steps(db, rid):
    return db.execute(
        """
        SELECT s.*, u.username
        FROM steps s JOIN users u ON u.id = s.user_id
        WHERE s.request_id = ?
        ORDER BY s.seq ASC
        """,
        (rid,),
    ).fetchall()


def can_view(req, steps, user):
    if user["id"] == req["applicant_id"]:
        return True
    return any(s["user_id"] == user["id"] for s in steps)


@app.route("/")
def index():
    if g.user:
        return redirect(url_for("workbench"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("workbench"))
    if request.method == "POST":
        validate_csrf()
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""
        if not username or not re.fullmatch(r"[\w\u4e00-\u9fff.-]{1,32}", username):
            flash("用户名须为 1–32 位汉字、字母、数字、下划线或点号。", "error")
            return render_template("register.html")
        if len(password) < 4:
            flash("密码长度不得少于 4 个字符。", "error")
            return render_template("register.html")
        if password != password2:
            flash("两次输入的密码不一致。", "error")
            return render_template("register.html")
        db = get_db()
        if get_user_by_name(db, username):
            flash("该用户名已被注册，请更换。", "error")
            return render_template("register.html")
        db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), now_iso()),
        )
        db.commit()
        flash("注册成功，请登录办理业务。", "ok")
        return redirect(url_for("index"))
    return render_template("register.html")


@app.route("/login", methods=["POST"])
def login():
    validate_csrf()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    db = get_db()
    user = db.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ? COLLATE NOCASE",
        (username,),
    ).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        flash("用户名或密码错误。", "error")
        return redirect(url_for("index"))
    session.clear()
    session["user_id"] = user["id"]
    session.permanent = True
    flash(f"欢迎回来，{user['username']} 同志。", "ok")
    return redirect(url_for("workbench"))


@app.route("/logout", methods=["POST"])
def logout():
    validate_csrf()
    session.clear()
    flash("已安全退出。", "ok")
    return redirect(url_for("index"))


@app.route("/workbench")
@login_required
def workbench():
    tab = request.args.get("tab") or "mine"
    if tab not in ("mine", "pending", "archive"):
        tab = "mine"
    db = get_db()
    uid = g.user["id"]
    mine = db.execute(
        """
        SELECT r.*, u.username AS applicant_name
        FROM requests r JOIN users u ON u.id = r.applicant_id
        WHERE r.applicant_id = ?
        ORDER BY r.id DESC
        """,
        (uid,),
    ).fetchall()
    pending = db.execute(
        """
        SELECT r.*, u.username AS applicant_name, s.id AS step_id
        FROM steps s
        JOIN requests r ON r.id = s.request_id
        JOIN users u ON u.id = r.applicant_id
        WHERE s.user_id = ? AND s.status = ? AND r.status = ?
        ORDER BY r.id ASC
        """,
        (uid, STEP_CURRENT, ST_PENDING),
    ).fetchall()
    archive = db.execute(
        """
        SELECT DISTINCT r.*, u.username AS applicant_name
        FROM requests r
        JOIN users u ON u.id = r.applicant_id
        LEFT JOIN steps s ON s.request_id = r.id
        WHERE r.status IN (?, ?)
          AND (r.applicant_id = ? OR s.user_id = ?)
        ORDER BY COALESCE(r.finished_at, r.created_at) DESC, r.id DESC
        """,
        (ST_APPROVED, ST_REJECTED, uid, uid),
    ).fetchall()
    counts = {"mine": len(mine), "pending": len(pending), "archive": len(archive)}
    rows = {"mine": mine, "pending": pending, "archive": archive}[tab]
    return render_template(
        "workbench.html", tab=tab, rows=rows, counts=counts
    )


@app.route("/requests/new", methods=["GET", "POST"])
@login_required
def new_request():
    db = get_db()
    others = db.execute(
        "SELECT username FROM users WHERE id != ? ORDER BY username COLLATE NOCASE",
        (g.user["id"],),
    ).fetchall()
    if request.method == "POST":
        validate_csrf()
        rtype = request.form.get("type") or ""
        reason = (request.form.get("reason") or "").strip()
        names = parse_approvers(request.form.get("approvers") or "")
        extra = request.form.getlist("approver")
        for e in extra:
            names.extend(parse_approvers(e))
        names = parse_approvers(",".join(names))
        amount = None
        eat_time = None
        if rtype not in (TYPE_EAT, TYPE_SPEND):
            flash("请选择申请类型。", "error")
            return render_template("new_request.html", others=others)
        if rtype == TYPE_EAT:
            item = (request.form.get("item_eat") or request.form.get("item") or "").strip()
            eat_time = parse_eat_time(request.form.get("eat_time"))
            if eat_time is None:
                flash("请填写进食时间。", "error")
                return render_template("new_request.html", others=others)
            if eat_time is False:
                flash("进食时间格式无效。", "error")
                return render_template("new_request.html", others=others)
        else:
            item = (request.form.get("item_spend") or request.form.get("item") or "").strip()
            amount = parse_amount(request.form.get("amount"))
            if amount is None:
                flash("请填写金额。", "error")
                return render_template("new_request.html", others=others)
            if amount is False:
                flash("金额须为正数，最多两位小数。", "error")
                return render_template("new_request.html", others=others)
        if not item:
            flash("请填写申请事项。", "error")
            return render_template("new_request.html", others=others)
        if not reason:
            flash("请填写申请理由。", "error")
            return render_template("new_request.html", others=others)
        if len(item) > 200 or len(reason) > 2000:
            flash("填写内容过长，请精简后重试。", "error")
            return render_template("new_request.html", others=others)
        if not names:
            flash("请至少指定一名审批人。", "error")
            return render_template("new_request.html", others=others)
        approver_ids = []
        for name in names:
            if name.lower() == g.user["username"].lower():
                flash("申请人不得将本人列为审批人。", "error")
                return render_template("new_request.html", others=others)
            u = get_user_by_name(db, name)
            if not u:
                flash(f"审批人「{name}」不存在，请核对用户名。", "error")
                return render_template("new_request.html", others=others)
            approver_ids.append((u["id"], u["username"]))
        doc_no = next_doc_no(db)
        cur = db.execute(
            """
            INSERT INTO requests (doc_no, type, item, reason, applicant_id, status, created_at, amount, eat_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (doc_no, rtype, item, reason, g.user["id"], ST_PENDING, now_iso(), amount, eat_time),
        )
        rid = cur.lastrowid
        for i, (uid, _uname) in enumerate(approver_ids, start=1):
            st = STEP_CURRENT if i == 1 else STEP_WAITING
            db.execute(
                "INSERT INTO steps (request_id, user_id, seq, status) VALUES (?, ?, ?, ?)",
                (rid, uid, i, st),
            )
        db.commit()
        flash(f"申请已呈报，文号 {doc_no}。", "ok")
        return redirect(url_for("detail", rid=rid))
    return render_template("new_request.html", others=others)


@app.route("/requests/<int:rid>")
@login_required
def detail(rid):
    db = get_db()
    req = load_request(db, rid)
    if not req:
        abort(404)
    steps = load_steps(db, rid)
    if not can_view(req, steps, g.user):
        flash("您无权查阅该审批单。", "error")
        return redirect(url_for("workbench"))
    my_current = next(
        (
            s
            for s in steps
            if s["user_id"] == g.user["id"]
            and s["status"] == STEP_CURRENT
            and req["status"] == ST_PENDING
        ),
        None,
    )
    return render_template(
        "detail.html", req=req, steps=steps, my_current=my_current
    )


@app.route("/requests/<int:rid>/decide", methods=["POST"])
@login_required
def decide(rid):
    validate_csrf()
    action = request.form.get("action")
    comment = (request.form.get("comment") or "").strip()
    if action not in ("approve", "reject"):
        flash("无效的审批操作。", "error")
        return redirect(url_for("detail", rid=rid))
    if len(comment) > 500:
        flash("审批意见过长。", "error")
        return redirect(url_for("detail", rid=rid))
    db = get_db()
    req = load_request(db, rid)
    if not req:
        abort(404)
    if req["applicant_id"] == g.user["id"]:
        flash("申请人不得审批本人提交的事项。", "error")
        return redirect(url_for("detail", rid=rid))
    if req["status"] != ST_PENDING:
        flash("该申请已办结，不可再审。", "error")
        return redirect(url_for("detail", rid=rid))
    step = db.execute(
        """
        SELECT * FROM steps
        WHERE request_id = ? AND user_id = ? AND status = ?
        """,
        (rid, g.user["id"], STEP_CURRENT),
    ).fetchone()
    if not step:
        flash("该申请不在待您审批状态。", "error")
        return redirect(url_for("detail", rid=rid))
    ts = now_iso()
    if action == "reject":
        db.execute(
            "UPDATE steps SET status = ?, comment = ?, acted_at = ? WHERE id = ?",
            (STEP_REJECTED, comment or None, ts, step["id"]),
        )
        db.execute(
            "UPDATE requests SET status = ?, finished_at = ? WHERE id = ?",
            (ST_REJECTED, ts, rid),
        )
        db.commit()
        flash("已驳回，本件归档。", "ok")
        return redirect(url_for("detail", rid=rid))
    db.execute(
        "UPDATE steps SET status = ?, comment = ?, acted_at = ? WHERE id = ?",
        (STEP_APPROVED, comment or None, ts, step["id"]),
    )
    nxt = db.execute(
        """
        SELECT * FROM steps
        WHERE request_id = ? AND seq > ? AND status = ?
        ORDER BY seq ASC LIMIT 1
        """,
        (rid, step["seq"], STEP_WAITING),
    ).fetchone()
    if nxt:
        db.execute("UPDATE steps SET status = ? WHERE id = ?", (STEP_CURRENT, nxt["id"]))
        db.commit()
        flash("已同意，呈下一审批人。", "ok")
    else:
        db.execute(
            "UPDATE requests SET status = ?, finished_at = ? WHERE id = ?",
            (ST_APPROVED, ts, rid),
        )
        db.commit()
        flash("各级均已同意，本件通过并归档。", "ok")
    return redirect(url_for("detail", rid=rid))


@app.errorhandler(400)
def err400(_e):
    flash("请求校验失败，请刷新页面后重试。", "error")
    if g.get("user"):
        return redirect(url_for("workbench"))
    return redirect(url_for("index"))


@app.errorhandler(404)
def err404(_e):
    return render_template("error.html", code=404, msg="未找到相应公文或页面。"), 404


@app.errorhandler(500)
def err500(_e):
    return render_template("error.html", code=500, msg="系统繁忙，请稍后再试。"), 500


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host="127.0.0.1", port=8000)
