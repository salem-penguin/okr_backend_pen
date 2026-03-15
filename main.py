from fastapi import FastAPI, Header, HTTPException, Query, BackgroundTasks
from contextlib import asynccontextmanager
from datetime import date
from db import init_db_pool, close_db_pool, fetchrow, record_to_dict,fetch ,fetchval,execute
from pydantic import BaseModel, Field
import json
from datetime import datetime, timezone
from typing import Optional
from fastapi.middleware.cors import CORSMiddleware
from typing import Any, List, Optional, Literal

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from passlib.context import CryptContext
import os
import secrets, hashlib, string
import html
from datetime import datetime, timezone, timedelta
import hashlib
from datetime import datetime, timezone
from fastapi.responses import RedirectResponse

from fastapi.responses import Response
from dotenv import load_dotenv
load_dotenv()  # add near the top of the file (right after imports)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Put this in env in production
SESSION_SECRET = os.getenv("SESSION_SECRET", "dev-change-me")
SESSION_COOKIE = "session"
from fastapi import Depends, Cookie

from fastapi import Depends, Cookie, HTTPException, Response
from itsdangerous import BadSignature, SignatureExpired

SESSION_COOKIE = "session"

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://127.0.0.1:9000")
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
EMAIL_VERIFY_TTL_MIN = int(os.getenv("EMAIL_VERIFY_TTL_MIN", "60"))
print("BREVO_API_KEY present?", bool(os.getenv("BREVO_API_KEY")))
print("BREVO_SENDER_EMAIL=", os.getenv("BREVO_SENDER_EMAIL"))

def make_verify_token() -> tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return raw, token_hash

def send_brevo_email(
    to_email: str,
    subject: str,
    html_content: str,
    sender_email: str | None = None,
    sender_name: str | None = None,
):
    """
    Thin wrapper around Brevo transactional emails.
    Defaults sender to the admin account unless explicitly overridden.
    """
    import sib_api_v3_sdk
    from sib_api_v3_sdk.rest import ApiException

    api_key = os.getenv("BREVO_API_KEY")
    sender_email = sender_email or os.getenv("BREVO_SENDER_EMAIL") or "s.alnsour@penguinin.com"
    sender_name = sender_name or os.getenv("BREVO_SENDER_NAME", "Penguinin Admin")

    if not api_key:
        raise RuntimeError("BREVO_API_KEY is missing in env")

    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key["api-key"] = api_key

    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
        sib_api_v3_sdk.ApiClient(configuration)
    )

    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": to_email}],
        sender={"email": sender_email, "name": sender_name},
        subject=subject,
        html_content=html_content,
    )

    try:
        resp = api_instance.send_transac_email(send_smtp_email)
        print("[BREVO OK] response=", resp)
    except ApiException as e:
        print("[BREVO ERROR] status=", getattr(e, "status", None), "body=", getattr(e, "body", None))
        raise


def send_verification_email(to_email: str, link: str):
    subject = "Verify your email"
    html_content = f"""
    <p>Verify your email:</p>
    <p><a href="{link}">{link}</a></p>
    """
    send_brevo_email(to_email=to_email, subject=subject, html_content=html_content)



INVITE_CODE_ALPHABET = string.ascii_uppercase + string.digits

async def generate_unique_invite_code(conn, length: int = 8, max_attempts: int = 5) -> str:
    for _ in range(max_attempts):
        code = "".join(secrets.choice(INVITE_CODE_ALPHABET) for _ in range(length))
        exists = await conn.fetchval("SELECT 1 FROM teams WHERE invite_code=$1", code)
        if not exists:
            return code
    raise HTTPException(status_code=500, detail="Failed to generate a unique invite code; please retry.")

def serialize_team_creation_request(row):
    if not row:
        return None
    data = record_to_dict(row)
    return {
        "id": str(data["id"]),
        "team_name": data["team_name"],
        "status": data["status"],
        "requested_at": data["requested_at"].isoformat() if data.get("requested_at") else None,
        "reviewed_at": data["reviewed_at"].isoformat() if data.get("reviewed_at") else None,
        "reviewed_by": str(data["reviewed_by"]) if data.get("reviewed_by") else None,
        "approved_team_id": str(data["approved_team_id"]) if data.get("approved_team_id") else None,
        "requester_user_id": str(data["requester_user_id"]),
        "admin_note": data.get("admin_note"),
    }

def get_admin_request_email() -> str | None:
    return os.getenv("TEAM_REQUEST_ADMIN_EMAIL") or os.getenv("BREVO_ADMIN_EMAIL")


async def get_current_user(session: str | None = Cookie(default=None, alias=SESSION_COOKIE)):
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        data = read_session_token(session)
        user_id = data["user_id"]
    except SignatureExpired:
        raise HTTPException(status_code=401, detail="Session expired")
    except BadSignature:
        raise HTTPException(status_code=401, detail="Invalid session")

    row = await fetchrow(
        """
        SELECT
          u.id, u.name, u.email, u.role, u.team_id,
          u.email_verified, u.status, u.role_locked,
          t.name AS team_name,
          t.leader_id
        FROM users u
        LEFT JOIN teams t ON t.id = u.team_id
        WHERE u.id=$1::uuid
        """,
        user_id,
    )
    if not row:
        raise HTTPException(status_code=401, detail="User not found")

    me = record_to_dict(row)

    # Optional hard gate (recommended): block disabled users immediately
    if me.get("status") == "disabled":
        raise HTTPException(status_code=403, detail="Account is disabled")

    return me



serializer = URLSafeTimedSerializer(SESSION_SECRET, salt="weekly-reports-session")

from uuid import UUID

def extract_kr_updates(payload: dict) -> list[dict]:
    items = payload.get("kr_updates") or []
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        return []

    out = []
    for it in items:
        if not isinstance(it, dict):
            continue

        kr_id = (it.get("kr_id") or "").strip()
        note = (it.get("note") or "").strip()
        if not kr_id or not note:
            continue

        # validate UUID early (avoid silent drops)
        try:
            kr_uuid = str(UUID(kr_id))
        except Exception:
            continue

        meta = dict(it)
        meta.pop("kr_id", None)
        meta.pop("note", None)

        out.append({"kr_id": kr_uuid, "note": note, "meta": meta})
    return out



def create_session_token(user_id: str) -> str:
    return serializer.dumps({"user_id": user_id})

def read_session_token(token: str, max_age_seconds: int = 60 * 60 * 24 * 7):
    # 7 days default
    return serializer.loads(token, max_age=max_age_seconds)

# def verify_password(plain: str, hashed: str) -> bool:
#     return pwd_context.verify(plain, hashed)
def verify_password(plain: str, hashed: str) -> bool:
    # bcrypt supports max 72 bytes
    if len(plain.encode("utf-8")) > 72:
        return False
    return pwd_context.verify(plain, hashed)

class LoginRequest(BaseModel):
    email: str
    password: str

class SaveFormSchemaRequest(BaseModel):
    scope: Literal["member", "leader"]
    fields: list  # keep flexible; can be List[dict[str, Any]] if you want stricter

    # ownership (depending on scope)
    team_id: Optional[str] = None
    leader_id: Optional[str] = None

class FormSchemaResponse(BaseModel):
    id: str
    scope: str
    team_id: Optional[str]
    leader_id: Optional[str]
    version: int
    is_active: bool
    fields: Any
    created_at: str
    updated_at: str

class SaveDraftRequest(BaseModel):
    week_id: str
    report_type: str = Field(pattern="^(member|leader)$")
    form_id: str
    payload: dict

class SubmitRequest(BaseModel):
    week_id: str
    report_type: str = Field(pattern="^(member|leader)$")

class SendLeaderReminderRequest(BaseModel):
    leader_id: str
    subject: str = Field(default="Reminder: Weekly report pending", max_length=120)
    message: str = Field(..., max_length=2000)

def ensure_json(value):
    return json.loads(value) if isinstance(value, str) else value


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db_pool()
    yield
    await close_db_pool()

app = FastAPI(title="Weekly Wins Hub API", version="0.2.0", lifespan=lifespan)

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=[
#         "http://localhost:9000",
#         "http://127.0.0.1:9000",
#         "http://localhost:5173",
#         "http://127.0.0.1:5173",
#         "http://192.168.2.183:9000",
#          "http://192.168.5.198:9000",
#     # optionally dev origins:
#     "http://localhost:9000",
#     "http://127.0.0.1:9000",
#    ],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:9000",
        "http://localhost:9000",
        "http://192.168.5.198:9000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



@app.get("/health")
async def health():
    return {"ok": True}

@app.get("/db/ping")
async def db_ping():
    pool = await init_db_pool()
    async with pool.acquire() as conn:
        val = await conn.fetchval("SELECT 1;")
    return {"db_ok": val == 1}



from fastapi import Depends

@app.get("/me")
async def me(me=Depends(get_current_user)):
    return {
        "id": str(me["id"]),
        "name": me["name"],
        "email": me["email"],
        "role": me.get("role"),
        "email_verified": me.get("email_verified"),
        "status": me.get("status"),
        "role_locked": me.get("role_locked"),
        "team": (
            {
                "id": str(me["team_id"]),
                "name": me.get("team_name"),
                "leader_id": str(me["leader_id"]) if me.get("leader_id") else None,
            }
            if me.get("team_id")
            else None
        ),
    }


from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo
from fastapi import Query, HTTPException

AMMAN_TZ = ZoneInfo("Asia/Amman")

def week_bounds_sun_to_sat(d: date) -> tuple[date, date]:
    # Sunday-start: Sunday..Saturday
    # weekday(): Mon=0 ... Sun=6
    days_since_sunday = (d.weekday() + 1) % 7
    start = d - timedelta(days=days_since_sunday)
    end = start + timedelta(days=6)
    return start, end

def week_id_sunday_based(d: date) -> str:
    # %U = week number (Sunday as first day), 00-53
    ww = int(d.strftime("%U")) + 1  # 01-54
    return f"{d.year}-{ww:02d}"

def week_label(week_id: str, start: date, end: date) -> str:
    year, ww = week_id.split("-")
    return f"Week {ww}, {year} ({start:%b %d} – {end:%b %d})"

@app.get("/weeks/current")
async def current_week(today: date | None = Query(default=None)):
    # Default to Asia/Amman “today”
    d = today or datetime.now(AMMAN_TZ).date()

    # 1) Try fetch
    row = await fetchrow(
        """
        SELECT week_id, start_date, end_date, display_label
        FROM weeks
        WHERE start_date <= $1 AND end_date >= $1
        ORDER BY start_date DESC
        LIMIT 1
        """,
        d,
    )

    # 2) If missing, create the computed week (idempotent)
    if not row:
        start, end = week_bounds_sun_to_sat(d)
        wid = week_id_sunday_based(d)
        label = week_label(wid, start, end)

        await execute(
            """
            INSERT INTO weeks (week_id, start_date, end_date, display_label)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (week_id) DO UPDATE
            SET start_date = EXCLUDED.start_date,
                end_date = EXCLUDED.end_date,
                display_label = EXCLUDED.display_label
            """,
            wid, start, end, label
        )

        row = await fetchrow(
            """
            SELECT week_id, start_date, end_date, display_label
            FROM weeks
            WHERE week_id = $1
            """,
            wid,
        )

        if not row:
            raise HTTPException(status_code=500, detail="Failed to create current week")

    w = record_to_dict(row)
    return {
        "week_id": w["week_id"],
        "start_date": w["start_date"].isoformat(),
        "end_date": w["end_date"].isoformat(),
        "display_label": w["display_label"],
    }

@app.post("/ceo/reminders/team-leader")
async def send_team_leader_reminder(body: SendLeaderReminderRequest, me=Depends(get_current_user)):
    if me["role"] != "ceo":
        raise HTTPException(status_code=403, detail="Only CEO can send reminders")

    leader = await fetchrow(
        """
        SELECT id, name, email, status
        FROM users
        WHERE id = $1::uuid AND role = 'team_leader'
        """,
        body.leader_id,
    )
    if not leader:
        raise HTTPException(status_code=404, detail="Team leader not found")
    if leader["status"] != "active":
        raise HTTPException(status_code=400, detail="Leader is not active")

    leader_name = leader["name"] or "there"
    safe_message = html.escape(body.message).replace("\n", "<br>")
    html_body = f"""
    <p>Hi {leader_name},</p>
    <p>{safe_message}</p>
    <p>- {me.get("name") or "CEO"}</p>
    """

    try:
        send_brevo_email(
            to_email=leader["email"],
            subject=body.subject,
            html_content=html_body,
            sender_email=os.getenv("BREVO_ADMIN_EMAIL") or "s.alnsour@penguinin.com",
            sender_name=os.getenv("BREVO_SENDER_NAME", "Penguinin Admin"),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send reminder email: {e}")

    return {"success": True, "leader_id": str(leader["id"])}

# -------------------------
# Forms: active schema
# -------------------------
@app.get("/forms/active")
async def active_form(
    scope: str = Query(..., pattern="^(member|leader)$"),
    team_id: str | None = Query(default=None),
    leader_id: str | None = Query(default=None),
):
    # Rules:
    # - member form: provide team_id
    # - leader form: provide leader_id
    if scope == "member" and not team_id:
        raise HTTPException(status_code=400, detail="team_id is required for member scope")
    if scope == "leader" and not leader_id:
        raise HTTPException(status_code=400, detail="leader_id is required for leader scope")

    row = await fetchrow(
        """
        SELECT id, scope, team_id, leader_id, version, is_active, fields, created_at, updated_at
        FROM form_schemas
        WHERE is_active = true
          AND scope = $1::form_scope
          AND ( ($1='member' AND team_id = $2::uuid) OR ($1='leader' AND leader_id = $3::uuid) )
        ORDER BY version DESC, updated_at DESC
        LIMIT 1
        """,
        scope,
        team_id,
        leader_id,
    )

    if not row:
        raise HTTPException(status_code=404, detail="Active form not found")

    f = record_to_dict(row)
    return {
        "id": str(f["id"]),
        "scope": f["scope"],
        "team_id": str(f["team_id"]) if f["team_id"] else None,
        "leader_id": str(f["leader_id"]) if f["leader_id"] else None,
        "version": f["version"],
        "is_active": f["is_active"],
        "fields": (json.loads(f["fields"]) if isinstance(f["fields"], str) else f["fields"]),
        "created_at": f["created_at"].isoformat(),
        "updated_at": f["updated_at"].isoformat(),
    }



@app.post("/reports/draft")
async def save_draft(body: SaveDraftRequest, me=Depends(get_current_user)):
    if not me["team_id"]:
        raise HTTPException(status_code=400, detail="User has no team")

    role = me["role"]

    if role == "team_member" and body.report_type != "member":
        raise HTTPException(status_code=403, detail="Members can only save member reports")
    if role == "ceo":
        raise HTTPException(status_code=403, detail="CEO cannot submit reports")

    # fetch the active form schema and snapshot it
    if body.report_type == "member":
        form = await fetchrow(
            """
            SELECT id, fields, version
            FROM form_schemas
            WHERE id=$1::uuid AND scope='member'::form_scope AND is_active=true AND team_id=$2::uuid
            """,
            body.form_id,
            me["team_id"],
        )
    else:
        # leader report -> schema owned by this leader
        form = await fetchrow(
            """
            SELECT id, fields, version
            FROM form_schemas
            WHERE id=$1::uuid AND scope='leader'::form_scope AND is_active=true AND leader_id=$2::uuid
            """,
            body.form_id,
            me["id"],
        )

    if not form:
        raise HTTPException(status_code=400, detail="Form not found or not active for this user")

    form_snapshot = {
        "id": str(form["id"]),
        "version": form["version"],
        "fields": ensure_json(form["fields"]),
    }

    pool = await init_db_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO weekly_reports
              (week_id, user_id, team_id, report_type, status, form_id, form_snapshot, payload)
            VALUES
              ($1, $2, $3, $4::report_type, 'draft'::report_status, $5, $6::jsonb, $7::jsonb)
            ON CONFLICT (week_id, user_id, report_type)
            DO UPDATE SET
              form_id = EXCLUDED.form_id,
              form_snapshot = EXCLUDED.form_snapshot,
              payload = EXCLUDED.payload,
              updated_at = now()
            RETURNING id, week_id, user_id, team_id, report_type, status, created_at, updated_at, submitted_at, form_id, form_snapshot, payload
            """,
            body.week_id,
            me["id"],
            me["team_id"],
            body.report_type,
            body.form_id,
            json.dumps(form_snapshot),
            json.dumps(body.payload),
        )

    r = record_to_dict(row)
    return {
        "id": str(r["id"]),
        "week_id": r["week_id"],
        "user_id": str(r["user_id"]),
        "team_id": str(r["team_id"]),
        "report_type": r["report_type"],
        "status": r["status"],
        "form_id": str(r["form_id"]),
        "form_snapshot": ensure_json(r["form_snapshot"]),
        "payload": ensure_json(r["payload"]),
        "created_at": r["created_at"].isoformat(),
        "updated_at": r["updated_at"].isoformat(),
        "submitted_at": r["submitted_at"].isoformat() if r["submitted_at"] else None,
    }




from fastapi import Depends, HTTPException
@app.post("/reports/submit")
async def submit_report(body: SubmitRequest, me=Depends(get_current_user)):
    if me["role"] == "ceo":
        raise HTTPException(status_code=403, detail="CEO cannot submit reports")

    pool = await init_db_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE weekly_reports
            SET status='submitted'::report_status,
                submitted_at=now(),
                updated_at=now()
            WHERE week_id=$1
              AND user_id=$2
              AND report_type=$3::report_type
              AND status='draft'::report_status
            RETURNING id, week_id, user_id, team_id, report_type, status, submitted_at, payload
            """,
            body.week_id,
            me["id"],
            body.report_type,
        )

        if not row:
            raise HTTPException(status_code=404, detail="Draft report not found (or already submitted)")

        report_id = str(row["id"])
        team_id = row["team_id"]
        payload = row["payload"] if not isinstance(row["payload"], str) else json.loads(row["payload"])

        # No team => cannot attach KR updates
        if not team_id:
            # you can choose to allow leader report without team, but for OKRs you need team
            raise HTTPException(status_code=400, detail="User has no team; cannot save KR updates")

        updates = extract_kr_updates(payload)

        # keep submit working even if no updates
        await conn.execute(
            "DELETE FROM company_key_result_updates WHERE report_id=$1::uuid",
            report_id,
        )

        if updates:
            inserted = await conn.fetch(
                """
                WITH items AS (
                  SELECT *
                  FROM jsonb_to_recordset($1::jsonb)
                  AS x(kr_id uuid, note text, meta jsonb)
                ),
                allowed AS (
                  SELECT x.*
                  FROM items x
                  JOIN company_key_results kr ON kr.id = x.kr_id
                  JOIN company_objectives o ON o.id = kr.objective_id
                  WHERE o.team_id = $2::uuid
                )
                INSERT INTO company_key_result_updates
                  (kr_id, week_id, report_id, author_user_id, team_id, note, meta)
                SELECT
                  a.kr_id, $3, $4::uuid, $5::uuid, $2::uuid, a.note, COALESCE(a.meta,'{}'::jsonb)
                FROM allowed a
                RETURNING id
                """,
                json.dumps(updates),
                str(team_id),
                body.week_id,
                report_id,
                str(me["id"]),
            )

            if len(inserted) != len(updates):
                raise HTTPException(
                    status_code=400,
                    detail="One or more selected key results are invalid for your team",
                )

    return {
        "id": report_id,
        "week_id": row["week_id"],
        "user_id": str(row["user_id"]),
        "report_type": row["report_type"],
        "status": row["status"],
        "submitted_at": row["submitted_at"].isoformat() if row["submitted_at"] else None,
    }





from fastapi import Depends, HTTPException, Query
from typing import Optional

@app.get("/reports")
async def list_reports(
    week_id: str = Query(...),
    report_type: Optional[str] = Query(default=None, pattern="^(member|leader)$"),
    team_id: Optional[str] = Query(default=None),
    me=Depends(get_current_user),
):
    role = me["role"]
    user_id = me["id"]
    user_team_id = me.get("team_id")

    base_sql = """
      SELECT
        r.id, r.week_id, r.user_id, r.team_id, r.report_type, r.status,
        r.form_id, r.form_snapshot, r.payload,
        r.created_at, r.updated_at, r.submitted_at,
        u.name AS user_name, u.email AS user_email, u.role AS user_role,
        t.name AS team_name
      FROM weekly_reports r
      JOIN users u ON u.id = r.user_id
      JOIN teams t ON t.id = r.team_id
      WHERE r.week_id = $1
    """

    args = [week_id]
    where = []

    if report_type:
        where.append(f"r.report_type = ${len(args)+1}::report_type")
        args.append(report_type)

    if role == "ceo":
        # CEO can filter by team_id optionally, otherwise sees all
        if team_id:
            where.append(f"r.team_id = ${len(args)+1}::uuid")
            args.append(team_id)

    elif role == "team_leader":
        leader_filters = []

        if report_type in (None, "leader"):
            leader_filters.append(
                f"(r.report_type='leader'::report_type AND r.user_id = ${len(args)+1}::uuid)"
            )
            args.append(str(user_id))

        if report_type in (None, "member"):
            if user_team_id:
                if team_id and team_id.lower() != str(user_team_id).lower():
                    raise HTTPException(status_code=403, detail="Leaders can only access their own team")

                leader_filters.append(
                    f"(r.report_type='member'::report_type AND r.team_id = ${len(args)+1}::uuid)"
                )
                args.append(str(user_team_id))

        if not leader_filters:
            return {"items": [], "count": 0}

        where.append("(" + " OR ".join(leader_filters) + ")")

    elif role == "team_member":
        where.append(f"r.user_id = ${len(args)+1}::uuid")
        args.append(str(user_id))

    else:
        raise HTTPException(status_code=403, detail="Unsupported role")

    sql = base_sql
    if where:
        sql += " AND " + " AND ".join(where)
    sql += " ORDER BY r.submitted_at DESC NULLS LAST, r.updated_at DESC;"

    pool = await init_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, *args)

    results = []
    for row in rows:
        r = dict(row)
        results.append({
            "id": str(r["id"]),
            "week_id": r["week_id"],
            "team": {"id": str(r["team_id"]), "name": r["team_name"]},
            "submitter": {
                "id": str(r["user_id"]),
                "name": r["user_name"],
                "email": r["user_email"],
                "role": r["user_role"],
            },
            "report_type": r["report_type"],
            "status": r["status"],
            "form_id": str(r["form_id"]),
            "form_snapshot": ensure_json(r["form_snapshot"]),
            "payload": ensure_json(r["payload"]),
            "created_at": r["created_at"].isoformat(),
            "updated_at": r["updated_at"].isoformat(),
            "submitted_at": r["submitted_at"].isoformat() if r["submitted_at"] else None,
        })

    return {"items": results, "count": len(results)}


from fastapi import Depends, Query

@app.get("/reports/me")
async def my_report_for_week(
    week_id: str = Query(...),
    report_type: str = Query(..., pattern="^(member|leader)$"),
    me=Depends(get_current_user),
):
    row = await fetchrow(
        """
        SELECT id, week_id, user_id, team_id, report_type, status,
               form_id, form_snapshot, payload, created_at, updated_at, submitted_at
        FROM weekly_reports
        WHERE week_id=$1 AND user_id=$2 AND report_type=$3::report_type
        """,
        week_id,
        me["id"],
        report_type,
    )

    if not row:
        return {"item": None}

    r = record_to_dict(row)
    return {
        "item": {
            "id": str(r["id"]),
            "week_id": r["week_id"],
            "user_id": str(r["user_id"]),
            "team_id": str(r["team_id"]),
            "report_type": r["report_type"],
            "status": r["status"],
            "form_id": str(r["form_id"]),
            "form_snapshot": ensure_json(r["form_snapshot"]),
            "payload": ensure_json(r["payload"]),
            "created_at": r["created_at"].isoformat(),
            "updated_at": r["updated_at"].isoformat(),
            "submitted_at": r["submitted_at"].isoformat() if r["submitted_at"] else None,
        }
    }


from fastapi import Header, HTTPException
import json



from fastapi import Depends, HTTPException
from typing import Optional
import json

@app.post("/forms/schemas")
async def save_form_schema(body: SaveFormSchemaRequest, me=Depends(get_current_user)):
    role = me["role"]
    caller_id = str(me["id"])
    caller_team_id = str(me["team_id"]) if me.get("team_id") else None

    # Authorization: members cannot manage schemas
    if role == "team_member":
        raise HTTPException(status_code=403, detail="Members cannot manage form schemas")

    # Ownership resolution (same as your logic)
    if body.scope == "member":
        if not body.team_id:
            raise HTTPException(status_code=400, detail="team_id is required for member scope")
        owner_team_id = body.team_id
        owner_leader_id = None
    else:  # leader
        owner_leader_id = body.leader_id or caller_id
        owner_team_id = None

    # Team leader restrictions
    if role == "team_leader":
        if body.scope == "member":
            if not caller_team_id:
                raise HTTPException(status_code=400, detail="Leader has no team_id")
            if owner_team_id.lower() != caller_team_id.lower():
                raise HTTPException(status_code=403, detail="Leaders can only manage their own team form")

        if body.scope == "leader":
            if owner_leader_id.lower() != caller_id.lower():
                raise HTTPException(status_code=403, detail="Leaders can only manage their own leader form")

    # CEO: allowed (keep as-is). If you want to forbid, add a check here.

    pool = await init_db_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            active = await conn.fetchrow(
                """
                SELECT id, version
                FROM form_schemas
                WHERE is_active = true
                  AND scope = $1::form_scope
                  AND (
                    ($1='member' AND team_id = $2::uuid)
                    OR
                    ($1='leader' AND leader_id = $3::uuid)
                  )
                ORDER BY version DESC, updated_at DESC
                LIMIT 1
                FOR UPDATE
                """,
                body.scope,
                owner_team_id,
                owner_leader_id,
            )

            next_version = (active["version"] + 1) if active else 1

            if active:
                await conn.execute(
                    "UPDATE form_schemas SET is_active=false, updated_at=now() WHERE id=$1::uuid",
                    active["id"],
                )

            row = await conn.fetchrow(
                """
                INSERT INTO form_schemas (scope, team_id, leader_id, version, is_active, fields, created_at, updated_at)
                VALUES ($1::form_scope, $2::uuid, $3::uuid, $4, true, $5::jsonb, now(), now())
                RETURNING id, scope, team_id, leader_id, version, is_active, fields, created_at, updated_at
                """,
                body.scope,
                owner_team_id,
                owner_leader_id,
                next_version,
                json.dumps(body.fields),
            )

    f = record_to_dict(row)
    return {
        "id": str(f["id"]),
        "scope": f["scope"],
        "team_id": str(f["team_id"]) if f["team_id"] else None,
        "leader_id": str(f["leader_id"]) if f["leader_id"] else None,
        "version": f["version"],
        "is_active": f["is_active"],
        "fields": ensure_json(f["fields"]),
        "created_at": f["created_at"].isoformat(),
        "updated_at": f["updated_at"].isoformat(),
    }


from fastapi import Response, HTTPException
from fastapi.responses import JSONResponse

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0") == "1"      # set 1 behind HTTPS
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax")       # use "none" only with HTTPS + secure=True
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN")                  # usually None in dev


@app.post("/auth/login")
async def auth_login(body: LoginRequest, response: Response):
    row = await fetchrow(
    """
    SELECT
      u.id, u.name, u.email, u.role, u.team_id,
      u.email_verified, u.status,
      u.password_hash,
      t.name AS team_name,
      t.leader_id
    FROM users u
    LEFT JOIN teams t ON t.id = u.team_id
    WHERE LOWER(u.email)=LOWER($1)
    """,
    body.email,
)
    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    

    user = record_to_dict(row)
    if not user.get("email_verified"):
        raise HTTPException(status_code=403, detail="Please verify your email before logging in.")

    if user.get("status") != "active":
        raise HTTPException(status_code=403, detail="Account is not active.")


    if not user.get("password_hash"):
        raise HTTPException(status_code=401, detail="User has no password set")
    # bcrypt hard limit
    if len(body.password.encode("utf-8")) > 72:
        raise HTTPException(
            status_code=400,
        detail="Password too long (bcrypt max 72 bytes)"
    )

    # bcrypt only supports 72 bytes max
    if len(body.password.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Password too long (max 72 bytes).")


    if not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_session_token(str(user["id"]))

    response.set_cookie(
    key=SESSION_COOKIE,
    value=token,
    httponly=True,
    secure=False,      # force for dev
    samesite="lax",    # force for dev
    max_age=60 * 60 * 24 * 7,
    path="/",
    domain=COOKIE_DOMAIN,       # force for dev
)


    # response.set_cookie(
    #     key=SESSION_COOKIE,
    #     value=token,
    #     httponly=True,
    #     secure=COOKIE_SECURE,
    #     samesite=COOKIE_SAMESITE,
    #     max_age=60 * 60 * 24 * 7,
    #     path="/",
    #     domain=COOKIE_DOMAIN,  # None in dev
    # )

    return {
        "success": True,
        "user": {
            "id": str(user["id"]),
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "teamId": str(user["team_id"]) if user["team_id"] else None,
            "team": (
                {
                    "id": str(user["team_id"]),
                    "name": user["team_name"],
                    "leader_id": str(user["leader_id"]) if user["leader_id"] else None,
                }
                if user["team_id"]
                else None
            ),
        },
    }



@app.post("/auth/logout")
async def auth_logout(response: Response):
    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/",
        domain=COOKIE_DOMAIN,
    )
    return {"success": True}

@app.get("/users")
async def list_users(role: str | None = Query(default=None), me=Depends(get_current_user)):
    if me["role"] != "ceo":
        raise HTTPException(status_code=403, detail="Forbidden")

    sql = """
      SELECT
        u.id, u.name, u.email, u.role, u.team_id,
        t.name AS team_name,
        t.leader_id
      FROM users u
      LEFT JOIN teams t ON t.id = u.team_id
    """
    args = []
    where = []
    if role:
        where.append(f"u.role = ${len(args)+1}")
        args.append(role)

    if where:
        sql += " WHERE " + " AND ".join(where)

    pool = await init_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, *args)

    items = []
    for row in rows:
        r = dict(row)
        items.append({
            "id": str(r["id"]),
            "name": r["name"],
            "email": r["email"],
            "role": r["role"],
            "team": (
                {"id": str(r["team_id"]), "name": r["team_name"], "leader_id": str(r["leader_id"]) if r["leader_id"] else None}
                if r["team_id"] else None
            )
        })

    return {"items": items, "count": len(items)}

@app.get("/teams/{team_id}/members")
async def list_team_members(team_id: str, me=Depends(get_current_user)):
    if me["role"] not in ("team_leader", "ceo"):
        raise HTTPException(status_code=403, detail="Forbidden")

    # if leader, enforce same team
    if me["role"] == "team_leader" and str(me["team_id"]) != team_id:
        raise HTTPException(status_code=403, detail="Forbidden")

    sql = """
      SELECT id, name, email, role
      FROM users
      WHERE team_id = $1::uuid AND role = 'team_member'
      ORDER BY name
    """

    pool = await init_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, team_id)

    return {
        "items": [
            {"id": str(r["id"]), "name": r["name"], "email": r["email"], "role": r["role"]}
            for r in rows
        ],
        "count": len(rows),
    }

from fastapi import Depends, HTTPException, Query
from typing import Optional

@app.get("/reports/my")
async def my_reports(
    report_type: Optional[str] = Query(default=None, pattern="^(member|leader)$"),
    me=Depends(get_current_user),
):
    # Role gate: CEO doesn't have "my reports" (optional)
    if me["role"] == "ceo":
        raise HTTPException(status_code=403, detail="CEO has no personal reports")

    sql = """
      SELECT
        r.id, r.week_id, r.user_id, r.team_id, r.report_type, r.status,
        r.form_id, r.form_snapshot, r.payload,
        r.created_at, r.updated_at, r.submitted_at,
        t.name AS team_name
      FROM weekly_reports r
      JOIN teams t ON t.id = r.team_id
      WHERE r.user_id = $1::uuid
    """
    args = [str(me["id"])]

    if report_type:
        sql += f" AND r.report_type = ${len(args)+1}::report_type"
        args.append(report_type)

    sql += " ORDER BY r.week_id DESC, r.submitted_at DESC NULLS LAST, r.updated_at DESC;"

    pool = await init_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, *args)

    items = []
    for row in rows:
        r = dict(row)
        items.append({
            "id": str(r["id"]),
            "week_id": r["week_id"],
            "team": {"id": str(r["team_id"]), "name": r["team_name"]},
            "report_type": r["report_type"],
            "status": r["status"],
            "form_id": str(r["form_id"]),
            "form_snapshot": ensure_json(r["form_snapshot"]),
            "payload": ensure_json(r["payload"]),
            "created_at": r["created_at"].isoformat(),
            "updated_at": r["updated_at"].isoformat(),
            "submitted_at": r["submitted_at"].isoformat() if r["submitted_at"] else None,
        })

    return {"items": items, "count": len(items)}

from datetime import date, datetime, timezone, timedelta
from pydantic import BaseModel
from typing import Any, Literal, Optional, List
from pydantic import BaseModel, Field
from typing import Literal, Optional

class AddObjectiveRequest(BaseModel):
    title: str
    team_id: Optional[str] = None 
    parent_id: str                     # company_level_objectives.id
    parent_weight: int = Field(ge=1, le=100) # assign objective to a team

class UpdateKeyResultRequest(BaseModel):
    id: str
    status: Literal["not_started", "in_progress", "completed"]
    progress: int = Field(ge=0, le=100)


async def get_parent_children_total_weight(parent_id: str) -> int:
    row = await fetchrow(
        """
        SELECT COALESCE(SUM(parent_weight), 0) AS total
        FROM company_objectives
        WHERE parent_company_level_objective_id = $1::uuid
        """,
        parent_id
    )
    return int(row["total"] or 0)



class UpsertCompanyOKRRequest(BaseModel):
    title: str = "Company OKRs"
    status: Literal["draft", "published"] = "draft"
    okrs: Any = []      # keep flexible (json list)
    notes: Optional[str] = None
from datetime import date, datetime, timezone
from typing import Optional, List
from pydantic import BaseModel

def quarter_for_date(d: date):
    q = (d.month - 1) // 3 + 1
    year = d.year
    if q == 1:
        start = date(year, 1, 1)
        end = date(year, 3, 31)
    elif q == 2:
        start = date(year, 4, 1)
        end = date(year, 6, 30)
    elif q == 3:
        start = date(year, 7, 1)
        end = date(year, 9, 30)
    else:
        start = date(year, 10, 1)
        end = date(year, 12, 31)

    quarter_id = f"{year}-Q{q}"
    return quarter_id, start, end

def seconds_until_end_of_quarter(end_date: date) -> int:
    end_dt = datetime(end_date.year, end_date.month, end_date.day, 23, 59, 59, tzinfo=timezone.utc)
    now_dt = datetime.now(timezone.utc)
    delta = end_dt - now_dt
    return max(0, int(delta.total_seconds()))

class AddObjectiveRequest(BaseModel):
    title: str

class AddKeyResultRequest(BaseModel):
    objective_id: str
    title: str
    weight:int = Field(default=1, ge = 1 , le = 100)

def obj_timeline_status(timeline_end: date):
    today = datetime.now(AMMAN_TZ).date()
    days_remaining = (timeline_end - today).days
    is_expired = days_remaining < 0
    return {
        "is_expired": is_expired,
        "days_remaining": max(0, days_remaining),
    }

class SetObjectiveTimelineRequest(BaseModel):
    timeline_start: date
    timeline_end: date


async def get_parent_total_child_weight(parent_id: str) -> int:
    row = await fetchrow(
        """
        SELECT COALESCE(SUM(parent_weight), 0) AS total
        FROM company_objectives
        WHERE parent_company_level_objective_id = $1::uuid
        """,
        parent_id,
    )
    return int(row["total"] or 0)

async def get_objective_total_weight(objective_id: str) -> int:
    row = await fetchrow(
        """
        SELECT COALESCE(SUM(weight), 0) AS total
        FROM company_key_results
        WHERE objective_id = $1::uuid
        """,
        objective_id,
    )
    return int(row["total"] or 0)

@app.get("/okrs/company/current")
async def get_current_company_okrs(me=Depends(get_current_user)):
    qid, qstart, qend = quarter_for_date(date.today())
    seconds_left = seconds_until_end_of_quarter(qend)

    okr_row = await fetchrow(
        """
        SELECT id, quarter_id, quarter_start, quarter_end
        FROM company_okrs
        WHERE quarter_id = $1
        """,
        qid,
    )

    if not okr_row:
        return {
            "quarter": {
                "quarter_id": qid,
                "start_date": qstart.isoformat(),
                "end_date": qend.isoformat(),
                "seconds_remaining": seconds_left,
            },
            "teams": [],
        }

    okr = record_to_dict(okr_row)
    okr_id = str(okr["id"])

    # fetch objectives + team info + objective timeline
    obj_rows = await fetch(
        """
        SELECT
  o.id AS objective_id,
  o.title AS objective_title,
  o.team_id,
  t.name AS team_name,
  o.timeline_start,
  o.timeline_end,
  o.parent_company_level_objective_id,
  o.parent_weight
FROM company_objectives o
LEFT JOIN teams t ON t.id = o.team_id
WHERE o.okr_id = $1::uuid
ORDER BY COALESCE(t.name, 'ZZZ'), o.created_at ASC
        """,
        okr_id,
    )

    teams_map = {}

    for o in obj_rows:
        o = dict(o)

        team_key = str(o["team_id"]) if o["team_id"] else "unassigned"
        team_name = o["team_name"] if o["team_name"] else "Unassigned"

        if team_key not in teams_map:
            teams_map[team_key] = {
                "team_id": None if team_key == "unassigned" else team_key,
                "team_name": team_name,
                "objectives": [],
            }

        # Objective timeline fallback: if null => quarter dates
        tl_start = o["timeline_start"] or qstart
        tl_end = o["timeline_end"] or qend

        ts = obj_timeline_status(tl_end)
        needs_extension_prompt = (me["role"] == "ceo" and ts["is_expired"])

        # ✅ FIX: use alias for company_key_results (prevents any accidental "progress.xxx" misuse)
        kr_rows = await fetch(
            """
            SELECT
              kr.id,
              kr.title,
              kr.status,
              kr.progress,
              kr.weight
            FROM company_key_results kr
            WHERE kr.objective_id = $1::uuid
            ORDER BY kr.created_at ASC
            """,
            str(o["objective_id"]),
        )

        # safer conversion (asyncpg.Record -> dict)
        krs = []
        for kr in kr_rows:
            kr = dict(kr)
            krs.append({
                "id": str(kr["id"]),
                "title": kr["title"],
                "status": kr["status"],
                "progress": kr["progress"],
                "weight": kr["weight"],
            })

        def kr_effective_progress(kr_item: dict):
            p = kr_item.get("progress")
            if p is None:
                if kr_item.get("status") == "completed":
                    return 100
                if kr_item.get("status") == "in_progress":
                    return 50
                return 0
            return int(p)

        total_w = 0
        weighted_sum = 0

        for kr_item in krs:
            w = int(kr_item.get("weight") or 0)
            if w <= 0:
                continue
            total_w += w
            weighted_sum += kr_effective_progress(kr_item) * w

        obj_progress = int(round(weighted_sum / total_w)) if total_w > 0 else 0

        teams_map[team_key]["objectives"].append({
            "id": str(o["objective_id"]),
            "title": o["objective_title"],
            "progress": obj_progress,
            "parent_id": str(o["parent_company_level_objective_id"]) if o["parent_company_level_objective_id"] else None,
            "parent_weight": int(o["parent_weight"] or 0),
            "key_results": krs,
            "timeline": {
                "timeline_start": tl_start.isoformat(),
                "timeline_end": tl_end.isoformat(),
                "is_expired": ts["is_expired"],
                "days_remaining": ts["days_remaining"],
                "needs_extension_prompt": needs_extension_prompt,
            },
        })

    return {
        "quarter": {
            "quarter_id": qid,
            "start_date": qstart.isoformat(),
            "end_date": qend.isoformat(),
            "seconds_remaining": seconds_left,
        },
        "teams": list(teams_map.values()),
    }



# @app.patch("/okrs/company/timeline")
# async def set_company_okr_timeline(body: SetOKRTimelineRequest, me=Depends(get_current_user)):
#     if me["role"] != "ceo":
#         raise HTTPException(status_code=403, detail="Forbidden")

#     # validate
#     if body.timeline_end < body.timeline_start:
#         raise HTTPException(status_code=400, detail="timeline_end must be >= timeline_start")

#     await execute(
#         """
#         UPDATE company_okrs
#         SET timeline_start = $2::date,
#             timeline_end   = $3::date,
#             updated_at = now()
#         WHERE quarter_id = $1
#         """,
#         body.quarter_id,
#         body.timeline_start,
#         body.timeline_end,
#     )

#     return {"success": True}
# @app.patch("/okrs/company/timeline/extend")
# async def extend_company_okr_timeline(body: ExtendOKRTimelineRequest, me=Depends(get_current_user)):
#     if me["role"] != "ceo":
#         raise HTTPException(status_code=403, detail="Forbidden")

#     # لازم تكون تمديد (مش تقليل)
#     row = await fetchrow("SELECT timeline_end FROM company_okrs WHERE quarter_id=$1", body.quarter_id)
#     if not row:
#         raise HTTPException(status_code=404, detail="OKR quarter not found")

#     current_end = row["timeline_end"]
#     if current_end and body.extend_to <= current_end:
#         raise HTTPException(status_code=400, detail="extend_to must be > current timeline_end")

#     await execute(
#         """
#         UPDATE company_okrs
#         SET timeline_end = $2::date,
#             updated_at = now()
#         WHERE quarter_id = $1
#         """,
#         body.quarter_id,
#         body.extend_to,
#     )

#     return {"success": True}

@app.patch("/okrs/company/objectives/{objective_id}/timeline")
async def set_objective_timeline(
    objective_id: str,
    body: SetObjectiveTimelineRequest,
    me=Depends(get_current_user),
):
    if me["role"] != "ceo":
        raise HTTPException(status_code=403, detail="Forbidden")

    if body.timeline_end < body.timeline_start:
        raise HTTPException(status_code=400, detail="timeline_end must be >= timeline_start")

    # Ensure objective exists
    row = await fetchrow(
        "SELECT id FROM company_objectives WHERE id=$1::uuid",
        objective_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Objective not found")

    await execute(
        """
        UPDATE company_objectives
        SET timeline_start = $2::date,
            timeline_end   = $3::date,
            updated_at = now()
        WHERE id = $1::uuid
        """,
        objective_id,
        body.timeline_start,
        body.timeline_end,
    )

    return {"success": True}


@app.get("/okrs/teams")
async def list_okr_teams(me=Depends(get_current_user)):
    if me["role"] != "ceo":
        raise HTTPException(status_code=403, detail="Forbidden")

    rows = await fetch(
        "SELECT id, name FROM teams ORDER BY name"
    )

    return {
        "items": [{"id": str(r["id"]), "name": r["name"]} for r in rows],
        "count": len(rows),
    }

class CreateTeamObjectiveRequest(BaseModel):
    title: str
    team_id: Optional[str] = None
    parent_id: str
    parent_weight: int = Field(ge=1, le=100)

class CreateCompanyObjectiveRequest(BaseModel):
    title: str
    team_id: Optional[str] = None  # allow "Unassigned" if you want

class AddObjectiveRequest(BaseModel):
    title: str
    team_id: Optional[str] = None  # null => unassigned

@app.post("/okrs/company/objectives")
async def add_objective(body: CreateTeamObjectiveRequest, me=Depends(get_current_user)):
    if me["role"] != "ceo":
        raise HTTPException(status_code=403, detail="Forbidden")

    qid, qstart, qend = quarter_for_date(date.today())

    okr_row = await fetchrow(
        """
        INSERT INTO company_okrs (quarter_id, quarter_start, quarter_end, created_by)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (quarter_id) DO UPDATE SET quarter_start=EXCLUDED.quarter_start
        RETURNING id
        """,
        qid, qstart, qend, me["id"]
    )
    okr_id = str(okr_row["id"])

    parent = await fetchrow(
        """
        SELECT id
        FROM company_level_objectives
        WHERE id=$1::uuid AND okr_id=$2::uuid
        """,
        body.parent_id,
        okr_id,
    )
    if not parent:
        raise HTTPException(status_code=404, detail="Parent company-level objective not found for this quarter")

    current_total = await get_parent_total_child_weight(body.parent_id)
    if current_total + body.parent_weight > 100:
        raise HTTPException(
            status_code=400,
            detail=f"Parent weight exceeds 100 (current: {current_total}, adding: {body.parent_weight})"
        )

    await execute(
        """
        INSERT INTO company_objectives (okr_id, team_id, title, parent_company_level_objective_id, parent_weight)
        VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5)
        """,
        okr_id,
        body.team_id,
        body.title,
        body.parent_id,
        body.parent_weight,
    )

    return {"success": True}




@app.post("/okrs/company/key-results")
async def create_key_result(body: AddKeyResultRequest, me=Depends(get_current_user)):
    if me["role"] != "ceo":
        raise HTTPException(403, "Only CEO can create key results")
    
    current_total = await get_objective_total_weight(body.objective_id)
    if current_total + body.weight > 100:
        raise HTTPException(
            status_code=400,
            detail=f"Total KR weight exceeds 100 (current: {current_total}, adding: {body.weight})"
        )


    await execute(
        """
        INSERT INTO company_key_results (objective_id, title, status, progress,weight)
        VALUES ($1::uuid, $2, 'not_started', 0 , $3)
        """,
        body.objective_id,
        body.title,
        body.weight
    )

    return {"success": True}

class UpdateKRProgressRequest(BaseModel):
    id: str
    status: Literal["not_started", "in_progress", "completed"]
    progress: int


@app.patch("/okrs/company/key-results/progress")
async def update_key_result_progress(body: UpdateKRProgressRequest, me=Depends(get_current_user)):
    if me["role"] != "team_leader":
        raise HTTPException(403, "Only team leader can update progress")

    row = await fetchrow(
        """
        SELECT o.team_id
        FROM company_key_results kr
        JOIN company_objectives o ON o.id = kr.objective_id
        WHERE kr.id = $1::uuid
        """,
        body.id
    )

    if not row or str(row["team_id"]) != str(me["team_id"]):
        raise HTTPException(403, "Cannot update other team OKRs")

    # await execute(
    #     """
    #     UPDATE company_key_results
    #     SET status=$2::kr_status, progress=$3, updated_at=now()
    #     WHERE id=$1::uuid
    #     """,
    #     body.id,
    #     body.status,
    #     body.progress
    # )
    await execute(
    """
    UPDATE company_key_results
    SET status=$2::kr_status,
        progress=$3
    WHERE id=$1::uuid
    """,
    body.id,
    body.status,
    body.progress
)


    return {"success": True}


@app.on_event("startup")
async def _print_routes():
    for r in app.routes:
        methods = getattr(r, "methods", None)
        if methods and "/okrs" in r.path:
            print("ROUTE:", r.path, methods)

            
@app.get("/okrs/team/current")
async def get_team_okrs_current(me=Depends(get_current_user)):
    if me["role"] != "team_leader":
        raise HTTPException(status_code=403, detail="Team leader only")

    if not me.get("team_id"):
        raise HTTPException(status_code=400, detail="Leader has no team")

    qid, qstart, qend = quarter_for_date(date.today())
    seconds_left = seconds_until_end_of_quarter(qend)

    okr_row = await fetchrow(
        """
        SELECT id
        FROM company_okrs
        WHERE quarter_id = $1
        """,
        qid,
    )

    if not okr_row:
        # no okrs row for this quarter yet
        team_name_row = await fetchrow("SELECT name FROM teams WHERE id=$1::uuid", str(me["team_id"]))
        return {
            "quarter": {
                "quarter_id": qid,
                "start_date": qstart.isoformat(),
                "end_date": qend.isoformat(),
                "seconds_remaining": seconds_left,
            },
            "team": {
                "team_id": str(me["team_id"]),
                "team_name": team_name_row["name"] if team_name_row else "My Team",
                "objectives": [],
            },
        }

    okr_id = str(okr_row["id"])
    team_id = str(me["team_id"])

    # objectives for this team only
    obj_rows = await fetch(
        """
        SELECT o.id, o.title, o.timeline_start, o.timeline_end
        FROM company_objectives o
        WHERE o.okr_id = $1::uuid
          AND o.team_id = $2::uuid
        ORDER BY o.created_at ASC
        """,
        okr_id,
        team_id,
    )

    objectives = []
    for o in obj_rows:
        o = dict(o)

        kr_rows = await fetch(
            """
            SELECT id, title, status, progress,weight
            FROM company_key_results
            WHERE objective_id = $1::uuid
            ORDER BY created_at ASC
            """,
            str(o["id"]),
        )

        krs = [
            {"id": str(kr["id"]), "title": kr["title"], "status": kr["status"], "progress": kr["progress"] , "weight" : kr["weight"]}
            for kr in kr_rows
        ]

        # objective progress = avg(kr progress), fallback to status mapping
        def kr_effective_progress(kr):
            p = kr["progress"]
            if p is None:
                if kr["status"] == "completed":
                    return 100
                if kr["status"] == "in_progress":
                    return 50
                return 0
            return int(p)

        total_w = 0
        weighted_sum = 0

        for kr in krs:
            w = int(kr.get("weight") or 0)
            if w <= 0:
                continue

            total_w += w
            weighted_sum += kr_effective_progress(kr) * w

        obj_progress = int(round(weighted_sum / total_w)) if total_w > 0 else 0

        tl_start = o.get("timeline_start") or qstart
        tl_end = o.get("timeline_end") or qend

        ts = obj_timeline_status(tl_end)  # you already have this helper



        objectives.append(
            {
                "id": str(o["id"]),
                "title": o["title"],
                "progress": obj_progress,
                "key_results": krs,
                        "timeline": {
            "timeline_start": tl_start.isoformat(),
            "timeline_end": tl_end.isoformat(),
            "is_expired": ts["is_expired"],
            "days_remaining": ts["days_remaining"],
        },
            }
        )

    team_name_row = await fetchrow("SELECT name FROM teams WHERE id=$1::uuid", team_id)

    return {
        "quarter": {
            "quarter_id": qid,
            "start_date": qstart.isoformat(),
            "end_date": qend.isoformat(),
            "seconds_remaining": seconds_left,
        },
        "team": {
            "team_id": team_id,
            "team_name": team_name_row["name"] if team_name_row else "My Team",
            "objectives": objectives,
        },
    }

class SignupRequest(BaseModel):
    name: str
    email: str
    password: str

@app.post("/auth/signup")
async def auth_signup(body: SignupRequest):
    email = body.email.strip().lower()

    # 1) Basic validation
    if len(body.password.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Password too long (bcrypt max 72 bytes)")

    # 2) Check if user exists
    existing = await fetchrow("SELECT id FROM users WHERE LOWER(email)=LOWER($1)", email)
    if existing:
        # prevent enumeration: respond success anyway
        return {"success": True}

    # 3) Create user as pending + unverified
    password_hash = pwd_context.hash(body.password)

    user_row = await fetchrow(
        """
        INSERT INTO users (name, email, password_hash, email_verified, status)
        VALUES ($1, $2, $3, false, 'pending')
        RETURNING id
        """,
        body.name.strip(),
        email,
        password_hash,
    )
    user_id = str(user_row["id"])

    # 4) Create verification token
    raw_token, token_hash = make_verify_token()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=EMAIL_VERIFY_TTL_MIN)

    await execute(
        """
        INSERT INTO email_verifications (user_id, token_hash, expires_at)
        VALUES ($1::uuid, $2, $3)
        """,
        user_id,
        token_hash,
        expires_at,
    )

    # 5) Send verification link (for now: prints in logs)
    link = f"{BACKEND_URL}/auth/verify-email?token={raw_token}"
    # await send_verification_email(email, link)
    send_verification_email(email, link)


    return {"success": True}

@app.get("/auth/verify-email")
async def verify_email(token: str):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)

    # 1) Find a valid verification record
    row = await fetchrow(
        """
        SELECT id, user_id, expires_at, used_at
        FROM email_verifications
        WHERE token_hash = $1
        LIMIT 1
        """,
        token_hash,
    )

    if not row:
        raise HTTPException(status_code=400, detail="Invalid verification link")

    if row["used_at"] is not None:
        raise HTTPException(status_code=400, detail="Verification link already used")

    if row["expires_at"] < now:
        raise HTTPException(status_code=400, detail="Verification link expired")

    # 2) Mark token as used
    await execute(
        """
        UPDATE email_verifications
        SET used_at = now()
        WHERE id = $1::uuid
        """,
        str(row["id"]),
    )

    # 3) Activate user
    await execute(
        """
        UPDATE users
        SET email_verified = true,
            status = 'active',
            updated_at = now()
        WHERE id = $1::uuid
        """,
        str(row["user_id"]),
    )

    # 4) Redirect to frontend role selection page (or login)
    return RedirectResponse(url=f"{FRONTEND_URL}/select-role", status_code=302)

class SelectRoleRequest(BaseModel):
    role: Literal["team_member", "team_leader"]  # do NOT include "ceo"

class CreateTeamRequestRequest(BaseModel):
    team_name: str

class RejectTeamRequestBody(BaseModel):
    admin_note: Optional[str] = None


@app.post("/auth/select-role")
async def select_role(body: SelectRoleRequest, me=Depends(get_current_user)):
    # Must be verified + active
    if not me.get("email_verified"):
        raise HTTPException(status_code=403, detail="Email must be verified first.")
    if me.get("status") != "active":
        raise HTTPException(status_code=403, detail="Account is not active.")

    # One-time set: if already set, block changes
    existing = await fetchrow(
        "SELECT role, role_locked FROM users WHERE id=$1::uuid",
        str(me["id"]),
    )
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")

    if existing["role"] is not None or existing["role_locked"] is True:
        raise HTTPException(status_code=400, detail="Role already set")

    # Body.role is already constrained by Literal, but keep a hard guard
    if body.role == "ceo":
        raise HTTPException(status_code=403, detail="Not allowed")

    await execute(
        """
        UPDATE users
        SET role = $2,
            role_locked = true,
            updated_at = now()
        WHERE id = $1::uuid
        """,
        str(me["id"]),
        body.role,
    )

    return {"success": True, "role": body.role}


@app.post("/teams/request-create")
async def request_team_creation(body: CreateTeamRequestRequest, background_tasks: BackgroundTasks, me=Depends(get_current_user)):
    if not me.get("email_verified") or me.get("status") != "active":
        raise HTTPException(status_code=403, detail="Account must be active and verified.")
    if me.get("role") != "team_leader":
        raise HTTPException(status_code=403, detail="Only team leaders can request a team.")
    if me.get("team_id"):
        raise HTTPException(status_code=400, detail="You already belong to a team.")

    team_name = (body.team_name or "").strip()
    if not team_name:
        raise HTTPException(status_code=400, detail="team_name is required")

    existing_team = await fetchval("SELECT 1 FROM teams WHERE LOWER(name)=LOWER($1)", team_name)
    if existing_team:
        raise HTTPException(status_code=400, detail="A team with this name already exists.")

    pending = await fetchrow(
        "SELECT id FROM team_creation_requests WHERE requester_user_id=$1::uuid AND status='pending'",
        str(me["id"]),
    )
    if pending:
        raise HTTPException(status_code=400, detail="You already have a pending team creation request.")

    row = await fetchrow(
        """
        INSERT INTO team_creation_requests (requester_user_id, team_name)
        VALUES ($1::uuid, $2)
        RETURNING id, requester_user_id, team_name, status, requested_at, reviewed_at, reviewed_by, approved_team_id, admin_note
        """,
        str(me["id"]),
        team_name,
    )

    request_id = str(row["id"])
    admin_email = get_admin_request_email()
    if admin_email:
        approval_link = f"{BACKEND_URL}/teams/requests/{request_id}/approve"
        rejection_link = f"{BACKEND_URL}/teams/requests/{request_id}/reject"
        requester_name = me.get("name") or "N/A"
        html_content = f"""
        <p>A team leader requested to create a new team.</p>
        <ul>
          <li>Requester: {html.escape(requester_name)} ({me.get("email")})</li>
          <li>User ID: {me["id"]}</li>
          <li>Team name: {html.escape(team_name)}</li>
          <li>Request ID: {request_id}</li>
        </ul>
        <p><strong>Approve:</strong> <a href="{approval_link}">{approval_link}</a></p>
        <p><strong>Reject:</strong> <a href="{rejection_link}">{rejection_link}</a></p>
        """
        background_tasks.add_task(
            send_brevo_email,
            to_email=admin_email,
            subject=f"[Action Needed] Team creation request: {team_name}",
            html_content=html_content,
            sender_email=os.getenv("BREVO_ADMIN_EMAIL") or os.getenv("BREVO_SENDER_EMAIL"),
            sender_name=os.getenv("BREVO_SENDER_NAME", "Penguinin Admin"),
        )
    else:
        print("[TEAM REQUEST] Admin email not configured; skipping email send.")

    return {"success": True, "request": serialize_team_creation_request(row)}


@app.get("/teams/requests")
async def list_team_creation_requests(status: Optional[str] = Query(default="pending"), me=Depends(get_current_user)):
    if me["role"] != "ceo":
        raise HTTPException(status_code=403, detail="Only CEO can view team requests")

    allowed_statuses = {"pending", "approved", "rejected"}
    filters = []
    args = []
    if status:
        st = status.lower()
        if st not in allowed_statuses:
            raise HTTPException(status_code=400, detail="Invalid status filter")
        filters.append(f"r.status = ${len(args)+1}")
        args.append(st)

    sql = """
      SELECT
        r.id, r.requester_user_id, r.team_name, r.status, r.requested_at,
        r.reviewed_at, r.reviewed_by, r.approved_team_id, r.admin_note,
        u.name AS requester_name, u.email AS requester_email
      FROM team_creation_requests r
      JOIN users u ON u.id = r.requester_user_id
    """
    if filters:
        sql += " WHERE " + " AND ".join(filters)
    sql += " ORDER BY r.requested_at DESC"

    rows = await fetch(sql, *args)
    items = []
    for r in rows:
        rd = dict(r)
        item = serialize_team_creation_request(r)
        item["requester"] = {
            "id": str(rd["requester_user_id"]),
            "name": rd.get("requester_name"),
            "email": rd.get("requester_email"),
        }
        items.append(item)

    return items


@app.get("/teams/requests/me")
async def my_team_requests(me=Depends(get_current_user)):
    rows = await fetch(
        """
        SELECT id, requester_user_id, team_name, status, requested_at, reviewed_at, reviewed_by, approved_team_id, admin_note
        FROM team_creation_requests
        WHERE requester_user_id=$1::uuid
        ORDER BY requested_at DESC
        """,
        str(me["id"]),
    )
    items = [serialize_team_creation_request(r) for r in rows]
    return items


@app.post("/teams/requests/{request_id}/approve")
async def approve_team_request(request_id: str, me=Depends(get_current_user)):
    if me["role"] != "ceo":
        raise HTTPException(status_code=403, detail="Only CEO can approve requests")

    pool = await init_db_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            req = await conn.fetchrow(
                """
                SELECT id, requester_user_id, team_name, status, requested_at, reviewed_at, reviewed_by, approved_team_id, admin_note
                FROM team_creation_requests
                WHERE id=$1::uuid
                FOR UPDATE
                """,
                request_id,
            )
            if not req:
                raise HTTPException(status_code=404, detail="Request not found")
            if req["status"] != "pending":
                raise HTTPException(status_code=400, detail="Request already reviewed")

            existing_team = await conn.fetchval("SELECT 1 FROM teams WHERE LOWER(name)=LOWER($1)", req["team_name"])
            if existing_team:
                raise HTTPException(status_code=400, detail="A team with this name already exists.")

            requester = await conn.fetchrow(
                """
                SELECT id, email_verified, status, role, team_id
                FROM users
                WHERE id=$1::uuid
                FOR UPDATE
                """,
                str(req["requester_user_id"]),
            )
            if not requester:
                raise HTTPException(status_code=404, detail="Requester user not found")
            if requester["team_id"]:
                raise HTTPException(status_code=400, detail="Requester already in a team")
            if requester["status"] != "active":
                raise HTTPException(status_code=400, detail="Requester is not active")
            if not requester["email_verified"]:
                raise HTTPException(status_code=400, detail="Requester email not verified")
            if requester["role"] != "team_leader":
                raise HTTPException(status_code=400, detail="Requester must be a team leader")

            invite_code = await generate_unique_invite_code(conn)

            team_row = await conn.fetchrow(
                """
                INSERT INTO teams (name, leader_id, invite_code)
                VALUES ($1, $2::uuid, $3)
                RETURNING id, name, leader_id, invite_code, created_at, updated_at
                """,
                req["team_name"],
                str(req["requester_user_id"]),
                invite_code,
            )

            await conn.execute(
                "UPDATE users SET team_id=$2::uuid, updated_at=now() WHERE id=$1::uuid",
                str(req["requester_user_id"]),
                str(team_row["id"]),
            )

            await conn.execute(
                """
                UPDATE team_creation_requests
                SET status='approved',
                    reviewed_at=now(),
                    reviewed_by=$2::uuid,
                    approved_team_id=$3::uuid
                WHERE id=$1::uuid
                """,
                str(req["id"]),
                str(me["id"]),
                str(team_row["id"]),
            )

            updated_req = await conn.fetchrow(
                """
                SELECT id, requester_user_id, team_name, status, requested_at, reviewed_at, reviewed_by, approved_team_id, admin_note
                FROM team_creation_requests
                WHERE id=$1::uuid
                """,
                str(req["id"]),
            )

    t = record_to_dict(team_row)
    return {
        "success": True,
        "team": {
            "id": str(t["id"]),
            "name": t["name"],
            "leader_id": str(t["leader_id"]),
            "invite_code": t["invite_code"].upper(),
            "created_at": t["created_at"].isoformat(),
            "updated_at": t["updated_at"].isoformat(),
        },
        "request": serialize_team_creation_request(updated_req),
    }


@app.post("/teams/requests/{request_id}/reject")
async def reject_team_request(request_id: str, body: RejectTeamRequestBody, me=Depends(get_current_user)):
    if me["role"] != "ceo":
        raise HTTPException(status_code=403, detail="Only CEO can reject requests")

    pool = await init_db_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            req = await conn.fetchrow(
                """
                SELECT id, requester_user_id, team_name, status, requested_at, reviewed_at, reviewed_by, approved_team_id, admin_note
                FROM team_creation_requests
                WHERE id=$1::uuid
                FOR UPDATE
                """,
                request_id,
            )
            if not req:
                raise HTTPException(status_code=404, detail="Request not found")
            if req["status"] != "pending":
                raise HTTPException(status_code=400, detail="Request already reviewed")

            await conn.execute(
                """
                UPDATE team_creation_requests
                SET status='rejected',
                    reviewed_at=now(),
                    reviewed_by=$2::uuid,
                    admin_note=$3
                WHERE id=$1::uuid
                """,
                str(req["id"]),
                str(me["id"]),
                body.admin_note,
            )

            updated_req = await conn.fetchrow(
                """
                SELECT id, requester_user_id, team_name, status, requested_at, reviewed_at, reviewed_by, approved_team_id, admin_note
                FROM team_creation_requests
                WHERE id=$1::uuid
                """,
                str(req["id"]),
            )

    return {"success": True, "request": serialize_team_creation_request(updated_req)}


class JoinTeamRequest(BaseModel):
    invite_code: str

@app.post("/auth/join-team")
async def join_team(body: JoinTeamRequest, me=Depends(get_current_user)):
    if not me.get("email_verified") or me.get("status") != "active":
        raise HTTPException(403, "Account must be active and verified.")
    if me.get("team_id"):
        raise HTTPException(400, "Team already set.")
    if me.get("role") not in ("team_member", "team_leader"):
        raise HTTPException(400, "Role must be set first.")

    invite_code = body.invite_code.strip().upper()
    team = await fetchrow("SELECT id FROM teams WHERE invite_code=$1", invite_code)
    if not team:
        raise HTTPException(400, "Invalid invite code.")

    await execute(
        "UPDATE users SET team_id=$2::uuid, updated_at=now() WHERE id=$1::uuid",
        str(me["id"]), str(team["id"])
    )
    return {"success": True}



@app.get("/weeks")
async def list_weeks(
    limit: int = Query(default=12, ge=1, le=104),
    include_current: bool = Query(default=True),
):
    """
    Returns a list of weeks (most recent first).
    - limit: how many weeks to return (default 12)
    - include_current: include current week in results (default True)
    """

    today = datetime.now(AMMAN_TZ).date()
    start_anchor = today if include_current else (today - timedelta(days=7))

    # Build desired week definitions in-memory
    desired = []
    for i in range(limit):
        d = start_anchor - timedelta(days=7 * i)
        start, end = week_bounds_sun_to_sat(d)
        wid = week_id_sunday_based(d)
        label = week_label(wid, start, end)
        desired.append((wid, start, end, label))

    # Upsert all desired weeks (idempotent)
    pool = await init_db_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            for wid, start, end, label in desired:
                await conn.execute(
                    """
                    INSERT INTO weeks (week_id, start_date, end_date, display_label)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (week_id) DO UPDATE
                    SET start_date = EXCLUDED.start_date,
                        end_date = EXCLUDED.end_date,
                        display_label = EXCLUDED.display_label
                    """,
                    wid, start, end, label
                )

            # Now fetch them back ordered by start_date desc
            rows = await conn.fetch(
                """
                SELECT week_id, start_date, end_date, display_label
                FROM weeks
                WHERE week_id = ANY($1::text[])
                ORDER BY start_date DESC
                """,
                [x[0] for x in desired],
            )

    items = []
    for r in rows:
        r = dict(r)
        items.append({
            "week_id": r["week_id"],
            "start_date": r["start_date"].isoformat(),
            "end_date": r["end_date"].isoformat(),
            "display_label": r["display_label"],
        })

    return {"items": items, "count": len(items)}


class AddKeyResultRequest(BaseModel):
    objective_id: str
    title: str
    weight: int = Field(default=1, ge=1, le=100)
class UpdateKRWeightRequest(BaseModel):
    id: str
    weight: int = Field(ge=1, le=100)


from uuid import UUID

@app.post("/okrs/team/key-results")
async def team_leader_create_key_result(body: AddKeyResultRequest, me=Depends(get_current_user)):
    if me["role"] != "team_leader":
        raise HTTPException(status_code=403, detail="Only team leader can create key results")

    if not me.get("team_id"):
        raise HTTPException(status_code=400, detail="Leader has no team")

    # 0) Validate UUID (so you don't get silent weird 404s)
    try:
        objective_id = str(UUID(body.objective_id))
    except Exception:
        raise HTTPException(status_code=400, detail="objective_id must be a valid UUID")

    # 1) Validate objective exists AND belongs to leader's team (same pattern as progress endpoint)
    obj = await fetchrow(
        """
        SELECT o.id
        FROM company_objectives o
        WHERE o.id = $1::uuid
          AND o.team_id = $2::uuid
        """,
        objective_id,
        str(me["team_id"]),
    )
    if not obj:
        # if you prefer 403 instead, change this line
        raise HTTPException(status_code=404, detail="Objective not found for your team")

    # 2) Enforce KR total weight <= 100 (same as CEO logic)
    current_total = await get_objective_total_weight(objective_id)
    if current_total + body.weight > 100:
        raise HTTPException(
            status_code=400,
            detail=f"Total KR weight exceeds 100 (current: {current_total}, adding: {body.weight})"
        )

    # 3) Insert KR
    await execute(
        """
        INSERT INTO company_key_results (objective_id, title, status, progress, weight)
        VALUES ($1::uuid, $2, 'not_started', 0, $3)
        """,
        objective_id,
        body.title,
        body.weight,
    )

    return {"success": True}


@app.patch("/okrs/company/key-results/weight")
async def update_key_result_weight(body: UpdateKRWeightRequest, me=Depends(get_current_user)):
    if me["role"] != "ceo":
        raise HTTPException(403, "Only CEO can update KR weight")
    
    
    kr = await fetchrow(
        """
        SELECT objective_id, weight
        FROM company_key_results
        WHERE id = $1::uuid
        """,
        body.id,
    )

    if not kr:
        raise HTTPException(404, "Key Result not found")

    objective_id = str(kr["objective_id"])
    old_weight = int(kr["weight"] or 0)

    # current total includes this KR → remove it
    current_total = await get_objective_total_weight(objective_id)
    new_total = current_total - old_weight + body.weight

    if new_total > 100:
        raise HTTPException(
            status_code=400,
            detail=f"Total KR weight exceeds 100 (current: {current_total}, new total: {new_total})"
        )

    await execute(
        """
        UPDATE company_key_results
        SET weight=$2, updated_at=now()
        WHERE id=$1::uuid
        """,
        body.id,
        body.weight,
    )
    return {"success": True}


class CreateCompanyLevelObjectiveRequest(BaseModel):
    title: str

@app.post("/okrs/company/level-objectives")
async def create_company_level_objective(body: CreateCompanyLevelObjectiveRequest, me=Depends(get_current_user)):
    if me["role"] != "ceo":
        raise HTTPException(403, "Forbidden")

    qid, qstart, qend = quarter_for_date(date.today())

    okr_row = await fetchrow(
        """
        INSERT INTO company_okrs (quarter_id, quarter_start, quarter_end, created_by)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (quarter_id) DO UPDATE SET quarter_start=EXCLUDED.quarter_start
        RETURNING id
        """,
        qid, qstart, qend, me["id"]
    )
    okr_id = okr_row["id"]

    await execute(
        """
        INSERT INTO company_level_objectives (okr_id, title)
        VALUES ($1::uuid, $2)
        """,
        okr_id, body.title
    )

    return {"success": True}


class CompanyLevelObjectiveItem(BaseModel):
    id: str
    title: str

@app.get("/okrs/company/level-objectives")
async def list_company_level_objectives(me=Depends(get_current_user)):
    if me["role"] != "ceo":
        raise HTTPException(status_code=403, detail="Forbidden")

    qid, qstart, qend = quarter_for_date(date.today())

    okr_row = await fetchrow(
        "SELECT id FROM company_okrs WHERE quarter_id=$1",
        qid,
    )
    if not okr_row:
        return {"items": [], "count": 0}

    okr_id = str(okr_row["id"])

    rows = await fetch(
        """
        SELECT id, title
        FROM company_level_objectives
        WHERE okr_id = $1::uuid
        ORDER BY created_at ASC
        """,
        okr_id,
    )

    items = [{"id": str(r["id"]), "title": r["title"]} for r in rows]
    return {"items": items, "count": len(items)}



class UpdateObjectiveParentWeightRequest(BaseModel):
    objective_id: str
    parent_weight: int = Field(ge=1, le=100)

@app.patch("/okrs/company/objectives/parent-weight")
async def update_objective_parent_weight(body: UpdateObjectiveParentWeightRequest, me=Depends(get_current_user)):
    if me["role"] != "ceo":
        raise HTTPException(status_code=403, detail="Only CEO can update objective weight")

    # Fetch objective + its parent + current weight
    obj = await fetchrow(
        """
        SELECT id, parent_company_level_objective_id, parent_weight
        FROM company_objectives
        WHERE id=$1::uuid
        """,
        body.objective_id,
    )
    if not obj:
        raise HTTPException(status_code=404, detail="Objective not found")

    parent_id = obj["parent_company_level_objective_id"]
    if not parent_id:
        raise HTTPException(status_code=400, detail="Objective has no parent company-level objective")

    old_weight = int(obj["parent_weight"] or 0)

    # Validate new sum <= 100 for that parent, excluding this objective
    current_total = await get_parent_total_child_weight(str(parent_id))
    new_total = current_total - old_weight + body.parent_weight
    if new_total > 100:
        raise HTTPException(
            status_code=400,
            detail=f"Total children weights exceed 100 (current: {current_total}, new total: {new_total})",
        )

    await execute(
        """
        UPDATE company_objectives
        SET parent_weight=$2, updated_at=now()
        WHERE id=$1::uuid
        """,
        body.objective_id,
        body.parent_weight,
    )
    return {"success": True}

from fastapi import Query

@app.get("/okrs/company/level-progress")
async def get_company_level_progress(
    week_id: str | None = Query(default=None),  # accepted for frontend compatibility (ignored)
    me=Depends(get_current_user),
):
    if me["role"] != "ceo":
        raise HTTPException(status_code=403, detail="Forbidden")

    # OKRs are quarter-based in your system
    qid, qstart, qend = quarter_for_date(date.today())

    okr_row = await fetchrow(
        "SELECT id FROM company_okrs WHERE quarter_id = $1",
        qid,
    )
    if not okr_row:
        return {"items": [], "count": 0}

    okr_id = str(okr_row["id"])

    # Parents
    parent_rows = await fetch(
        """
        SELECT id, title
        FROM company_level_objectives
        WHERE okr_id = $1::uuid
        ORDER BY created_at ASC
        """,
        okr_id,
    )
    parents = [{"id": str(p["id"]), "title": p["title"]} for p in parent_rows]

    # Children objectives (team objectives) for this quarter
    obj_rows = await fetch(
        """
        SELECT
          o.id,
          o.title,
          o.team_id,
          t.name AS team_name,
          o.parent_company_level_objective_id AS parent_id,
          o.parent_weight
        FROM company_objectives o
        LEFT JOIN teams t ON t.id = o.team_id
        WHERE o.okr_id = $1::uuid
        ORDER BY o.created_at ASC
        """,
        okr_id,
    )

    if not obj_rows:
        # parents exist but no children yet
        return {
            "items": [
                {"id": p["id"], "title": p["title"], "progress": 0, "children": []}
                for p in parents
            ],
            "count": len(parents),
        }

    objective_ids = [str(o["id"]) for o in obj_rows]

    # Fetch ALL KRs for these objectives in one query
    kr_rows = await fetch(
        """
        SELECT id, objective_id, status, progress, weight
        FROM company_key_results
        WHERE objective_id = ANY($1::uuid[])
        ORDER BY created_at ASC
        """,
        objective_ids,
    )

    # Group KRs by objective
    krs_by_obj: dict[str, list[dict]] = {}
    for r in kr_rows:
        oid = str(r["objective_id"])
        krs_by_obj.setdefault(oid, []).append(
            {
                "id": str(r["id"]),
                "status": r["status"],
                "progress": r["progress"],
                "weight": int(r["weight"] or 0),
            }
        )

    def kr_effective_progress(kr: dict) -> int:
        p = kr.get("progress")
        if p is None:
            if kr.get("status") == "completed":
                return 100
            if kr.get("status") == "in_progress":
                return 50
            return 0
        return int(p)

    # Compute objective progress from its KRs
    obj_progress_map: dict[str, int] = {}
    for o in obj_rows:
        oid = str(o["id"])
        krs = krs_by_obj.get(oid, [])
        total_w = 0
        weighted_sum = 0
        for kr in krs:
            w = int(kr.get("weight") or 0)
            if w <= 0:
                continue
            total_w += w
            weighted_sum += kr_effective_progress(kr) * w
        obj_progress_map[oid] = int(round(weighted_sum / total_w)) if total_w > 0 else 0

    # Group children under parent
    children_by_parent: dict[str, list[dict]] = {}
    for o in obj_rows:
        parent_id = o["parent_id"]
        if not parent_id:
            # objective not linked to a company-level parent → skip in parent cards
            continue

        oid = str(o["id"])
        pid = str(parent_id)
        children_by_parent.setdefault(pid, []).append(
            {
                "id": oid,
                "title": o["title"],
                "team_name": o["team_name"],
                "progress": obj_progress_map.get(oid, 0),
                "parent_weight": int(o["parent_weight"] or 0),
            }
        )

    # Compute parent progress from children (weighted by parent_weight)
    items = []
    for p in parents:
        pid = p["id"]
        children = children_by_parent.get(pid, [])

        total_w = 0
        weighted_sum = 0
        for c in children:
            w = int(c.get("parent_weight") or 0)
            if w <= 0:
                continue
            total_w += w
            weighted_sum += int(c.get("progress") or 0) * w

        parent_progress = int(round(weighted_sum / total_w)) if total_w > 0 else 0

        items.append(
            {
                "id": pid,
                "title": p["title"],
                "progress": parent_progress,
                "children": children,
            }
        )

    return {"items": items, "count": len(items)}


@app.get("/okrs/key-results/{kr_id}/updates")
async def get_kr_updates(
    kr_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    me=Depends(get_current_user),
):
    role = me["role"]
    team_id = me.get("team_id")

    where = ["u.kr_id = $1::uuid"]
    args = [kr_id, limit]

    if role == "ceo":
        pass
    elif role == "team_leader":
        if not team_id:
            raise HTTPException(400, "Leader has no team")
        where.append("u.team_id = $3::uuid")
        args.append(str(team_id))
    elif role == "team_member":
        where.append("u.author_user_id = $3::uuid")
        args.append(str(me["id"]))
    else:
        raise HTTPException(403, "Forbidden")

    sql = f"""
      SELECT
        u.id, u.week_id, w.display_label,
        u.note, u.meta, u.created_at,
        au.id AS author_id, au.name AS author_name, au.email AS author_email
      FROM company_key_result_updates u
      LEFT JOIN weeks w ON w.week_id = u.week_id
      LEFT JOIN users au ON au.id = u.author_user_id
      WHERE {" AND ".join(where)}
      ORDER BY u.created_at DESC
      LIMIT $2
    """

    rows = await fetch(sql, *args)

    items = []
    for r in rows:
        r = dict(r)
        items.append({
            "id": str(r["id"]),
            "week_id": r["week_id"],
            "week_label": r.get("display_label"),
            "note": r["note"],
            "meta": ensure_json(r["meta"]),
            "created_at": r["created_at"].isoformat(),
            "author": None if not r.get("author_id") else {
                "id": str(r["author_id"]),
                "name": r.get("author_name"),
                "email": r.get("author_email"),
            }
        })

    return {"items": items, "count": len(items)}


@app.get("/okrs/company/key-results/updates")
async def get_company_kr_updates(
    limit: int = Query(default=200, ge=1, le=500),
    me=Depends(get_current_user),
):
    if me["role"] != "ceo":
        raise HTTPException(status_code=403, detail="Forbidden")

    qid, qstart, qend = quarter_for_date(date.today())

    sql = """
      SELECT
        u.id,
        u.kr_id,
        kr.title AS kr_title,
        kr.objective_id,
        o.title AS objective_title,
        o.team_id,
        t.name AS team_name,
        u.week_id,
        w.display_label AS week_label,
        u.note,
        u.meta,
        u.created_at,
        au.id AS author_id,
        au.name AS author_name,
        au.email AS author_email
      FROM company_key_result_updates u
      JOIN company_key_results kr ON kr.id = u.kr_id
      JOIN company_objectives o ON o.id = kr.objective_id
      JOIN company_okrs ok ON ok.id = o.okr_id
      LEFT JOIN teams t ON t.id = o.team_id
      LEFT JOIN weeks w ON w.week_id = u.week_id
      LEFT JOIN users au ON au.id = u.author_user_id
      WHERE ok.quarter_id = $1
      ORDER BY u.created_at DESC
      LIMIT $2
    """

    rows = await fetch(sql, qid, limit)

    items = []
    for r in rows:
        r = dict(r)
        items.append({
            "id": str(r["id"]),
            "kr_id": str(r["kr_id"]),
            "kr_title": r["kr_title"],
            "objective_id": str(r["objective_id"]),
            "objective_title": r["objective_title"],
            "team": None if not r.get("team_id") else {"id": str(r["team_id"]), "name": r.get("team_name")},
            "week_id": r["week_id"],
            "week_label": r.get("week_label"),
            "note": r["note"],
            "meta": ensure_json(r["meta"]),
            "created_at": r["created_at"].isoformat(),
            "author": None if not r.get("author_id") else {
                "id": str(r["author_id"]),
                "name": r.get("author_name"),
                "email": r.get("author_email"),
            }
        })

    return {"items": items, "count": len(items)}

if __name__ == "__main__":
    import uvicorn

    #uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
