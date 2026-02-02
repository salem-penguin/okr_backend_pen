from fastapi import FastAPI, Header, HTTPException, Query
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
import secrets, hashlib
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

# async def send_verification_email(to_email: str, link: str):
#     # Step-by-step: for now we just print the link in the server logs
#     print(f"[VERIFY EMAIL] To: {to_email} Link: {link}")

def send_verification_email(to_email: str, link: str):
    import sib_api_v3_sdk
    from sib_api_v3_sdk.rest import ApiException

    api_key = os.getenv("BREVO_API_KEY")
    sender_email = os.getenv("BREVO_SENDER_EMAIL")
    sender_name = os.getenv("BREVO_SENDER_NAME", "Weekly Wins Hub")

    if not api_key or not sender_email:
        raise RuntimeError("BREVO_API_KEY / BREVO_SENDER_EMAIL are missing in env")

    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key["api-key"] = api_key

    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
        sib_api_v3_sdk.ApiClient(configuration)
    )

    subject = "Verify your email"
    html_content = f"""
    <p>Verify your email:</p>
    <p><a href="{link}">{link}</a></p>
    """

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
    # role gate
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
            RETURNING id, week_id, user_id, report_type, status, submitted_at
            """,
            body.week_id,
            me["id"],
            body.report_type,
        )

    if not row:
        raise HTTPException(status_code=404, detail="Draft report not found (or already submitted)")

    r = record_to_dict(row)
    return {
        "id": str(r["id"]),
        "week_id": r["week_id"],
        "user_id": str(r["user_id"]),
        "report_type": r["report_type"],
        "status": r["status"],
        "submitted_at": r["submitted_at"].isoformat() if r["submitted_at"] else None,
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
        if not user_team_id:
            raise HTTPException(status_code=400, detail="Leader has no team_id")

        # If caller requests team_id that isn't theirs → forbid
        if team_id and team_id.lower() != str(user_team_id).lower():
            raise HTTPException(status_code=403, detail="Leaders can only access their own team")

        # - member reports: team_id = leader team
        # - leader reports: only where user_id = leader
        where.append(
            f"""(
                (r.report_type='member'::report_type AND r.team_id = ${len(args)+1}::uuid)
                OR
                (r.report_type='leader'::report_type AND r.user_id = ${len(args)+2}::uuid)
            )"""
        )
        args.append(str(user_team_id))
        args.append(str(user_id))

    elif role == "team_member":
        where.append(f"r.user_id = ${len(args)+1}::uuid")
        args.append(str(user_id))

        # Optional: forbid team_id filter mismatch
        if team_id and user_team_id and team_id.lower() != str(user_team_id).lower():
            raise HTTPException(status_code=403, detail="Cannot access other teams")

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
    team_id: Optional[str] = None  # assign objective to a team

class UpdateKeyResultRequest(BaseModel):
    id: str
    status: Literal["not_started", "in_progress", "completed"]
    progress: int = Field(ge=0, le=100)



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
          o.timeline_end
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


class AddObjectiveRequest(BaseModel):
    title: str
    team_id: Optional[str] = None  # null => unassigned

@app.post("/okrs/company/objectives")
async def add_objective(body: AddObjectiveRequest, me=Depends(get_current_user)):
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
    okr_id = okr_row["id"]

    await execute(
        """
        INSERT INTO company_objectives (okr_id, team_id, title)
        VALUES ($1::uuid, $2::uuid, $3)
        """,
        okr_id,
        body.team_id,   # may be None
        body.title
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

    team = await fetchrow("SELECT id FROM teams WHERE invite_code=$1", body.invite_code.strip())
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



if __name__ == "__main__":
    import uvicorn

    #uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
    uvicorn.run("main:app", host="0.0.0.0", port=8000)

