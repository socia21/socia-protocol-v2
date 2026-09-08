import os
import json
import socket
socket.setdefaulttimeout(8)  # Hard cap on ALL network ops (including DNS lookups), prevents indefinite hangs
import hashlib
import hmac
import binascii
from datetime import datetime, timedelta
import random
import smtplib
import time
import jwt
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, BackgroundTasks, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlmodel import Field, SQLModel, Session, create_engine, select
from sqlalchemy import text, or_

# Environment Variables
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./socia_database.db")

# Google Workspace SMTP credentials (sociacreator@contactsocia.com)
GMAIL_SENDER = os.getenv("GMAIL_SENDER", "sociacreator@contactsocia.com")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")  # 16-char App Password, set in Railway Variables

BASE_COMMISSION_PERCENT = float(os.getenv("BASE_COMMISSION_PERCENT", "7"))  # standard take rate
SUBSCRIBER_COMMISSION_PERCENT = float(os.getenv("SUBSCRIBER_COMMISSION_PERCENT", "3.5"))  # discounted rate for Sovereign Pass subscribers
SUBSCRIPTION_PRICE_INR = float(os.getenv("SUBSCRIPTION_PRICE_INR", "20000"))  # monthly price in ₹

def get_commission_rate(sponsor: "UserAccount") -> float:
    """Sponsors with an active, non-expired subscription pay the discounted rate."""
    if sponsor.is_subscribed and sponsor.subscription_expires_at and sponsor.subscription_expires_at > datetime.utcnow():
        return SUBSCRIBER_COMMISSION_PERCENT
    return BASE_COMMISSION_PERCENT
PLATFORM_URL = os.getenv("RAILWAY_PUBLIC_DOMAIN")
PLATFORM_URL = f"https://{PLATFORM_URL}" if PLATFORM_URL else "https://www.contactsocia.com"

# --- RAZORPAY ROUTE CONFIG (active payment provider for India — Stripe India is invite-only) ---
import requests as http_requests
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")  # rzp_test_... or rzp_live_... — set in Railway Variables
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")
RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "")
RAZORPAY_SUBSCRIPTION_WEBHOOK_SECRET = os.getenv("RAZORPAY_SUBSCRIPTION_WEBHOOK_SECRET", "") or RAZORPAY_WEBHOOK_SECRET
RAZORPAY_API_BASE = "https://api.razorpay.com/v1"
if not RAZORPAY_KEY_ID:
    print("[PAYMENTS WARNING] RAZORPAY_KEY_ID not set. Razorpay payment endpoints will return 503 until configured.")

def razorpay_request(method: str, path: str, json_body: dict = None, params: dict = None):
    """Thin wrapper around Razorpay's REST API using HTTP Basic Auth (key_id:key_secret).
    Used instead of guessing at SDK method names, so behavior matches Razorpay's documented
    REST endpoints exactly."""
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        raise HTTPException(status_code=503, detail="Payments are not configured yet. Set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET in Railway Variables.")
    url = f"{RAZORPAY_API_BASE}{path}"
    try:
        resp = http_requests.request(
            method, url,
            auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET),
            json=json_body, params=params, timeout=15
        )
        if resp.status_code >= 400:
            detail = resp.json().get("error", {}).get("description", resp.text) if resp.content else resp.text
            raise HTTPException(status_code=400, detail=f"Razorpay error: {detail}")
        return resp.json()
    except http_requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Could not reach Razorpay: {str(e)}")

# --- JWT AUTH CONFIG ---
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_SECRET_IS_FIXED = bool(JWT_SECRET)
if not JWT_SECRET:
    JWT_SECRET = binascii.hexlify(os.urandom(32)).decode()
    print("[SECURITY WARNING] JWT_SECRET is not set in environment variables. Using a random secret "
          "generated at startup — this means all existing logins will be invalidated on every restart/redeploy. "
          "Set JWT_SECRET to a fixed random string in Railway Variables for production use.")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24

# --- ADMIN ACCESS CONFIG ---
ADMIN_SECRET = os.getenv("ADMIN_SECRET")  # Set this in Railway Variables to enable the admin ticket dashboard
ADMIN_NOTIFICATION_EMAIL = os.getenv("ADMIN_NOTIFICATION_EMAIL", "")  # where new support ticket alerts are sent

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

### BUG FIX (Sept 2026): this was hardcoded `echo=True` — every single SQL statement,
### including full parameter values (emails, tokens, OTP codes, bio text...) was being
### written to stdout/Railway logs on every request in PRODUCTION, unconditionally. That's
### a real cost at scale (log volume) and a real exposure risk (sensitive data in logs).
### Now off by default; set SQL_ECHO=true in Railway Variables only when you actually need
### to debug a query.
engine = create_engine(DATABASE_URL, echo=os.getenv("SQL_ECHO", "false").lower() == "true")

# --- DATABASE MODELS ---
class UserAccount(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    role: str  # 'sponsor' or 'influencer'
    display_name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    handle: str
    is_verified: bool = Field(default=False)
    otp_code: Optional[str] = Field(default=None)
    otp_purpose: Optional[str] = Field(default=None)  # 'register' | 'login_2fa' | 'reset' — prevents an OTP issued for one flow being replayed in another
    phone_number: str = Field(default="")
    industry: str = Field(default="")

    company_name: Optional[str] = Field(default=None)
    notification_preferences: Optional[str] = Field(default="all")
    avatar_url: Optional[str] = Field(default=None)
    accepted_terms: bool = Field(default=False)
    accepted_terms_at: Optional[datetime] = Field(default=None)
    stripe_connect_account_id: Optional[str] = Field(default=None)
    stripe_connect_onboarded: bool = Field(default=False)
    razorpay_account_id: Optional[str] = Field(default=None)
    is_subscribed: bool = Field(default=False)
    subscription_id: Optional[str] = Field(default=None)
    subscription_expires_at: Optional[datetime] = Field(default=None)
    razorpay_account_active: bool = Field(default=False)
    payout_account_linked_at: Optional[datetime] = Field(default=None)  # tracks when the CURRENT payout account was linked, for the cooldown check

class MarketplaceListing(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    contact: str
    name: str
    role: str
    industry: str
    rates: str
    stats: str
    bio: str
    pre_conditions_str: str
    match_score: int = Field(default=98)
    # SECURITY/TRUST FIX (Sept 2026): this used to default to True, meaning every listing
    # anyone ever created was instantly shown a "SOCIA Verified Reputator" badge with zero
    # actual verification — a false trust signal on a platform whose entire pitch is trust.
    # New listings now start unverified; an admin must explicitly flip this via
    # /api/admin/listings/{id}/verify. Existing rows already stored as verified=True in the
    # database are left as-is by this change (no retroactive un-verification of live data).
    verified: bool = Field(default=False)
    # --- Mandated structured fields, required for real algorithmic matching ---
    budget_min: float = Field(default=0)
    budget_max: float = Field(default=0)
    # NOTE ON SEMANTICS (role-dependent — see compute_match_breakdown):
    #   influencer listing -> this creator's OWN actual audience size / engagement rate.
    #   sponsor listing     -> the MINIMUM creator audience size / engagement rate this
    #                          sponsor requires (0 = no minimum stated). Sponsors have no
    #                          "audience size" of their own, so mirroring the same two
    #                          fields as a requirement bar (rather than a self-stat) is what
    #                          makes them meaningful for a sponsor listing at all.
    audience_size: int = Field(default=0)
    engagement_rate: float = Field(default=0)  # percentage, e.g. 3.5 = 3.5%
    niche_tags: str = Field(default="")  # comma-separated, e.g. "fitness,tech,beauty"
    is_anonymous: bool = Field(default=False)  # masks identity in public browsing; real name only shown once a pitch is accepted
    # --- Optional matching signals — never required, always disclosed to the user as optional ---
    location: str = Field(default="")  # e.g. "Mumbai, India" — now mandatory at listing creation
    platforms: str = Field(default="")  # comma-separated: Instagram, YouTube, TikTok, etc. — mandatory
    content_languages: str = Field(default="")  # comma-separated: language(s) of content produced — mandatory
    interests: str = Field(default="")  # comma-separated tags, optional
    hide_location_publicly: bool = Field(default=False)  # used for matching regardless; hidden from public view if set
    # --- New (Sept 2026): brand-safety + locality signals, sponsor-side ---
    excluded_niches: str = Field(default="")  # comma-separated niches a SPONSOR won't be associated with (e.g. "gambling,alcohol")
    requires_local_presence: bool = Field(default=False)  # sponsor flag: this campaign needs an in-market/local creator, so location should count
    created_at: datetime = Field(default_factory=datetime.utcnow)  # for growth/trend analytics; backfilled to epoch-ish default on old rows via migration

class DealLedgerRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    deal_ref: str
    counterparty: str
    amount: float
    status: str = Field(default="Pending")

class Pitch(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    sender_email: str = Field(index=True)
    sender_name: str
    sender_role: str  # 'sponsor' or 'influencer'
    recipient_email: str = Field(index=True)
    recipient_name: str
    amount: float
    brief: str
    status: str = Field(default="Pending")  # Pending / Accepted / Rejected

class AuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True)
    action: str
    detail: str = Field(default="")
    created_at: datetime = Field(default_factory=datetime.utcnow)

class SupportTicket(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True)
    name: str
    subject: str
    message: str
    status: str = Field(default="Open")  # Open / In Progress / Resolved
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Negotiation(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    pitch_id: int
    sponsor_email: str = Field(index=True)
    sponsor_name: str
    influencer_email: str = Field(index=True)
    influencer_name: str
    amount: float
    brief: str
    sponsor_locked: bool = Field(default=False)
    influencer_locked: bool = Field(default=False)

class NegotiationCondition(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    negotiation_id: int = Field(index=True)
    text: str
    author_role: str
    author_name: str

class NegotiationMessage(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    negotiation_id: int = Field(index=True)
    sender_name: str
    text: str

class EscrowPayment(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    negotiation_id: int = Field(index=True, unique=True)
    sponsor_email: str
    influencer_email: str
    amount: float  # total amount sponsor pays, in dollars
    platform_fee: float  # calculated at funding time
    influencer_payout: float  # amount - platform_fee
    stripe_payment_intent_id: Optional[str] = Field(default=None)
    stripe_transfer_id: Optional[str] = Field(default=None)
    razorpay_order_id: Optional[str] = Field(default=None)
    razorpay_payment_id: Optional[str] = Field(default=None)
    razorpay_transfer_id: Optional[str] = Field(default=None)
    status: str = Field(default="pending")  # pending -> funded -> released | refunded | disputed
    created_at: datetime = Field(default_factory=datetime.utcnow)
    funded_at: Optional[datetime] = Field(default=None)
    released_at: Optional[datetime] = Field(default=None)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)
    migrate_schema()

def migrate_schema():
    """SQLModel's create_all only creates NEW tables — it never adds columns to
    tables that already exist. Since this app has been redeployed many times with
    an evolving schema, we need to explicitly patch in any columns added after a
    table's first creation. Each statement is wrapped individually: if the column
    already exists (fresh install, or already migrated), the error is swallowed
    and we move on — this makes the function safe to run on every single startup."""
    migrations = [
        "ALTER TABLE useraccount ADD COLUMN accepted_terms BOOLEAN DEFAULT FALSE",
        "ALTER TABLE useraccount ADD COLUMN accepted_terms_at TIMESTAMP",
        "ALTER TABLE marketplacelisting ADD COLUMN budget_min FLOAT DEFAULT 0",
        "ALTER TABLE marketplacelisting ADD COLUMN budget_max FLOAT DEFAULT 0",
        "ALTER TABLE marketplacelisting ADD COLUMN audience_size INTEGER DEFAULT 0",
        "ALTER TABLE marketplacelisting ADD COLUMN engagement_rate FLOAT DEFAULT 0",
        "ALTER TABLE marketplacelisting ADD COLUMN niche_tags VARCHAR DEFAULT ''",
        "ALTER TABLE useraccount ADD COLUMN stripe_connect_account_id VARCHAR",
        "ALTER TABLE useraccount ADD COLUMN stripe_connect_onboarded BOOLEAN DEFAULT FALSE",
        "ALTER TABLE useraccount ADD COLUMN payout_account_linked_at TIMESTAMP",
        "ALTER TABLE useraccount ADD COLUMN razorpay_account_id VARCHAR",
        "ALTER TABLE useraccount ADD COLUMN razorpay_account_active BOOLEAN DEFAULT FALSE",
        "ALTER TABLE escrowpayment ADD COLUMN razorpay_order_id VARCHAR",
        "ALTER TABLE escrowpayment ADD COLUMN razorpay_payment_id VARCHAR",
        "ALTER TABLE escrowpayment ADD COLUMN razorpay_transfer_id VARCHAR",
        "ALTER TABLE useraccount ADD COLUMN phone_number VARCHAR DEFAULT ''",
        "ALTER TABLE useraccount ADD COLUMN industry VARCHAR DEFAULT ''",
        "ALTER TABLE useraccount ADD COLUMN otp_purpose VARCHAR",
        "ALTER TABLE useraccount ADD COLUMN is_subscribed BOOLEAN DEFAULT FALSE",
        "ALTER TABLE useraccount ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
        "ALTER TABLE useraccount ADD COLUMN subscription_id VARCHAR",
        "ALTER TABLE useraccount ADD COLUMN subscription_expires_at TIMESTAMP",
        # Drop billing/tax/payout data — this belongs exclusively to Razorpay's regulated
        # KYC flow, never duplicated in SOCIA's own database. Existing rows lose this data
        # permanently on migration, which is the intended outcome, not an oversight.
        "ALTER TABLE useraccount DROP COLUMN IF EXISTS billing_address",
        "ALTER TABLE useraccount DROP COLUMN IF EXISTS tax_id",
        "ALTER TABLE useraccount DROP COLUMN IF EXISTS payout_details",
        "ALTER TABLE marketplacelisting ADD COLUMN is_anonymous BOOLEAN DEFAULT FALSE",
        "ALTER TABLE marketplacelisting ADD COLUMN location VARCHAR DEFAULT ''",
        "ALTER TABLE marketplacelisting ADD COLUMN platforms VARCHAR DEFAULT ''",
        "ALTER TABLE marketplacelisting ADD COLUMN content_languages VARCHAR DEFAULT ''",
        "ALTER TABLE marketplacelisting ADD COLUMN interests VARCHAR DEFAULT ''",
        "ALTER TABLE marketplacelisting ADD COLUMN hide_location_publicly BOOLEAN DEFAULT FALSE",
        "ALTER TABLE marketplacelisting ADD COLUMN excluded_niches VARCHAR DEFAULT ''",
        "ALTER TABLE marketplacelisting ADD COLUMN requires_local_presence BOOLEAN DEFAULT FALSE",
        "ALTER TABLE marketplacelisting ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
    ]
    with engine.connect() as conn:
        for stmt in migrations:
            try:
                conn.execute(text(stmt))
                conn.commit()
                print(f"[MIGRATION] Applied: {stmt}")
            except Exception as e:
                conn.rollback()
                # Expected on every startup after the first successful run — column already exists
                print(f"[MIGRATION] Skipped (likely already applied): {stmt.split('ADD COLUMN')[1].strip().split(' ')[0] if 'ADD COLUMN' in stmt else stmt}")

app = FastAPI(title="SOCIA Protocol Institutional Backend", version="1.4.0")

@app.get("/api/config-status")
def config_status():
    """Safe to hit without auth — reveals only whether each critical config value is
    properly set as a fixed value, never the actual secret content. Use this to
    instantly diagnose 'invalid token' type issues instead of digging through logs."""
    return {
        "jwt_secret_is_fixed": JWT_SECRET_IS_FIXED,
        "jwt_secret_warning": None if JWT_SECRET_IS_FIXED else "JWT_SECRET is NOT set — using a random secret that changes on every restart, invalidating all logins each time. Set JWT_SECRET in Railway Variables.",
        "razorpay_configured": bool(RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET),
        "razorpay_webhook_configured": bool(RAZORPAY_WEBHOOK_SECRET),
        "razorpay_subscription_webhook_configured": bool(RAZORPAY_SUBSCRIPTION_WEBHOOK_SECRET),
        "gmail_configured": bool(GMAIL_APP_PASSWORD),
        "admin_secret_configured": bool(ADMIN_SECRET),
    }

ALLOWED_ORIGINS = [
    "https://contactsocia.com",
    "https://www.contactsocia.com",
]
# Add your Railway-provided domain too, useful during transition/testing:
railway_domain = os.getenv("RAILWAY_PUBLIC_DOMAIN")
if railway_domain:
    ALLOWED_ORIGINS.append(f"https://{railway_domain}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

def get_session():
    with Session(engine) as session:
        yield session

def get_current_user_optional(authorization: Optional[str] = Header(None), session: Session = Depends(get_session)) -> Optional[UserAccount]:
    """Like get_current_user, but returns None instead of raising — lets marketplace
    browsing stay public while still personalizing match scores for logged-in users."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    try:
        token = authorization.split(" ", 1)[1]
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email = payload.get("sub")
    except jwt.InvalidTokenError:
        return None
    return session.exec(select(UserAccount).where(UserAccount.email == email)).first()

# --- MATCHING ALGORITHM v2 (Sept 2026 rewrite) ---
#
# v1 (kept here only in the CHANGELOG below for context) produced a 0-100 score by summing
# fixed point buckets out of a flat 100, and handed out "neutral credit" whenever data was
# missing. Rebuilt from scratch with four fixes, each one found by reading the actual data
# model and comparing against how real creator/sponsor marketplaces (AspireIQ/Aspire, Grin,
# CreatorIQ-style tools) structure matching:
#
#   1. BLANK-DATA LOOPHOLE: v1 gave a flat +8/100 "neutral credit" whenever budget data was
#      missing on either side — meaning an empty profile could score competitively with a
#      fully-filled-in one. v2 normalizes by EVALUABLE weight: a factor neither side can
#      supply data for is excluded from both the numerator and denominator, so the score
#      always reflects 100% of what was actually comparable, never inflated by absence.
#
#   2. SPONSOR AUDIENCE/ENGAGEMENT BUG: v1 compared candidate.audience_size directly against
#      viewer_listing.audience_size — but a SPONSOR listing has no meaningful "audience size"
#      of its own. In practice this meant sponsors left it at 0, silently zeroing out 24 of
#      v1's 100 points (audience + engagement) for the single most common browsing direction
#      on the platform (sponsor -> creator). v2 treats a sponsor's audience_size/engagement_rate
#      as the MINIMUM they require from a creator, and scores the creator against that bar.
#
#   3. NO USE OF SOCIA'S OWN TRUST DATA: the whole point of an escrow platform is a track
#      record, yet v1 never touched EscrowPayment/Pitch history. v2 adds a reliability signal
#      (completed vs. disputed/refunded escrow deals, pitch response rate) — a signal no
#      generic influencer-discovery tool can offer, because they don't run the escrow.
#
#   4. BRITTLE LOCATION MATCH: v1 required an exact lowercased string match ("Mumbai" !=
#      "Mumbai, India"), and weighted location for every single pair even though most creator
#      deals are fully remote. v2 normalizes to just the first comma-segment, and only counts
#      location at all when a sponsor has explicitly flagged the campaign as needing local
#      presence — otherwise it's excluded from scoring entirely rather than penalizing a
#      perfectly good remote-first match.
#
# Also added: brand-safety / category-conflict checking (sponsor-declared excluded_niches),
# a small verified-listing trust bonus (now meaningful now that "verified" isn't auto-True —
# see MarketplaceListing.verified), and symmetric Jaccard overlap (intersection/union) in
# place of v1's viewer-only-denominator overlap for niches/platforms/languages.

WEIGHTS = {
    "niche": 22,
    "budget": 20,
    "audience_engagement": 15,
    "reliability": 15,
    "platforms": 8,
    "brand_safety": 8,
    "languages": 5,
    "location": 4,
    "verified": 3,
}  # sums to 100 — see compute_match_breakdown for which factors apply to a given pair

REASON_LABELS = {
    "niche": "Strong category / niche overlap",
    "budget": "Budget and rate expectations align",
    "audience_engagement": "Meets audience & engagement requirements",
    "reliability": "Proven track record on SOCIA",
    "platforms": "Active on the same platforms",
    "brand_safety": "No brand-safety conflicts",
    "languages": "Shares content language(s)",
    "location": "Located in the required market",
    "verified": "SOCIA-verified listing",
}

def _tagset(csv: str) -> set:
    return set(t.strip().lower() for t in (csv or "").split(",") if t.strip())

def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    union = a | b
    return len(a & b) / len(union) if union else 0.0

def _normalize_location(loc: str) -> str:
    """'Mumbai, India' / 'mumbai' / 'Mumbai, Maharashtra' all normalize to 'mumbai', so
    formatting differences between two honestly-matching locations don't zero out the
    location factor the way an exact string match did in v1."""
    if not loc or not loc.strip():
        return ""
    return loc.strip().lower().split(",")[0].strip()

def _sponsor_and_creator(a: "MarketplaceListing", b: "MarketplaceListing"):
    """Returns (sponsor_listing, creator_listing) for a valid sponsor/influencer pair,
    or (None, None) if the pair isn't one of each (e.g. admin comparing two sponsors) —
    callers must handle the None case rather than assume every pair is sponsor+creator."""
    if a.role == "sponsor" and b.role == "influencer":
        return a, b
    if a.role == "influencer" and b.role == "sponsor":
        return b, a
    return None, None

def get_reliability_signals(session: Session, emails: set) -> dict:
    """Batch-computes each email's real track record on SOCIA — completed vs. disputed/
    refunded escrow deals, plus pitch response rate. Batched as two queries covering every
    listing being scored on the current request, instead of a query per candidate."""
    emails = [e for e in emails if e]
    if not emails:
        return {}
    signals = {e: {"completed": 0, "disputed": 0, "refunded": 0, "pitches_received": 0, "pitches_answered": 0} for e in emails}

    payments = session.exec(
        select(EscrowPayment).where(or_(EscrowPayment.sponsor_email.in_(emails), EscrowPayment.influencer_email.in_(emails)))
    ).all()
    for p in payments:
        for email in (p.sponsor_email, p.influencer_email):
            sig = signals.get(email)
            if sig is None:
                continue
            if p.status == "released":
                sig["completed"] += 1
            elif p.status == "disputed":
                sig["disputed"] += 1
            elif p.status == "refunded":
                sig["refunded"] += 1

    pitches = session.exec(select(Pitch).where(Pitch.recipient_email.in_(emails))).all()
    for pt in pitches:
        sig = signals.get(pt.recipient_email)
        if sig is None:
            continue
        sig["pitches_received"] += 1
        if pt.status != "Pending":
            sig["pitches_answered"] += 1

    return signals

def _reliability_score(signal: Optional[dict]) -> float:
    """Returns the FRACTION (0.0-1.0) of the reliability weight earned. A brand-new account
    with no history yet gets a neutral 0.65 — being new is never treated as a strike, but a
    real track record (good or bad) moves the number from there."""
    if not signal:
        return 0.65

    completed, disputed, refunded = signal["completed"], signal["disputed"], signal["refunded"]
    total_deals = completed + disputed + refunded
    if total_deals == 0:
        deal_component = 0.65
    else:
        clean_rate = completed / total_deals
        volume_bonus = min(total_deals / 10, 1.0) * 0.15  # small credit for a longer proven history
        deal_component = min(clean_rate * 0.85 + volume_bonus, 1.0)

    received, answered = signal["pitches_received"], signal["pitches_answered"]
    response_component = 0.65 if received == 0 else answered / received

    return round(deal_component * 0.75 + response_component * 0.25, 3)

def compute_match_breakdown(
    viewer_listing: Optional["MarketplaceListing"],
    candidate: "MarketplaceListing",
    reliability_signal: Optional[dict] = None,
) -> Optional[dict]:
    """Full transparent scoring breakdown: which factors applied, how many points each
    earned out of its weight, the final 0-100 score, and up to 3 plain-English reasons for
    the match. compute_match_score() below is a thin wrapper around this for callers that
    only need the number — this is the single source of truth for the algorithm."""
    if viewer_listing is None:
        return None

    factors = {}
    earned = 0.0
    applicable_weight = 0.0
    sponsor, creator = _sponsor_and_creator(viewer_listing, candidate)

    # --- Niche / category overlap ---
    viewer_tags, candidate_tags = _tagset(viewer_listing.niche_tags), _tagset(candidate.niche_tags)
    if viewer_tags and candidate_tags:
        w = WEIGHTS["niche"]; applicable_weight += w
        pts = _jaccard(viewer_tags, candidate_tags) * w
        earned += pts
        factors["niche"] = {"weight": w, "earned": pts, "applicable": True}
    elif viewer_listing.industry.strip() and candidate.industry.strip():
        w = WEIGHTS["niche"]; applicable_weight += w
        pts = w * 0.6 if viewer_listing.industry.strip().lower() == candidate.industry.strip().lower() else 0.0
        earned += pts
        factors["niche"] = {"weight": w, "earned": pts, "applicable": True}
    else:
        factors["niche"] = {"weight": WEIGHTS["niche"], "earned": 0.0, "applicable": False}

    # --- Budget / rate range overlap (true intersection-over-union) ---
    v_min, v_max = viewer_listing.budget_min, viewer_listing.budget_max
    c_min, c_max = candidate.budget_min, candidate.budget_max
    if v_max > 0 and c_max > 0:
        w = WEIGHTS["budget"]; applicable_weight += w
        overlap_low, overlap_high = max(v_min, c_min), min(v_max, c_max)
        if overlap_high >= overlap_low:
            union_span = max(v_max, c_max) - min(v_min, c_min)
            iou = (overlap_high - overlap_low) / union_span if union_span > 0 else 1.0
        else:
            iou = 0.0
        pts = iou * w
        earned += pts
        factors["budget"] = {"weight": w, "earned": pts, "applicable": True}
    else:
        factors["budget"] = {"weight": WEIGHTS["budget"], "earned": 0.0, "applicable": False}

    # --- Audience / engagement: sponsor's stated MINIMUM vs. the creator's real stats ---
    w = WEIGHTS["audience_engagement"]
    if sponsor and creator:
        applicable_weight += w
        sub_total, sub_count = 0.0, 0
        if sponsor.audience_size > 0:
            sub_count += 1
            sub_total += 1.0 if creator.audience_size >= sponsor.audience_size else (creator.audience_size / sponsor.audience_size if sponsor.audience_size else 0)
        if sponsor.engagement_rate > 0:
            sub_count += 1
            sub_total += 1.0 if creator.engagement_rate >= sponsor.engagement_rate else (creator.engagement_rate / sponsor.engagement_rate if sponsor.engagement_rate else 0)
        fraction = (sub_total / sub_count) if sub_count > 0 else 1.0  # sponsor stated no minimum at all -> trivially satisfied
        pts = fraction * w
        earned += pts
        factors["audience_engagement"] = {"weight": w, "earned": pts, "applicable": True}
    else:
        factors["audience_engagement"] = {"weight": w, "earned": 0.0, "applicable": False}

    # --- Reliability: SOCIA's own escrow/pitch track record ---
    w = WEIGHTS["reliability"]; applicable_weight += w
    pts = _reliability_score(reliability_signal) * w
    earned += pts
    factors["reliability"] = {"weight": w, "earned": pts, "applicable": True}

    # --- Platform overlap ---
    viewer_platforms, candidate_platforms = _tagset(viewer_listing.platforms), _tagset(candidate.platforms)
    if viewer_platforms and candidate_platforms:
        w = WEIGHTS["platforms"]; applicable_weight += w
        pts = _jaccard(viewer_platforms, candidate_platforms) * w
        earned += pts
        factors["platforms"] = {"weight": w, "earned": pts, "applicable": True}
    else:
        factors["platforms"] = {"weight": WEIGHTS["platforms"], "earned": 0.0, "applicable": False}

    # --- Brand safety / category-conflict check (always evaluated when it's a sponsor/creator pair) ---
    w = WEIGHTS["brand_safety"]
    if sponsor and creator:
        applicable_weight += w
        excluded = _tagset(sponsor.excluded_niches)
        conflict = bool(excluded & _tagset(creator.niche_tags))
        pts = 0.0 if conflict else w
        earned += pts
        factors["brand_safety"] = {"weight": w, "earned": pts, "applicable": True, "conflict": conflict}
    else:
        factors["brand_safety"] = {"weight": w, "earned": 0.0, "applicable": False}

    # --- Content language overlap ---
    viewer_langs, candidate_langs = _tagset(viewer_listing.content_languages), _tagset(candidate.content_languages)
    if viewer_langs and candidate_langs:
        w = WEIGHTS["languages"]; applicable_weight += w
        pts = _jaccard(viewer_langs, candidate_langs) * w
        earned += pts
        factors["languages"] = {"weight": w, "earned": pts, "applicable": True}
    else:
        factors["languages"] = {"weight": WEIGHTS["languages"], "earned": 0.0, "applicable": False}

    # --- Location: only counts when the sponsor has flagged this campaign as needing local presence ---
    w = WEIGHTS["location"]
    if sponsor and sponsor.requires_local_presence:
        applicable_weight += w
        v_loc, c_loc = _normalize_location(viewer_listing.location), _normalize_location(candidate.location)
        pts = w if (v_loc and c_loc and v_loc == c_loc) else 0.0
        earned += pts
        factors["location"] = {"weight": w, "earned": pts, "applicable": True}
    else:
        factors["location"] = {"weight": w, "earned": 0.0, "applicable": False}

    # --- Verified-listing trust bonus (meaningful now that verified isn't auto-True) ---
    w = WEIGHTS["verified"]; applicable_weight += w
    pts = w if candidate.verified else 0.0
    earned += pts
    factors["verified"] = {"weight": w, "earned": pts, "applicable": True}

    # --- Interests: pure bonus on top, exactly as v1 — never required, never subtracted ---
    viewer_interests, candidate_interests = _tagset(viewer_listing.interests), _tagset(candidate.interests)
    interest_bonus = _jaccard(viewer_interests, candidate_interests) * 5 if (viewer_interests and candidate_interests) else 0.0

    # --- Coverage / confidence adjustment ---
    # A raw earned/applicable_weight ratio is only as trustworthy as how much of the total
    # 100-point weight was actually evaluable. Two nearly-blank listings can otherwise land
    # on a deceptively high score just because the FEW factors that stayed applicable (e.g.
    # "sponsor stated no minimum" or "no brand-safety exclusions declared") are neutral-to-
    # positive by construction — that's not a real match, it's an absence of data. Blend the
    # raw score toward a neutral midpoint in proportion to how little was actually covered,
    # so a low-coverage score can never masquerade as a high-confidence one.
    total_possible = sum(WEIGHTS.values())  # == 100 by construction
    coverage = (applicable_weight / total_possible) if total_possible else 0.0
    raw_base = (earned / applicable_weight) * 100 if applicable_weight > 0 else 0.0
    NEUTRAL_MIDPOINT = 50
    confidence_adjusted = raw_base * coverage + NEUTRAL_MIDPOINT * (1 - coverage)
    score = round(min(confidence_adjusted + interest_bonus, 100))

    reasons = [
        REASON_LABELS[name] for name, f in sorted(factors.items(), key=lambda kv: -kv[1]["weight"])
        if f["applicable"] and f["weight"] > 0 and (f["earned"] / f["weight"]) >= 0.7
    ][:3]

    return {
        "score": score,
        "factors": factors,
        "reasons": reasons,
        "interest_bonus": interest_bonus,
        "applicable_weight": applicable_weight,
        "coverage": round(coverage, 3),
        "lowConfidence": coverage < 0.5,
    }

def compute_match_score(
    viewer_listing: Optional["MarketplaceListing"],
    candidate: "MarketplaceListing",
    reliability_signal: Optional[dict] = None,
) -> Optional[int]:
    result = compute_match_breakdown(viewer_listing, candidate, reliability_signal)
    return result["score"] if result else None

# --- HELPER: SECURE PASSWORD HASHING (PBKDF2-HMAC-SHA256, stdlib only) ---
def hash_password(plain_password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, 200_000)
    return f"{binascii.hexlify(salt).decode()}${binascii.hexlify(dk).decode()}"

def verify_password(plain_password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        salt = binascii.unhexlify(salt_hex)
        expected = binascii.unhexlify(hash_hex)
        dk = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, 200_000)
        return hmac.compare_digest(dk, expected)
    except (ValueError, binascii.Error):
        return False  # Handles old plaintext passwords from before this fix — they'll safely fail verification

# --- HELPER: JWT ISSUANCE & VERIFICATION (replaces the old forgeable f-string token) ---
def create_access_token(email: str) -> str:
    payload = {
        "sub": email,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_current_user(authorization: Optional[str] = Header(None), session: Session = Depends(get_session)) -> UserAccount:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header.")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email = payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token.")

    user = session.exec(select(UserAccount).where(UserAccount.email == email)).first()
    if not user:
        raise HTTPException(status_code=401, detail="Account associated with this token no longer exists.")
    return user

# --- HELPER: SIMPLE IN-MEMORY RATE LIMITING (per-process; resets on restart) ---
_rate_limit_buckets = {}

def enforce_rate_limit(key: str, max_attempts: int, window_seconds: int):
    now = time.time()
    bucket = _rate_limit_buckets.get(key, [])
    bucket = [t for t in bucket if now - t < window_seconds]
    if len(bucket) >= max_attempts:
        raise HTTPException(status_code=429, detail="Too many attempts. Please wait before trying again.")
    bucket.append(now)
    _rate_limit_buckets[key] = bucket

# --- HELPER: GOOGLE WORKSPACE SMTP EMAIL DISPATCHER (sociacreator@contactsocia.com) ---
def send_otp_email(recipient_email: str, otp_code: str):
    # ALWAYS print to logs first so you have the code instantly even if Google fails
    print(f"\n==========================================")
    print(f"[OTP DEBUG BACKUP] Code for {recipient_email}: {otp_code}")
    print(f"==========================================\n")

    app_password = (GMAIL_APP_PASSWORD or "").strip()
    if not app_password:
        print("[EMAIL ERROR] GMAIL_APP_PASSWORD is not set or empty. Skipping send, OTP only available in logs above.")
        return

    html_body = f"""
    <div style="font-family: Arial, sans-serif; padding: 20px; background: #0f172a; color: #f8fafc; border-radius: 8px;">
        <h2 style="color: #38bdf8;">SOCIA Protocol Authentication</h2>
        <p>Your secure verification code is:</p>
        <div style="font-size: 32px; font-weight: bold; background: #1e293b; color: #38bdf8; padding: 12px 24px; display: inline-block; border-radius: 6px; letter-spacing: 4px;">{otp_code}</div>
        <p style="margin-top: 20px; font-size: 12px; color: #94a3b8;">If you did not request this verification, please ignore this transmission.</p>
    </div>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your SOCIA Protocol Verification Code"
    msg["From"] = f"SOCIA Protocol <{GMAIL_SENDER}>"
    msg["To"] = recipient_email
    msg.attach(MIMEText(html_body, "html"))

    try:
        # Connected with a strict 5-second timeout so it never hangs server workers
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as server:
            server.starttls()
            server.login(GMAIL_SENDER, app_password)
            server.sendmail(GMAIL_SENDER, [recipient_email], msg.as_string())
        print(f"[SMTP SUCCESS] OTP dispatched via Google Workspace to {recipient_email}")
    except Exception as e:
        print(f"[SMTP ERROR] Could not send via Google Workspace: {str(e)}. OTP still available in logs above.")

# --- HELPER: GENERIC NOTIFICATION EMAIL (new pitches, ticket updates, etc.) ---
def send_notification_email(recipient_email: str, subject: str, body_text: str):
    app_password = (GMAIL_APP_PASSWORD or "").strip()
    if not app_password:
        print(f"[EMAIL ERROR] GMAIL_APP_PASSWORD not set. Skipped notification to {recipient_email}: {subject}")
        return

    html_body = f"""
    <div style="font-family: Arial, sans-serif; padding: 20px; background: #0f172a; color: #f8fafc; border-radius: 8px;">
        <h2 style="color: #38bdf8;">{subject}</h2>
        <p style="white-space: pre-line;">{body_text}</p>
        <p style="margin-top: 20px; font-size: 12px; color: #94a3b8;">SOCIA Protocol — you're receiving this because of activity on your account.</p>
    </div>
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"SOCIA Protocol <{GMAIL_SENDER}>"
    msg["To"] = recipient_email
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as server:
            server.starttls()
            server.login(GMAIL_SENDER, app_password)
            server.sendmail(GMAIL_SENDER, [recipient_email], msg.as_string())
        print(f"[SMTP SUCCESS] Notification '{subject}' sent to {recipient_email}")
    except Exception as e:
        print(f"[SMTP ERROR] Notification failed for {recipient_email}: {str(e)}")

# --- HELPER: AUDIT LOGGING ---
def log_audit(session: Session, email: str, action: str, detail: str = ""):
    entry = AuditLog(email=email, action=action, detail=detail)
    session.add(entry)
    session.commit()

# --- SCHEMAS ---
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    role: str
    display_name: str
    handle: str
    phone_number: str
    industry: str
    accepted_terms: bool

class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp_code: str

class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str

class UserSettingsUpdate(BaseModel):
    new_email: Optional[EmailStr] = None
    display_name: Optional[str] = None
    handle: Optional[str] = None
    company_name: Optional[str] = None
    phone_number: Optional[str] = None
    industry: Optional[str] = None
    notification_preferences: Optional[str] = None

class ListingCreate(BaseModel):
    name: str
    role: str
    industry: str
    rates: str
    stats: str
    bio: str
    pre_conditions: List[str]
    budget_min: float
    budget_max: float
    audience_size: int
    engagement_rate: float
    niche_tags: List[str]
    is_anonymous: bool = False
    location: str
    platforms: List[str]
    content_languages: List[str]
    interests: List[str] = []
    hide_location_publicly: bool = False
    excluded_niches: List[str] = []
    requires_local_presence: bool = False

class DealSimulationRequest(BaseModel):
    sponsor_contact: str
    influencer_name: str
    amount: float
    conditions: List[str]

class PitchCreate(BaseModel):
    recipient_listing_id: int
    amount: float
    brief: str

class PitchRespond(BaseModel):
    action: str  # 'accept' or 'reject'

class NegotiationMessageCreate(BaseModel):
    text: str

class NegotiationConditionCreate(BaseModel):
    text: str

class NegotiationLockUpdate(BaseModel):
    locked: bool

class SupportTicketCreate(BaseModel):
    subject: str
    message: str

# --- ENDPOINTS ---
@app.post("/auth/register")
def register_user(payload: RegisterRequest, background_tasks: BackgroundTasks, session: Session = Depends(get_session)):
    enforce_rate_limit(f"register:{payload.email}", max_attempts=5, window_seconds=3600)
    print(f"[DEBUG] Registration requested for: {payload.email}")
    
    existing = session.exec(select(UserAccount).where(UserAccount.email == payload.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Account with this email already registered.")

    if not payload.accepted_terms:
        raise HTTPException(status_code=400, detail="You must accept the Terms of Service and Privacy Policy to register.")

    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    if not payload.phone_number or len(payload.phone_number.strip()) < 8:
        raise HTTPException(status_code=400, detail="A valid phone number is required.")
    if not payload.industry or not payload.industry.strip():
        raise HTTPException(status_code=400, detail="Industry/category is required.")
    if payload.role not in ("sponsor", "influencer"):
        raise HTTPException(status_code=400, detail="Role must be 'sponsor' or 'influencer'.")

    generated_otp = str(random.randint(100000, 999999))
    
    user = UserAccount(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        display_name=payload.display_name,
        handle=payload.handle,
        phone_number=payload.phone_number.strip(),
        industry=payload.industry.strip(),
        is_verified=False,
        otp_code=generated_otp,
        otp_purpose="register",
        accepted_terms=True,
        accepted_terms_at=datetime.utcnow()
    )
    
    try:
        session.add(user)
        session.commit()
        session.refresh(user)
        print(f"[DEBUG] Database commit successful for user ID: {user.id}")
    except Exception as db_err:
        session.rollback()
        print(f"[DB ERROR] Commit failed: {str(db_err)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(db_err)}")

    # Queue email task after successful database commit
    background_tasks.add_task(send_otp_email, payload.email, generated_otp)
    
    return {
        "status": "pending_verification",
        "message": f"Verification code successfully initiated for {payload.email}. Check console/inbox."
    }

@app.post("/auth/verify-otp")
def verify_otp(payload: VerifyOTPRequest, session: Session = Depends(get_session)):
    enforce_rate_limit(f"verify_otp:{payload.email}", max_attempts=8, window_seconds=600)
    user = session.exec(select(UserAccount).where(UserAccount.email == payload.email)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")

    if user.otp_purpose != "register" or user.otp_code != payload.otp_code:
        raise HTTPException(status_code=400, detail="Invalid OTP verification code.")
    
    user.is_verified = True
    user.otp_code = None
    user.otp_purpose = None
    session.add(user)
    session.commit()
    log_audit(session, user.email, "account_verified")
    
    return {"status": "success", "message": "Account successfully verified and activated in database."}

class ResendOTPRequest(BaseModel):
    email: EmailStr
    purpose: str  # 'register' or 'login_2fa'

@app.post("/auth/resend-otp")
def resend_otp(payload: ResendOTPRequest, background_tasks: BackgroundTasks, session: Session = Depends(get_session)):
    enforce_rate_limit(f"resend_otp:{payload.email}", max_attempts=5, window_seconds=600)
    user = session.exec(select(UserAccount).where(UserAccount.email == payload.email)).first()
    # Generic response regardless of whether the account exists — avoids leaking registered emails
    if user and payload.purpose in ("register", "login_2fa"):
        new_otp = str(random.randint(100000, 999999))
        user.otp_code = new_otp
        user.otp_purpose = payload.purpose
        session.add(user)
        session.commit()
        background_tasks.add_task(send_otp_email, payload.email, new_otp)
    return {"status": "success", "message": "If an account exists, a new code has been sent."}

@app.post("/auth/token")
def login_step1_password(form_data: OAuth2PasswordRequestForm = Depends(), background_tasks: BackgroundTasks = None, session: Session = Depends(get_session)):
    """Step 1 of login: verifies email+password. Does NOT return an access token —
    instead triggers a 2FA OTP to the user's email. The token is only issued after
    that code is verified via /auth/verify-login-otp."""
    enforce_rate_limit(f"login:{form_data.username}", max_attempts=8, window_seconds=600)
    user = session.exec(select(UserAccount).where(UserAccount.email == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        log_audit(session, form_data.username, "login_failed", "Incorrect credentials")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account pending email verification. Please complete OTP verification first."
        )

    login_otp = str(random.randint(100000, 999999))
    user.otp_code = login_otp
    user.otp_purpose = "login_2fa"
    session.add(user)
    session.commit()
    log_audit(session, user.email, "login_password_verified_2fa_sent")

    background_tasks.add_task(send_otp_email, user.email, login_otp)
    return {"status": "otp_required", "message": f"Password verified. A 2FA code was sent to {user.email}."}

class VerifyLoginOTPRequest(BaseModel):
    email: EmailStr
    otp_code: str

@app.post("/auth/verify-login-otp")
def login_step2_verify_otp(payload: VerifyLoginOTPRequest, session: Session = Depends(get_session)):
    """Step 2 of login: verifies the 2FA code and issues the real access token."""
    enforce_rate_limit(f"login_2fa:{payload.email}", max_attempts=8, window_seconds=600)
    user = session.exec(select(UserAccount).where(UserAccount.email == payload.email)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")

    if user.otp_purpose != "login_2fa" or user.otp_code != payload.otp_code:
        log_audit(session, payload.email, "login_2fa_failed")
        raise HTTPException(status_code=400, detail="Invalid or expired 2FA code.")

    user.otp_code = None
    user.otp_purpose = None
    session.add(user)
    session.commit()
    log_audit(session, user.email, "login_success")

    return {
        "access_token": create_access_token(user.email),
        "token_type": "bearer",
        "email": user.email,
        "role": user.role,
        "display_name": user.display_name,
        "handle": user.handle
    }

@app.post("/auth/change-password")
def change_password(payload: PasswordChangeRequest, session: Session = Depends(get_session), current_user: UserAccount = Depends(get_current_user)):
    enforce_rate_limit(f"changepw:{current_user.email}", max_attempts=5, window_seconds=600)
    if not verify_password(payload.old_password, current_user.hashed_password):
        log_audit(session, current_user.email, "password_change_failed", "Incorrect existing password")
        raise HTTPException(status_code=400, detail="Incorrect existing password.")

    current_user.hashed_password = hash_password(payload.new_password)
    session.add(current_user)
    session.commit()
    log_audit(session, current_user.email, "password_changed")

    return {"status": "success", "message": "Password successfully updated."}

@app.get("/api/account/settings")
def get_account_settings(current_user: UserAccount = Depends(get_current_user)):
    user = current_user
    return {
        "email": user.email,
        "role": user.role,
        "display_name": user.display_name,
        "handle": user.handle,
        "is_verified": user.is_verified,
        "avatar_url": user.avatar_url,
        "is_subscribed": user.is_subscribed,
        "private_details": {
            "company_name": user.company_name,
            "phone_number": user.phone_number,
            "industry": user.industry,
            "notification_preferences": user.notification_preferences
        }
    }

@app.put("/api/account/settings")
def update_account_settings(payload: UserSettingsUpdate, session: Session = Depends(get_session), current_user: UserAccount = Depends(get_current_user)):
    user = current_user

    if payload.new_email is not None and payload.new_email != user.email:
        existing_email = session.exec(select(UserAccount).where(UserAccount.email == payload.new_email)).first()
        if existing_email:
            raise HTTPException(status_code=400, detail="Email address already in use by another account.")
        user.email = payload.new_email

    if payload.display_name is not None:
        user.display_name = payload.display_name
    if payload.handle is not None:
        user.handle = payload.handle
    if payload.company_name is not None:
        user.company_name = payload.company_name
    if payload.phone_number is not None:
        user.phone_number = payload.phone_number
    if payload.industry is not None:
        user.industry = payload.industry
    if payload.notification_preferences is not None:
        user.notification_preferences = payload.notification_preferences
        
    session.add(user)
    session.commit()
    session.refresh(user)
    log_audit(session, user.email, "settings_updated")
    
    return {"status": "success", "message": "Private account settings updated successfully."}

ALLOWED_AVATAR_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}
ALLOWED_AVATAR_CONTENT_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
MAX_AVATAR_SIZE_BYTES = 5 * 1024 * 1024  # 5MB

@app.post("/api/account/upload-avatar")
async def upload_avatar(file: UploadFile = File(...), session: Session = Depends(get_session), current_user: UserAccount = Depends(get_current_user)):
    user = current_user
    enforce_rate_limit(f"avatar_upload:{current_user.email}", max_attempts=10, window_seconds=3600)

    file_extension = (file.filename.rsplit(".", 1)[-1] if "." in file.filename else "").lower()
    if file_extension not in ALLOWED_AVATAR_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported file type. Allowed: {', '.join(sorted(ALLOWED_AVATAR_EXTENSIONS))}")
    if file.content_type not in ALLOWED_AVATAR_CONTENT_TYPES:
        raise HTTPException(status_code=400, detail="File content type does not match an allowed image format.")

    content = await file.read()
    if len(content) > MAX_AVATAR_SIZE_BYTES:
        raise HTTPException(status_code=400, detail=f"File too large. Maximum size is {MAX_AVATAR_SIZE_BYTES // (1024*1024)}MB.")
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file.")

    upload_dir = "./uploads"
    os.makedirs(upload_dir, exist_ok=True)

    # Filename is fully server-generated — the original filename is never used in the
    # path, which also rules out any path-traversal attempt via a crafted filename.
    file_name = f"avatar_{user.id}_{random.randint(100000, 999999)}.{file_extension}"
    file_path = os.path.join(upload_dir, file_name)

    with open(file_path, "wb") as buffer:
        buffer.write(content)
        
    user.avatar_url = f"/{file_path}"
    session.add(user)
    session.commit()
    
    return {"status": "success", "avatar_url": user.avatar_url, "message": "File uploaded and avatar updated successfully."}

MAX_ACTIVE_LISTINGS_PER_USER = int(os.getenv("MAX_ACTIVE_LISTINGS_PER_USER", "5"))

def looks_like_spam_text(text: str, min_length: int = 15) -> bool:
    """Catches the cheapest, most common low-effort spam patterns — not a full
    content moderation system, just a floor against obvious junk."""
    stripped = text.strip()
    if len(stripped) < min_length:
        return True
    # Same character repeated (e.g. "aaaaaaaaaaaaaa")
    if len(set(stripped.replace(" ", ""))) <= 2 and len(stripped) > 5:
        return True
    return False

@app.post("/api/register")
def create_listing(payload: ListingCreate, session: Session = Depends(get_session), current_user: UserAccount = Depends(get_current_user)):
    enforce_rate_limit(f"create_listing:{current_user.email}", max_attempts=10, window_seconds=3600)

    existing_count = session.exec(select(MarketplaceListing).where(MarketplaceListing.contact == current_user.email)).all()
    if len(existing_count) >= MAX_ACTIVE_LISTINGS_PER_USER:
        raise HTTPException(status_code=400, detail=f"You've reached the maximum of {MAX_ACTIVE_LISTINGS_PER_USER} active listings. Remove one from My Listings before posting another.")

    if looks_like_spam_text(payload.bio, min_length=15):
        raise HTTPException(status_code=400, detail="Bio is too short or low-effort. Please provide a genuine description (15+ characters, not repeated characters).")
    if looks_like_spam_text(payload.name, min_length=2):
        raise HTTPException(status_code=400, detail="Listing name looks invalid. Please provide a real name.")

    if not payload.location.strip():
        raise HTTPException(status_code=400, detail="Location is required.")
    if not payload.platforms or not any(p.strip() for p in payload.platforms):
        raise HTTPException(status_code=400, detail="At least one platform is required.")
    if not payload.content_languages or not any(l.strip() for l in payload.content_languages):
        raise HTTPException(status_code=400, detail="At least one content language is required.")

    cond_str = ", ".join(payload.pre_conditions)
    niche_str = ", ".join(t.strip() for t in payload.niche_tags if t.strip())
    interests_str = ", ".join(t.strip() for t in payload.interests if t.strip())
    platforms_str = ", ".join(p.strip() for p in payload.platforms if p.strip())
    languages_str = ", ".join(l.strip() for l in payload.content_languages if l.strip())
    excluded_niches_str = ", ".join(t.strip() for t in payload.excluded_niches if t.strip())
    listing = MarketplaceListing(
        contact=current_user.email,
        name=payload.name,
        role=payload.role,
        industry=payload.industry,
        rates=payload.rates,
        stats=payload.stats,
        bio=payload.bio,
        pre_conditions_str=cond_str,
        budget_min=payload.budget_min,
        budget_max=payload.budget_max,
        audience_size=payload.audience_size,
        engagement_rate=payload.engagement_rate,
        niche_tags=niche_str,
        is_anonymous=payload.is_anonymous,
        location=payload.location.strip(),
        platforms=platforms_str,
        content_languages=languages_str,
        interests=interests_str,
        hide_location_publicly=payload.hide_location_publicly,
        excluded_niches=excluded_niches_str,
        requires_local_presence=payload.requires_local_presence,
        # verified intentionally left at the model default (False) — see MarketplaceListing.verified
    )
    session.add(listing)
    session.commit()
    return {"status": "success", "message": "Listing published successfully to protocol database. New listings start unverified until reviewed by SOCIA."}

@app.get("/api/marketplace")
def get_marketplace_listings(role: str, session: Session = Depends(get_session), current_user: Optional[UserAccount] = Depends(get_current_user_optional)):
    results = session.exec(select(MarketplaceListing).where(MarketplaceListing.role == role)).all()

    viewer_listing = None
    if current_user:
        viewer_listing = session.exec(
            select(MarketplaceListing).where(MarketplaceListing.contact == current_user.email)
        ).first()

    # Batch-fetch reliability signals for every candidate + the viewer in ONE pair of queries,
    # instead of re-querying EscrowPayment/Pitch per candidate (would be N+1 on this endpoint).
    all_emails = {r.contact for r in results}
    if viewer_listing:
        all_emails.add(viewer_listing.contact)
    reliability_map = get_reliability_signals(session, all_emails)

    formatted = []
    for r in results:
        breakdown = compute_match_breakdown(viewer_listing, r, reliability_map.get(r.contact))
        is_own_listing = current_user and r.contact == current_user.email
        masked = r.is_anonymous and not is_own_listing
        formatted.append({
            "id": r.id,
            "name": f"Anonymous {r.role.capitalize()} — {r.industry}" if masked else r.name,
            "contact": None if masked else r.contact,  # real email withheld from public browsing while anonymous
            "isAnonymous": r.is_anonymous,
            "role": r.role,
            "industry": r.industry,
            "rates": r.rates,
            "stats": r.stats,
            "bio": r.bio,
            "preConditions": [c.strip() for c in r.pre_conditions_str.split(",")],
            "match": breakdown["score"] if breakdown else None,  # None if viewer hasn't posted their own listing yet
            "matchReasons": breakdown["reasons"] if breakdown else [],
            "matchLowConfidence": breakdown["lowConfidence"] if breakdown else False,
            "budgetMin": r.budget_min,
            "budgetMax": r.budget_max,
            "audienceSize": r.audience_size,
            "engagementRate": r.engagement_rate,
            "nicheTags": [t.strip() for t in r.niche_tags.split(",") if t.strip()],
            "location": None if (r.hide_location_publicly and not is_own_listing) else (r.location or None),
            "interests": [t.strip() for t in r.interests.split(",") if t.strip()],
            "platforms": [t.strip() for t in r.platforms.split(",") if t.strip()],
            "contentLanguages": [t.strip() for t in r.content_languages.split(",") if t.strip()],
            "excludedNiches": [t.strip() for t in r.excluded_niches.split(",") if t.strip()],
            "requiresLocalPresence": r.requires_local_presence,
            "verified": r.verified
        })
    formatted.sort(key=lambda x: (x["match"] is None, -(x["match"] or 0)))
    return formatted

@app.get("/api/marketplace/mine")
def get_my_listings(current_user: UserAccount = Depends(get_current_user), session: Session = Depends(get_session)):
    results = session.exec(select(MarketplaceListing).where(MarketplaceListing.contact == current_user.email)).all()
    formatted = []
    for r in results:
        formatted.append({
            "id": r.id,
            "name": r.name,
            "contact": r.contact,
            "role": r.role,
            "industry": r.industry,
            "rates": r.rates,
            "stats": r.stats,
            "bio": r.bio,
            "preConditions": [c.strip() for c in r.pre_conditions_str.split(",")],
            "match": r.match_score,
            "verified": r.verified,
            "isAnonymous": r.is_anonymous,
            "budgetMin": r.budget_min,
            "budgetMax": r.budget_max,
            "audienceSize": r.audience_size,
            "engagementRate": r.engagement_rate,
            "nicheTags": [t.strip() for t in r.niche_tags.split(",") if t.strip()]
        })
    return formatted

@app.delete("/api/marketplace/{listing_id}")
def delete_my_listing(listing_id: int, session: Session = Depends(get_session), current_user: UserAccount = Depends(get_current_user)):
    listing = session.get(MarketplaceListing, listing_id)
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found.")
    if listing.contact != current_user.email:
        raise HTTPException(status_code=403, detail="You can only delete your own listings.")
    session.delete(listing)
    session.commit()
    log_audit(session, current_user.email, "listing_deleted", f"listing_id={listing_id}")
    return {"status": "success", "message": "Listing removed."}


@app.post("/api/deals/simulate")
def simulate_deal(payload: DealSimulationRequest, session: Session = Depends(get_session)):
    ref_id = f"REF-{random.randint(100000, 999999)}"
    deal = DealLedgerRecord(
        deal_ref=ref_id,
        counterparty=payload.influencer_name,
        amount=payload.amount,
        status="Secured Escrow"
    )
    session.add(deal)
    session.commit()
    return {"status": "success", "deal_ref": ref_id, "message": "Escrow proposal registered in database ledger."}

@app.get("/api/deals/history")
def get_deal_history(session: Session = Depends(get_session), current_user: UserAccount = Depends(get_current_user)):
    deals = session.exec(select(DealLedgerRecord)).all()
    return deals

# --- PITCH ENDPOINTS ---
@app.post("/api/pitches")
def create_pitch(payload: PitchCreate, background_tasks: BackgroundTasks, session: Session = Depends(get_session), current_user: UserAccount = Depends(get_current_user)):
    enforce_rate_limit(f"create_pitch:{current_user.email}", max_attempts=20, window_seconds=3600)

    target_listing = session.get(MarketplaceListing, payload.recipient_listing_id)
    if not target_listing:
        raise HTTPException(status_code=404, detail="Target listing not found.")
    if target_listing.contact == current_user.email:
        raise HTTPException(status_code=400, detail="You cannot pitch your own listing.")

    pitch = Pitch(
        sender_email=current_user.email,
        sender_name=current_user.display_name,
        sender_role=current_user.role,
        recipient_email=target_listing.contact,
        recipient_name=target_listing.name,
        amount=payload.amount,
        brief=payload.brief,
        status="Pending"
    )
    session.add(pitch)
    session.commit()
    session.refresh(pitch)
    log_audit(session, current_user.email, "pitch_sent", f"to_listing={payload.recipient_listing_id} amount={payload.amount}")
    background_tasks.add_task(
        send_notification_email,
        target_listing.contact,
        "New Pitch Received on SOCIA Protocol",
        f"{current_user.display_name} sent you a proposal for ${payload.amount:,.2f}.\n\n{payload.brief}\n\nLog in to your Incoming Pitches tab to accept or decline."
    )
    return {"status": "success", "message": "Pitch transmitted to counterparty.", "pitch_id": pitch.id}

@app.get("/api/pitches/incoming")
def get_incoming_pitches(current_user: UserAccount = Depends(get_current_user), session: Session = Depends(get_session)):
    pitches = session.exec(
        select(Pitch).where(Pitch.recipient_email == current_user.email, Pitch.status == "Pending")
    ).all()
    return pitches

@app.get("/api/pitches/sent")
def get_sent_pitches(current_user: UserAccount = Depends(get_current_user), session: Session = Depends(get_session)):
    pitches = session.exec(select(Pitch).where(Pitch.sender_email == current_user.email)).all()
    return pitches

@app.post("/api/pitches/{pitch_id}/respond")
def respond_to_pitch(pitch_id: int, payload: PitchRespond, session: Session = Depends(get_session), current_user: UserAccount = Depends(get_current_user)):
    pitch = session.get(Pitch, pitch_id)
    if not pitch:
        raise HTTPException(status_code=404, detail="Pitch not found.")
    if pitch.recipient_email != current_user.email:
        raise HTTPException(status_code=403, detail="Only the recipient may respond to this pitch.")
    if pitch.status != "Pending":
        raise HTTPException(status_code=400, detail="This pitch has already been responded to.")

    if payload.action == "accept":
        pitch.status = "Accepted"
        session.add(pitch)

        if pitch.sender_role == "sponsor":
            sponsor_email, sponsor_name = pitch.sender_email, pitch.sender_name
            influencer_email, influencer_name = pitch.recipient_email, pitch.recipient_name
        else:
            sponsor_email, sponsor_name = pitch.recipient_email, pitch.recipient_name
            influencer_email, influencer_name = pitch.sender_email, pitch.sender_name

        negotiation = Negotiation(
            pitch_id=pitch.id,
            sponsor_email=sponsor_email,
            sponsor_name=sponsor_name,
            influencer_email=influencer_email,
            influencer_name=influencer_name,
            amount=pitch.amount,
            brief=pitch.brief,
        )
        session.add(negotiation)
        session.commit()
        session.refresh(negotiation)

        session.add(NegotiationCondition(
            negotiation_id=negotiation.id, text=pitch.brief, author_role=pitch.sender_role, author_name=pitch.sender_name
        ))
        session.add(NegotiationCondition(
            negotiation_id=negotiation.id, text="100% Escrow Hold", author_role=pitch.sender_role, author_name=pitch.sender_name
        ))
        session.add(NegotiationMessage(
            negotiation_id=negotiation.id, sender_name="System",
            text=f"Negotiation channel established between {sponsor_name} and {influencer_name}. Escrow locked at ${pitch.amount}."
        ))
        session.commit()
        return {"status": "success", "message": "Pitch accepted. Negotiation opened.", "negotiation_id": negotiation.id}
    else:
        pitch.status = "Rejected"
        session.add(pitch)
        session.commit()
        return {"status": "success", "message": "Pitch declined."}

# --- NEGOTIATION ENDPOINTS ---
@app.get("/api/negotiations")
def get_negotiations(current_user: UserAccount = Depends(get_current_user), session: Session = Depends(get_session)):
    negs = session.exec(
        select(Negotiation).where(
            (Negotiation.sponsor_email == current_user.email) | (Negotiation.influencer_email == current_user.email)
        )
    ).all()
    return negs

@app.get("/api/negotiations/{negotiation_id}")
def get_negotiation_detail(negotiation_id: int, session: Session = Depends(get_session), current_user: UserAccount = Depends(get_current_user)):
    neg = session.get(Negotiation, negotiation_id)
    if not neg:
        raise HTTPException(status_code=404, detail="Negotiation not found.")
    if current_user.email not in (neg.sponsor_email, neg.influencer_email):
        raise HTTPException(status_code=403, detail="Not a participant in this negotiation.")
    messages = session.exec(
        select(NegotiationMessage).where(NegotiationMessage.negotiation_id == negotiation_id)
    ).all()
    conditions = session.exec(
        select(NegotiationCondition).where(NegotiationCondition.negotiation_id == negotiation_id)
    ).all()
    return {"negotiation": neg, "messages": messages, "conditions": conditions}

@app.post("/api/negotiations/{negotiation_id}/messages")
def add_negotiation_message(negotiation_id: int, payload: NegotiationMessageCreate, session: Session = Depends(get_session), current_user: UserAccount = Depends(get_current_user)):
    neg = session.get(Negotiation, negotiation_id)
    if not neg:
        raise HTTPException(status_code=404, detail="Negotiation not found.")
    if current_user.email not in (neg.sponsor_email, neg.influencer_email):
        raise HTTPException(status_code=403, detail="Not a participant in this negotiation.")
    msg = NegotiationMessage(negotiation_id=negotiation_id, sender_name=current_user.display_name, text=payload.text)
    session.add(msg)
    session.commit()
    return {"status": "success"}

@app.post("/api/negotiations/{negotiation_id}/conditions")
def add_negotiation_condition(negotiation_id: int, payload: NegotiationConditionCreate, session: Session = Depends(get_session), current_user: UserAccount = Depends(get_current_user)):
    neg = session.get(Negotiation, negotiation_id)
    if not neg:
        raise HTTPException(status_code=404, detail="Negotiation not found.")
    if current_user.email not in (neg.sponsor_email, neg.influencer_email):
        raise HTTPException(status_code=403, detail="Not a participant in this negotiation.")
    caller_role = "sponsor" if current_user.email == neg.sponsor_email else "influencer"

    session.add(NegotiationCondition(negotiation_id=negotiation_id, text=payload.text, author_role=caller_role, author_name=current_user.display_name))
    neg.sponsor_locked = False
    neg.influencer_locked = False
    session.add(neg)
    session.add(NegotiationMessage(
        negotiation_id=negotiation_id, sender_name="System",
        text=f"Condition appended by {caller_role.upper()}: \"{payload.text}\" (Locks reset)"
    ))
    session.commit()
    return {"status": "success"}

@app.delete("/api/negotiations/{negotiation_id}/conditions/{condition_id}")
def delete_negotiation_condition(negotiation_id: int, condition_id: int, session: Session = Depends(get_session), current_user: UserAccount = Depends(get_current_user)):
    neg = session.get(Negotiation, negotiation_id)
    if not neg:
        raise HTTPException(status_code=404, detail="Negotiation not found.")
    cond = session.get(NegotiationCondition, condition_id)
    if not cond or cond.negotiation_id != negotiation_id:
        raise HTTPException(status_code=404, detail="Condition not found.")

    is_sponsor = current_user.email == neg.sponsor_email
    is_influencer = current_user.email == neg.influencer_email
    if not (is_sponsor or is_influencer):
        raise HTTPException(status_code=403, detail="Not a participant in this negotiation.")
    caller_role = "sponsor" if is_sponsor else "influencer"
    if cond.author_role != caller_role:
        raise HTTPException(status_code=403, detail="You can only delete conditions your role introduced.")

    removed_text = cond.text
    session.delete(cond)
    neg.sponsor_locked = False
    neg.influencer_locked = False
    session.add(neg)
    session.add(NegotiationMessage(
        negotiation_id=negotiation_id, sender_name="System",
        text=f"Condition removed by {caller_role.upper()}: \"{removed_text}\". Mutual re-lock required."
    ))
    session.commit()
    return {"status": "success"}

@app.post("/api/negotiations/{negotiation_id}/lock")
def set_negotiation_lock(negotiation_id: int, payload: NegotiationLockUpdate, session: Session = Depends(get_session), current_user: UserAccount = Depends(get_current_user)):
    neg = session.get(Negotiation, negotiation_id)
    if not neg:
        raise HTTPException(status_code=404, detail="Negotiation not found.")

    if current_user.email == neg.sponsor_email:
        neg.sponsor_locked = payload.locked
        actor_role = "sponsor"
    elif current_user.email == neg.influencer_email:
        neg.influencer_locked = payload.locked
        actor_role = "influencer"
    else:
        raise HTTPException(status_code=403, detail="Not a participant in this negotiation.")

    session.add(neg)
    action_text = "locked in their side of the agreement." if payload.locked else "unlocked their agreement terms."
    session.add(NegotiationMessage(negotiation_id=negotiation_id, sender_name="System", text=f"{actor_role.upper()} has {action_text}"))
    session.commit()
    session.refresh(neg)
    if neg.sponsor_locked and neg.influencer_locked:
        log_audit(session, current_user.email, "negotiation_mutual_lock", f"negotiation_id={negotiation_id}")
        release_escrow_if_ready(negotiation_id, session)
    return {"status": "success", "sponsor_locked": neg.sponsor_locked, "influencer_locked": neg.influencer_locked}


# --- SUPPORT TICKET ENDPOINTS ---
@app.post("/api/support/tickets")
def create_support_ticket(payload: SupportTicketCreate, background_tasks: BackgroundTasks, session: Session = Depends(get_session), current_user: UserAccount = Depends(get_current_user)):
    ticket = SupportTicket(
        email=current_user.email,
        name=current_user.display_name,
        subject=payload.subject,
        message=payload.message,
        status="Open"
    )
    session.add(ticket)
    session.commit()
    session.refresh(ticket)

    if ADMIN_NOTIFICATION_EMAIL:
        background_tasks.add_task(
            send_security_alert_email,
            ADMIN_NOTIFICATION_EMAIL,
            f"New SOCIA support ticket: {payload.subject}",
            f"From: {current_user.display_name} ({current_user.email})<br><br>{payload.message}<br><br>View and respond at {PLATFORM_URL}/admin"
        )
    return {"status": "success", "message": "Support ticket submitted. Our team will respond via your registered email.", "ticket_id": ticket.id}

@app.get("/api/support/tickets")
def get_my_support_tickets(current_user: UserAccount = Depends(get_current_user), session: Session = Depends(get_session)):
    tickets = session.exec(
        select(SupportTicket).where(SupportTicket.email == current_user.email).order_by(SupportTicket.created_at.desc())
    ).all()
    return tickets

# --- ADMIN DASHBOARD (protected by a separate secret, not tied to any user account) ---
import secrets as _secrets_module
_admin_otp_store = {}  # single-slot: {"code": str, "expires_at": datetime, "attempts": int}
_admin_sessions = {}  # {token: expires_at}
_admin_lockout = {"locked_until": None}  # global (not per-IP) hard lockout after too many wrong OTPs
ADMIN_SESSION_HOURS = 4
ADMIN_OTP_MAX_ATTEMPTS = 3      # 3 wrong codes on a single OTP -> hard lockout
ADMIN_LOCKOUT_MINUTES = 30      # lockout blocks BOTH requesting a new code and verifying one

class AdminLoginRequest(BaseModel):
    secret: str

class AdminVerify2FARequest(BaseModel):
    otp_code: str

@app.post("/api/admin/request-2fa")
def admin_request_2fa(payload: AdminLoginRequest, request: Request, background_tasks: BackgroundTasks, session: Session = Depends(get_session)):
    if not ADMIN_SECRET:
        raise HTTPException(status_code=503, detail="Admin dashboard is not configured. Set ADMIN_SECRET in Railway Variables.")
    client_ip = request.client.host if request.client else "unknown"
    enforce_rate_limit(f"admin_login:{client_ip}", max_attempts=5, window_seconds=900)

    _admin_check_lockout(session, client_ip)

    if not payload.secret or not hmac.compare_digest(payload.secret, ADMIN_SECRET):
        log_audit(session, f"ip:{client_ip}", "admin_login_failed", "Incorrect secret")
        raise HTTPException(status_code=401, detail="Invalid admin credentials.")

    if not ADMIN_NOTIFICATION_EMAIL:
        raise HTTPException(status_code=503, detail="2FA requires ADMIN_NOTIFICATION_EMAIL to be set in Railway Variables.")

    otp_code = str(random.randint(100000, 999999))
    _admin_otp_store.clear()
    _admin_otp_store["code"] = otp_code
    _admin_otp_store["expires_at"] = datetime.utcnow() + timedelta(minutes=5)
    _admin_otp_store["attempts"] = 0
    log_audit(session, f"ip:{client_ip}", "admin_2fa_requested")
    background_tasks.add_task(send_otp_email, ADMIN_NOTIFICATION_EMAIL, otp_code)
    return {"status": "otp_sent", "message": f"Code sent to {ADMIN_NOTIFICATION_EMAIL}. Expires in 5 minutes.", "max_attempts": ADMIN_OTP_MAX_ATTEMPTS}

def _admin_check_lockout(session: Session, client_ip: str):
    """Raise 423 if the admin panel is currently in a hard lockout window.
    The lockout is global (not per-IP) since the admin credentials are a single
    shared secret -- this closes the loophole of just requesting a fresh OTP
    (or attacking from a different IP) immediately after burning 3 guesses."""
    locked_until = _admin_lockout.get("locked_until")
    if locked_until and datetime.utcnow() < locked_until:
        remaining_seconds = int((locked_until - datetime.utcnow()).total_seconds())
        remaining_minutes = max(1, (remaining_seconds // 60) + 1)
        log_audit(session, f"ip:{client_ip}", "admin_blocked_by_lockout", f"{remaining_minutes} min remaining")
        raise HTTPException(
            status_code=423,
            detail=f"Admin access is locked after too many incorrect codes. Try again in {remaining_minutes} minute(s)."
        )

@app.post("/api/admin/verify-2fa")
def admin_verify_2fa(payload: AdminVerify2FARequest, request: Request, session: Session = Depends(get_session)):
    client_ip = request.client.host if request.client else "unknown"
    enforce_rate_limit(f"admin_2fa:{client_ip}", max_attempts=8, window_seconds=900)

    _admin_check_lockout(session, client_ip)

    stored = _admin_otp_store.get("code")
    expires_at = _admin_otp_store.get("expires_at")
    if not stored or not expires_at or datetime.utcnow() > expires_at:
        raise HTTPException(status_code=400, detail="Code expired or not requested. Start over.")

    if payload.otp_code != stored:
        _admin_otp_store["attempts"] = _admin_otp_store.get("attempts", 0) + 1
        attempts_used = _admin_otp_store["attempts"]
        log_audit(session, f"ip:{client_ip}", "admin_2fa_failed", f"attempt {attempts_used}/{ADMIN_OTP_MAX_ATTEMPTS}")

        if attempts_used >= ADMIN_OTP_MAX_ATTEMPTS:
            _admin_otp_store.clear()
            _admin_lockout["locked_until"] = datetime.utcnow() + timedelta(minutes=ADMIN_LOCKOUT_MINUTES)
            log_audit(session, f"ip:{client_ip}", "admin_lockout_triggered", f"locked {ADMIN_LOCKOUT_MINUTES} min after {ADMIN_OTP_MAX_ATTEMPTS} wrong codes")
            raise HTTPException(
                status_code=423,
                detail=f"Too many incorrect codes ({ADMIN_OTP_MAX_ATTEMPTS}/{ADMIN_OTP_MAX_ATTEMPTS}). Admin access is locked for {ADMIN_LOCKOUT_MINUTES} minutes."
            )

        remaining_attempts = ADMIN_OTP_MAX_ATTEMPTS - attempts_used
        raise HTTPException(status_code=400, detail=f"Invalid code. {remaining_attempts} attempt(s) remaining before lockout.")

    _admin_otp_store.clear()
    session_token = _secrets_module.token_hex(32)
    _admin_sessions[session_token] = datetime.utcnow() + timedelta(hours=ADMIN_SESSION_HOURS)
    log_audit(session, f"ip:{client_ip}", "admin_login_success")
    return {"session_token": session_token, "expires_in_hours": ADMIN_SESSION_HOURS}

def verify_admin(x_admin_session: Optional[str] = Header(None)):
    """All admin endpoints now require a real 2FA session token — not the raw
    shared secret directly. The secret alone only gets you an OTP email; the
    session token is only issued after that OTP is correctly verified."""
    if not x_admin_session or x_admin_session not in _admin_sessions:
        raise HTTPException(status_code=401, detail="Admin session invalid or expired. Please log in again.")
    if datetime.utcnow() > _admin_sessions[x_admin_session]:
        del _admin_sessions[x_admin_session]
        raise HTTPException(status_code=401, detail="Admin session expired. Please log in again.")
    return True

class TicketStatusUpdate(BaseModel):
    status: str

@app.get("/api/admin/tickets")
def admin_get_all_tickets(session: Session = Depends(get_session), _: bool = Depends(verify_admin)):
    tickets = session.exec(select(SupportTicket).order_by(SupportTicket.created_at.desc())).all()
    return tickets

@app.put("/api/admin/tickets/{ticket_id}")
def admin_update_ticket_status(ticket_id: int, payload: TicketStatusUpdate, session: Session = Depends(get_session), _: bool = Depends(verify_admin)):
    ticket = session.get(SupportTicket, ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found.")
    ticket.status = payload.status
    session.add(ticket)
    session.commit()
    background_tasks_note = None  # notification below is optional/manual for now
    return {"status": "success", "message": "Ticket status updated."}

@app.get("/api/admin/audit-log")
def admin_get_audit_log(session: Session = Depends(get_session), _: bool = Depends(verify_admin)):
    logs = session.exec(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(200)).all()
    return logs

@app.get("/api/admin/users")
def admin_get_all_users(session: Session = Depends(get_session), _: bool = Depends(verify_admin)):
    users = session.exec(select(UserAccount).order_by(UserAccount.created_at.desc())).all()
    return [{
        "id": u.id,
        "email": u.email,
        "role": u.role,
        "display_name": u.display_name,
        "phone_number": u.phone_number,
        "industry": u.industry,
        "is_verified": u.is_verified,
        "is_subscribed": u.is_subscribed,
        "razorpay_account_id": u.razorpay_account_id,
        "razorpay_account_active": u.razorpay_account_active,
        "created_at": u.created_at,
    } for u in users]

@app.get("/api/admin/overview")
def admin_get_overview(session: Session = Depends(get_session), _: bool = Depends(verify_admin)):
    """Fast top-level stats — meant to be the first thing you see in the dashboard."""
    users = session.exec(select(UserAccount)).all()
    listings = session.exec(select(MarketplaceListing)).all()
    pitches = session.exec(select(Pitch)).all()
    negotiations = session.exec(select(Negotiation)).all()
    payments = session.exec(select(EscrowPayment)).all()
    tickets = session.exec(select(SupportTicket)).all()

    total_gmv = sum(p.amount for p in payments if p.status == "released")
    total_commission = sum(p.platform_fee for p in payments if p.status == "released")

    return {
        "total_users": len(users),
        "verified_users": sum(1 for u in users if u.is_verified),
        "sponsors": sum(1 for u in users if u.role == "sponsor"),
        "influencers": sum(1 for u in users if u.role == "influencer"),
        "active_subscribers": sum(1 for u in users if u.is_subscribed),
        "total_listings": len(listings),
        "total_pitches": len(pitches),
        "pending_pitches": sum(1 for p in pitches if p.status == "Pending"),
        "total_negotiations": len(negotiations),
        "escrow_funded_count": sum(1 for p in payments if p.status in ("funded", "released", "pending_review")),
        "escrow_released_count": sum(1 for p in payments if p.status == "released"),
        "total_gmv_released": total_gmv,
        "total_commission_earned": total_commission,
        "open_tickets": sum(1 for t in tickets if t.status == "Open"),
    }

@app.get("/api/admin/analytics")
def admin_get_analytics(session: Session = Depends(get_session), _: bool = Depends(verify_admin)):
    """Real analytics for the admin panel: collects platform data across every table,
    reads and aggregates it into trends and breakdowns, and returns the summarized
    result. This is deliberately separate from /api/admin/overview (which stays a
    fast single-glance snapshot) -- this endpoint is the "read, analyse, summarize"
    layer: growth over time, where the data is concentrated, and where the funnels
    are leaking."""
    users = session.exec(select(UserAccount)).all()
    listings = session.exec(select(MarketplaceListing)).all()
    pitches = session.exec(select(Pitch)).all()
    negotiations = session.exec(select(Negotiation)).all()
    payments = session.exec(select(EscrowPayment)).all()
    tickets = session.exec(select(SupportTicket)).all()

    def _daily_counts(items, date_attr, days=30):
        """Buckets items into day-granularity counts for the trailing N days."""
        today = datetime.utcnow().date()
        buckets = {(today - timedelta(days=i)).isoformat(): 0 for i in range(days - 1, -1, -1)}
        for it in items:
            dt = getattr(it, date_attr, None)
            if not dt:
                continue
            key = dt.date().isoformat()
            if key in buckets:
                buckets[key] += 1
        return [{"date": k, "count": v} for k, v in buckets.items()]

    def _tally(items, extractor, top_n=12):
        """Splits comma-separated tag fields across all items and tallies frequency."""
        counts = {}
        for it in items:
            raw = extractor(it) or ""
            for tag in raw.split(","):
                tag = tag.strip()
                if not tag:
                    continue
                key = tag.title() if len(tag) > 3 else tag.upper()
                counts[key] = counts.get(key, 0) + 1
        ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
        return [{"label": k, "count": v} for k, v in ranked[:top_n]]

    def _bucket_budget(listings_subset):
        buckets = {"₹0–1K": 0, "₹1K–5K": 0, "₹5K–20K": 0, "₹20K–100K": 0, "₹100K+": 0}
        for l in listings_subset:
            b = l.budget_max or l.budget_min or 0
            if b <= 0:
                continue
            elif b < 1000:
                buckets["₹0–1K"] += 1
            elif b < 5000:
                buckets["₹1K–5K"] += 1
            elif b < 20000:
                buckets["₹5K–20K"] += 1
            elif b < 100000:
                buckets["₹20K–100K"] += 1
            else:
                buckets["₹100K+"] += 1
        return [{"label": k, "count": v} for k, v in buckets.items()]

    # --- Growth trends (last 30 days) ---
    signups_trend = _daily_counts(users, "created_at", days=30)
    listings_trend = _daily_counts(listings, "created_at", days=30)

    # --- Content / demand breakdowns ---
    industry_breakdown = _tally(listings, lambda l: l.industry)
    niche_breakdown = _tally(listings, lambda l: l.niche_tags)
    platform_breakdown = _tally(listings, lambda l: l.platforms)
    location_breakdown = _tally(listings, lambda l: l.location)
    language_breakdown = _tally(listings, lambda l: l.content_languages)
    budget_distribution = _bucket_budget(listings)

    sponsor_listings = [l for l in listings if l.role == "sponsor"]
    influencer_listings = [l for l in listings if l.role == "influencer"]
    brand_safety_conscious = sum(1 for l in sponsor_listings if l.excluded_niches.strip())
    local_presence_required = sum(1 for l in sponsor_listings if l.requires_local_presence)

    # --- Funnels ---
    pitch_total = len(pitches)
    pitch_accepted = sum(1 for p in pitches if p.status == "Accepted")
    pitch_rejected = sum(1 for p in pitches if p.status == "Rejected")
    pitch_pending = sum(1 for p in pitches if p.status == "Pending")

    escrow_by_status = {}
    for p in payments:
        escrow_by_status[p.status] = escrow_by_status.get(p.status, 0) + 1
    released = [p for p in payments if p.status == "released"]
    total_gmv = sum(p.amount for p in released)
    total_commission = sum(p.platform_fee for p in released)
    avg_deal_size = (total_gmv / len(released)) if released else 0

    # --- Trust / reliability distribution across the whole marketplace ---
    all_emails = set(l.contact for l in listings if l.contact)
    reliability_signals = get_reliability_signals(session, all_emails)
    reliability_buckets = {"New (no history)": 0, "Building (0.4–0.7)": 0, "Trusted (0.7–0.9)": 0, "Highly Trusted (0.9+)": 0}
    for email in all_emails:
        score = _reliability_score(reliability_signals.get(email))
        if email not in reliability_signals or (reliability_signals[email]["completed"] + reliability_signals[email]["disputed"] + reliability_signals[email]["refunded"]) == 0:
            reliability_buckets["New (no history)"] += 1
        elif score < 0.7:
            reliability_buckets["Building (0.4–0.7)"] += 1
        elif score < 0.9:
            reliability_buckets["Trusted (0.7–0.9)"] += 1
        else:
            reliability_buckets["Highly Trusted (0.9+)"] += 1

    verified_count = sum(1 for l in listings if l.verified)

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "trends": {
            "signups_last_30_days": signups_trend,
            "listings_last_30_days": listings_trend,
        },
        "breakdowns": {
            "industry": industry_breakdown,
            "niche_tags": niche_breakdown,
            "platforms": platform_breakdown,
            "location": location_breakdown,
            "content_languages": language_breakdown,
            "budget_distribution": budget_distribution,
            "reliability": [{"label": k, "count": v} for k, v in reliability_buckets.items()],
        },
        "supply_demand": {
            "sponsor_listings": len(sponsor_listings),
            "influencer_listings": len(influencer_listings),
            "verified_listings": verified_count,
            "unverified_listings": len(listings) - verified_count,
            "brand_safety_conscious_sponsors": brand_safety_conscious,
            "local_presence_required_campaigns": local_presence_required,
        },
        "funnels": {
            "pitches": {
                "total": pitch_total,
                "accepted": pitch_accepted,
                "rejected": pitch_rejected,
                "pending": pitch_pending,
                "acceptance_rate_pct": round((pitch_accepted / pitch_total * 100), 1) if pitch_total else 0,
            },
            "negotiations_opened": len(negotiations),
            "escrow_by_status": escrow_by_status,
            "total_gmv_released": total_gmv,
            "total_commission_earned": total_commission,
            "avg_deal_size": round(avg_deal_size, 2),
        },
        "support": {
            "total_tickets": len(tickets),
            "open": sum(1 for t in tickets if t.status == "Open"),
            "in_progress": sum(1 for t in tickets if t.status == "In Progress"),
            "resolved": sum(1 for t in tickets if t.status == "Resolved"),
        },
        "users": {
            "total": len(users),
            "verified": sum(1 for u in users if u.is_verified),
            "subscribed": sum(1 for u in users if u.is_subscribed),
            "subscription_conversion_rate_pct": round((sum(1 for u in users if u.is_subscribed) / len(users) * 100), 1) if users else 0,
        },
    }

@app.get("/api/admin/escrow/pending-review")
def admin_get_pending_review_escrows(session: Session = Depends(get_session), _: bool = Depends(verify_admin)):
    payments = session.exec(select(EscrowPayment).where(EscrowPayment.status == "pending_review")).all()
    return payments

@app.post("/api/admin/escrow/{payment_id}/approve")
def admin_approve_escrow_release(payment_id: int, session: Session = Depends(get_session), _: bool = Depends(verify_admin)):
    """Manually approve a large-amount escrow release that was held for review."""
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        raise HTTPException(status_code=503, detail="Payments are not configured yet. Set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET in Railway Variables.")
    payment = session.get(EscrowPayment, payment_id)
    if not payment:
        raise HTTPException(status_code=404, detail="Escrow payment not found.")
    if payment.status != "pending_review":
        raise HTTPException(status_code=400, detail=f"This payment is not pending review (current status: {payment.status}).")

    influencer = session.exec(select(UserAccount).where(UserAccount.email == payment.influencer_email)).first()
    if not influencer or not influencer.razorpay_account_id:
        raise HTTPException(status_code=400, detail="Influencer has no linked payout account.")

    try:
        release_razorpay_escrow(payment, session)
        session.add(NegotiationMessage(
            negotiation_id=payment.negotiation_id, sender_name="System",
            text=f"Escrow released (admin-approved): ₹{payment.influencer_payout:,.2f} transferred to the influencer."
        ))
        session.commit()
        log_audit(session, "admin", "escrow_release_admin_approved", f"payment_id={payment_id} amount={payment.influencer_payout}")
        return {"status": "success", "message": "Escrow released."}
    except HTTPException as e:
        raise e


# --- FORGOT PASSWORD (reuses the OTP + Google Workspace SMTP infrastructure) ---
class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp_code: str
    new_password: str

@app.post("/auth/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, background_tasks: BackgroundTasks, session: Session = Depends(get_session)):
    enforce_rate_limit(f"forgot:{payload.email}", max_attempts=3, window_seconds=900)
    user = session.exec(select(UserAccount).where(UserAccount.email == payload.email)).first()
    # Always return the same generic response, whether or not the account exists —
    # prevents leaking which emails are registered (a real security consideration).
    if user:
        reset_otp = str(random.randint(100000, 999999))
        user.otp_code = reset_otp
        session.add(user)
        session.commit()
        background_tasks.add_task(send_otp_email, payload.email, reset_otp)
    return {"status": "success", "message": "If an account exists for this email, a reset code has been sent."}

@app.post("/auth/reset-password")
def reset_password(payload: ResetPasswordRequest, session: Session = Depends(get_session)):
    user = session.exec(select(UserAccount).where(UserAccount.email == payload.email)).first()
    if not user or not user.otp_code or user.otp_code != payload.otp_code:
        raise HTTPException(status_code=400, detail="Invalid or expired reset code.")

    user.hashed_password = hash_password(payload.new_password)
    user.otp_code = None
    session.add(user)
    session.commit()
    return {"status": "success", "message": "Password has been reset. You may now log in."}

# --- DATA PROTECTION: RIGHT TO ACCESS & RIGHT TO ERASURE (GDPR/CCPA-style compliance) ---
@app.get("/api/account/export")
def export_my_data(current_user: UserAccount = Depends(get_current_user), session: Session = Depends(get_session)):
    """Returns everything stored about the requesting account in one JSON payload."""
    listings = session.exec(select(MarketplaceListing).where(MarketplaceListing.contact == current_user.email)).all()
    pitches_sent = session.exec(select(Pitch).where(Pitch.sender_email == current_user.email)).all()
    pitches_received = session.exec(select(Pitch).where(Pitch.recipient_email == current_user.email)).all()
    negotiations = session.exec(
        select(Negotiation).where(
            (Negotiation.sponsor_email == current_user.email) | (Negotiation.influencer_email == current_user.email)
        )
    ).all()
    tickets = session.exec(select(SupportTicket).where(SupportTicket.email == current_user.email)).all()

    log_audit(session, current_user.email, "data_export_requested")

    return {
        "account": {
            "email": current_user.email,
            "role": current_user.role,
            "display_name": current_user.display_name,
            "handle": current_user.handle,
            "company_name": current_user.company_name,
            "phone_number": current_user.phone_number,
            "industry": current_user.industry,
            "accepted_terms_at": current_user.accepted_terms_at,
        },
        "listings": listings,
        "pitches_sent": pitches_sent,
        "pitches_received": pitches_received,
        "negotiations": negotiations,
        "support_tickets": tickets,
    }

class AccountDeleteRequest(BaseModel):
    password: str
    confirm: str  # must be exactly "DELETE" to proceed — prevents accidental one-click deletion

@app.post("/api/account/delete")
def delete_my_account(payload: AccountDeleteRequest, current_user: UserAccount = Depends(get_current_user), session: Session = Depends(get_session)):
    if payload.confirm != "DELETE":
        raise HTTPException(status_code=400, detail="Type DELETE exactly to confirm account deletion.")
    if not verify_password(payload.password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect password.")

    email = current_user.email
    # Remove owned listings; leave historical pitches/negotiations/deals intact for the
    # counterparty's records, but anonymize this account's identifying fields.
    listings = session.exec(select(MarketplaceListing).where(MarketplaceListing.contact == email)).all()
    for l in listings:
        session.delete(l)

    log_audit(session, email, "account_deleted")
    session.delete(current_user)
    session.commit()
    return {"status": "success", "message": "Account and owned listings permanently deleted."}

class ConnectOnboardingRequest(BaseModel):
    password: str

def send_security_alert_email(recipient_email: str, subject: str, message: str):
    """Reuses the same Google Workspace SMTP pipeline as OTP emails, for security-relevant alerts."""
    html_body = f"""
    <div style="font-family: Arial, sans-serif; padding: 20px; background: #0f172a; color: #f8fafc; border-radius: 8px;">
        <h2 style="color: #f59e0b;">SOCIA Security Alert</h2>
        <p>{message}</p>
        <p style="margin-top: 20px; font-size: 12px; color: #94a3b8;">If this wasn't you, contact support immediately and change your password.</p>
    </div>
    """
    app_password = (GMAIL_APP_PASSWORD or "").strip()
    if not app_password:
        print(f"[SECURITY ALERT - EMAIL SKIPPED, no SMTP configured] To: {recipient_email} | {subject} | {message}")
        return
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"SOCIA Protocol Security <{GMAIL_SENDER}>"
    msg["To"] = recipient_email
    msg.attach(MIMEText(html_body, "html"))
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as server:
            server.starttls()
            server.login(GMAIL_SENDER, app_password)
            server.sendmail(GMAIL_SENDER, [recipient_email], msg.as_string())
    except Exception as e:
        print(f"[SECURITY ALERT EMAIL ERROR] {str(e)}")

@app.get("/api/negotiations/{negotiation_id}/escrow-status")
def get_escrow_status(negotiation_id: int, current_user: UserAccount = Depends(get_current_user), session: Session = Depends(get_session)):
    payment = session.exec(select(EscrowPayment).where(EscrowPayment.negotiation_id == negotiation_id)).first()
    if not payment:
        return {"status": "not_funded"}
    if current_user.email not in (payment.sponsor_email, payment.influencer_email):
        raise HTTPException(status_code=403, detail="Not a participant in this negotiation.")
    return payment


PAYOUT_COOLDOWN_HOURS = 48
MANUAL_REVIEW_THRESHOLD = float(os.getenv("MANUAL_REVIEW_THRESHOLD", "5000"))  # releases above this $ amount need admin approval

def release_escrow_if_ready(negotiation_id: int, session: Session):
    """Called automatically when both parties mutually lock a negotiation.
    Transfers funds from the platform balance to the influencer's connected Razorpay account.
    Includes two safety gates: a cooldown on newly-linked payout accounts (protects
    against a hijacked account immediately redirecting funds), and a manual review
    threshold for large amounts."""
    payment = session.exec(select(EscrowPayment).where(EscrowPayment.negotiation_id == negotiation_id)).first()
    if not payment or payment.status != "funded":
        return  # Nothing to release — not funded, or already released

    influencer = session.exec(select(UserAccount).where(UserAccount.email == payment.influencer_email)).first()
    payout_ready = influencer and influencer.razorpay_account_id and influencer.razorpay_account_active

    if not payout_ready:
        session.add(NegotiationMessage(
            negotiation_id=negotiation_id, sender_name="System",
            text="Mutual lock achieved, but the influencer hasn't completed Razorpay payout KYC yet. Funds remain in escrow until they do."
        ))
        session.commit()
        return

    # Gate 1: cooldown on newly-linked payout accounts
    if influencer.payout_account_linked_at:
        hours_since_link = (datetime.utcnow() - influencer.payout_account_linked_at).total_seconds() / 3600
        if hours_since_link < PAYOUT_COOLDOWN_HOURS:
            remaining = round(PAYOUT_COOLDOWN_HOURS - hours_since_link, 1)
            session.add(NegotiationMessage(
                negotiation_id=negotiation_id, sender_name="System",
                text=f"Mutual lock achieved, but this payout account was linked recently. For security, a {PAYOUT_COOLDOWN_HOURS}-hour hold applies to new payout accounts — approximately {remaining}h remaining before funds can release."
            ))
            session.commit()
            log_audit(session, payment.influencer_email, "escrow_release_held_cooldown", f"negotiation_id={negotiation_id} hours_remaining={remaining}")
            return

    # Gate 2: manual review threshold for large amounts
    if payment.influencer_payout > MANUAL_REVIEW_THRESHOLD:
        payment.status = "pending_review"
        session.add(payment)
        session.add(NegotiationMessage(
            negotiation_id=negotiation_id, sender_name="System",
            text=f"Mutual lock achieved. This release (₹{payment.influencer_payout:,.2f}) exceeds the automatic threshold and has been queued for manual admin review before funds are transferred."
        ))
        session.commit()
        log_audit(session, payment.influencer_email, "escrow_release_held_review", f"negotiation_id={negotiation_id} amount={payment.influencer_payout}")
        return

    try:
        release_razorpay_escrow(payment, session)
        session.add(NegotiationMessage(
            negotiation_id=negotiation_id, sender_name="System",
            text=f"Escrow released: ₹{payment.influencer_payout:,.2f} transferred to the influencer (platform fee: ₹{payment.platform_fee:,.2f})."
        ))
        session.commit()
        log_audit(session, payment.influencer_email, "escrow_released", f"negotiation_id={negotiation_id} amount={payment.influencer_payout}")
    except HTTPException as e:
        session.add(NegotiationMessage(
            negotiation_id=negotiation_id, sender_name="System",
            text=f"Escrow release failed due to a payment processing error. Support has been notified."
        ))
        session.commit()
        print(f"[PAYMENT ERROR] Transfer failed for negotiation {negotiation_id}: {str(e)}")


# ============================================================================
# RAZORPAY ROUTE — ACTIVE PROVIDER FOR INDIA (Stripe India is invite-only)
# ============================================================================
# Pattern: an Order is created with an embedded transfer to the influencer's
# Linked Account, set to on_hold=True (indefinite hold). Razorpay auto-splits
# the payment into its regulated nodal account at capture time — funds sit
# there, not in SOCIA's bank account, satisfying the "don't hold money
# yourself" requirement. Release is a single PATCH call flipping on_hold to
# False once both parties mutually lock the negotiation.
#
# Prerequisites (real-world actions, not code):
#   1. Create a Razorpay account, activate Route in the dashboard.
#   2. Set RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET in Railway Variables
#      (start with rzp_test_... keys, NOT live keys).
#   3. In Razorpay Dashboard → Webhooks, add an endpoint pointing to:
#      https://yourdomain.com/api/payments/razorpay/webhook
#      Subscribe to: payment.captured
#      Copy the webhook secret into RAZORPAY_WEBHOOK_SECRET.
#   4. IMPORTANT — confirm directly with Razorpay's integration/compliance
#      team whether an indefinite on_hold is permitted for your specific
#      "hold until mutual negotiation lock-in" use case, since RBI settlement
#      rules (T+1 default) may require a bounded hold rather than an
#      open-ended one. Do not assume this is fine without asking them.
#   5. Test everything with Razorpay's test mode and test cards before ever
#      switching to live keys.
# ============================================================================

@app.post("/api/payments/razorpay/connect-onboarding")
def start_razorpay_onboarding(payload: ConnectOnboardingRequest, background_tasks: BackgroundTasks, current_user: UserAccount = Depends(get_current_user), session: Session = Depends(get_session)):
    """Creates a Razorpay Linked Account for the current user (influencer receiving payouts).
    NOTE: Razorpay's Linked Account creation requires real business/KYC details
    (legal name, business type, registered address, bank details) — the fields
    below are the minimum documented requirement. Expect to expand this with
    real onboarding form fields once you're testing against a real Razorpay
    test account; consult current docs at razorpay.com/docs/api/payments/route/create-linked-account/"""
    if not verify_password(payload.password, current_user.hashed_password):
        log_audit(session, current_user.email, "payout_link_failed_razorpay", "Incorrect password")
        raise HTTPException(status_code=400, detail="Incorrect password.")

    if current_user.razorpay_account_id:
        raise HTTPException(status_code=400, detail="A Razorpay payout account is already linked. Use the relink endpoint to change it.")

    body = {
        "email": current_user.email,
        "phone": "9999999999",  # placeholder — MUST collect a real phone number from the user before going live
        "type": "route",
        "legal_business_name": current_user.display_name,
        "business_type": "individual",
        "contact_name": current_user.display_name,
        "profile": {
            "category": "ecommerce",
            "subcategory": "marketplace",
            "addresses": {
                "registered": {
                    "street1": "NOT_YET_COLLECTED",
                    "street2": "",
                    "city": "NOT_YET_COLLECTED",
                    "state": "NOT_YET_COLLECTED",
                    "postal_code": "000000",
                    "country": "IN"
                }
            }
        }
    }
    result = razorpay_request("POST", "/accounts", json_body=body)

    current_user.razorpay_account_id = result["id"]
    current_user.payout_account_linked_at = datetime.utcnow()
    session.add(current_user)
    session.commit()

    log_audit(session, current_user.email, "razorpay_payout_account_linked", f"account={result['id']}")
    background_tasks.add_task(
        send_security_alert_email,
        current_user.email,
        "New payout account linked on SOCIA Protocol",
        f"A new Razorpay payout account was just linked to your SOCIA account ({current_user.email}). "
        f"A {PAYOUT_COOLDOWN_HOURS}-hour security hold applies before any funds can release to it."
    )
    return {"status": "success", "razorpay_account_id": result["id"], "message": "Linked account created. Complete KYC in your Razorpay-provided dashboard link before payouts can be released."}

@app.get("/api/payments/razorpay/connect-status")
def get_razorpay_connect_status(current_user: UserAccount = Depends(get_current_user), session: Session = Depends(get_session)):
    if not current_user.razorpay_account_id:
        return {"connected": False, "onboarded": False}
    result = razorpay_request("GET", f"/accounts/{current_user.razorpay_account_id}")
    onboarded = result.get("status") == "activated"
    if onboarded != current_user.razorpay_account_active:
        current_user.razorpay_account_active = onboarded
        session.add(current_user)
        session.commit()
    return {"connected": True, "onboarded": onboarded, "status": result.get("status")}

@app.post("/api/negotiations/{negotiation_id}/fund-escrow-razorpay")
def fund_escrow_razorpay(negotiation_id: int, session: Session = Depends(get_session), current_user: UserAccount = Depends(get_current_user)):
    """Creates a Razorpay Order with an embedded, indefinitely-held transfer to the
    influencer's Linked Account. Returns order details for the frontend to open
    Razorpay's Checkout modal with."""
    neg = session.get(Negotiation, negotiation_id)
    if not neg:
        raise HTTPException(status_code=404, detail="Negotiation not found.")
    if current_user.email != neg.sponsor_email:
        raise HTTPException(status_code=403, detail="Only the sponsor can fund escrow for this negotiation.")

    existing = session.exec(select(EscrowPayment).where(EscrowPayment.negotiation_id == negotiation_id)).first()
    if existing and existing.status in ("funded", "released"):
        raise HTTPException(status_code=400, detail=f"Escrow already {existing.status} for this negotiation.")

    influencer = session.exec(select(UserAccount).where(UserAccount.email == neg.influencer_email)).first()
    if not influencer or not influencer.razorpay_account_id:
        raise HTTPException(status_code=400, detail="The influencer hasn't set up their Razorpay payout account yet.")

    # All math done in integer paise from the start — the payout is defined as
    # "total minus fee" via integer subtraction, which makes it mathematically
    # impossible for a rounding gap to exist between the transfer amount and the
    # order total. This closes the exact failure mode where a leftover fraction
    # would otherwise silently default to the platform's own settlement account.
    amount_paise = int(round(neg.amount * 100))
    platform_fee_paise = int(round(amount_paise * (get_commission_rate(current_user) / 100)))
    payout_paise = amount_paise - platform_fee_paise

    if payout_paise + platform_fee_paise != amount_paise:
        raise HTTPException(status_code=500, detail="Escrow split arithmetic failed to reconcile — refusing to proceed.")

    platform_fee = platform_fee_paise / 100
    influencer_payout = payout_paise / 100

    order_body = {
        "amount": amount_paise,
        "currency": "INR",
        "payment_capture": 1,
        "partial_payment": False,
        "notes": {"negotiation_id": str(negotiation_id)},
        "transfers": [{
            "account": influencer.razorpay_account_id,
            "amount": payout_paise,
            "currency": "INR",
            "on_hold": True,  # held indefinitely until we explicitly release on mutual lock-in
            "notes": {"negotiation_id": str(negotiation_id)},
        }]
    }
    order = razorpay_request("POST", "/orders", json_body=order_body)

    if existing:
        existing.razorpay_order_id = order["id"]
        existing.amount = neg.amount
        existing.platform_fee = platform_fee
        existing.influencer_payout = influencer_payout
        existing.status = "pending"
        session.add(existing)
    else:
        session.add(EscrowPayment(
            negotiation_id=negotiation_id,
            sponsor_email=neg.sponsor_email,
            influencer_email=neg.influencer_email,
            amount=neg.amount,
            platform_fee=platform_fee,
            influencer_payout=influencer_payout,
            razorpay_order_id=order["id"],
            status="pending"
        ))
    session.commit()
    log_audit(session, current_user.email, "razorpay_order_created", f"negotiation_id={negotiation_id} amount={neg.amount}")

    return {
        "provider": "razorpay",
        "order_id": order["id"],
        "amount": amount_paise,
        "currency": "INR",
        "key_id": RAZORPAY_KEY_ID,
        "sponsor_name": current_user.display_name,
        "sponsor_email": current_user.email,
    }

class RazorpayVerifyPayment(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str

@app.post("/api/negotiations/{negotiation_id}/verify-razorpay-payment")
def verify_razorpay_payment(negotiation_id: int, payload: RazorpayVerifyPayment, session: Session = Depends(get_session), current_user: UserAccount = Depends(get_current_user)):
    """Verifies the payment signature returned by Razorpay's Checkout modal after
    a successful payment. This is the primary confirmation path; the webhook
    below is a backup in case the browser closes before this call fires."""
    import hmac as _hmac
    import hashlib as _hashlib

    payload_str = f"{payload.razorpay_order_id}|{payload.razorpay_payment_id}"
    expected_signature = _hmac.new(
        RAZORPAY_KEY_SECRET.encode(), payload_str.encode(), _hashlib.sha256
    ).hexdigest()

    if not _hmac.compare_digest(expected_signature, payload.razorpay_signature):
        log_audit(session, current_user.email, "razorpay_signature_invalid", f"negotiation_id={negotiation_id}")
        raise HTTPException(status_code=400, detail="Payment signature verification failed.")

    payment = session.exec(select(EscrowPayment).where(EscrowPayment.negotiation_id == negotiation_id)).first()
    if not payment:
        raise HTTPException(status_code=404, detail="Escrow record not found.")

    if payment.status == "pending":
        payment.status = "funded"
        payment.funded_at = datetime.utcnow()
        payment.razorpay_payment_id = payload.razorpay_payment_id
        session.add(payment)
        session.add(NegotiationMessage(
            negotiation_id=negotiation_id, sender_name="System",
            text=f"Escrow funded: ₹{payment.amount:,.2f} secured. Funds will release to the influencer upon mutual lock-in."
        ))
        session.commit()
        log_audit(session, current_user.email, "razorpay_escrow_funded", f"negotiation_id={negotiation_id}")

    return {"status": "success"}

@app.post("/api/payments/razorpay/webhook")
async def razorpay_webhook(request: Request, session: Session = Depends(get_session)):
    """Backup confirmation path — Razorpay calls this server-to-server regardless
    of whether the user's browser stayed open. Signature verification is the
    authentication for this endpoint; no user auth applies."""
    import hmac as _hmac
    import hashlib as _hashlib

    payload = await request.body()
    sig_header = request.headers.get("x-razorpay-signature", "")

    if RAZORPAY_WEBHOOK_SECRET:
        expected = _hmac.new(RAZORPAY_WEBHOOK_SECRET.encode(), payload, _hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(expected, sig_header):
            raise HTTPException(status_code=400, detail="Invalid webhook signature.")

    event = json.loads(payload)
    if event.get("event") == "payment.captured":
        entity = event.get("payload", {}).get("payment", {}).get("entity", {})
        order_id = entity.get("order_id")
        if order_id:
            payment = session.exec(select(EscrowPayment).where(EscrowPayment.razorpay_order_id == order_id)).first()
            if payment and payment.status == "pending":
                payment.status = "funded"
                payment.funded_at = datetime.utcnow()
                payment.razorpay_payment_id = entity.get("id")
                session.add(payment)
                session.add(NegotiationMessage(
                    negotiation_id=payment.negotiation_id, sender_name="System",
                    text=f"Escrow funded (webhook-confirmed): ₹{payment.amount:,.2f} secured."
                ))
                session.commit()
                log_audit(session, payment.sponsor_email, "razorpay_escrow_funded_webhook", f"negotiation_id={payment.negotiation_id}")

    return {"status": "received"}

def release_razorpay_escrow(payment: EscrowPayment, session: Session):
    """Releases a held Razorpay transfer by flipping on_hold to False.
    Requires knowing the transfer_id, which we fetch by listing transfers for the order
    since Razorpay's order-with-transfers response nests the transfer entity."""
    order_details = razorpay_request("GET", f"/orders/{payment.razorpay_order_id}/payments")
    payments_list = order_details.get("items", [])
    if not payments_list:
        raise HTTPException(status_code=400, detail="No captured payment found for this order yet.")
    payment_id = payments_list[0]["id"]

    transfers = razorpay_request("GET", f"/payments/{payment_id}/transfers")
    transfer_items = transfers.get("items", [])
    if not transfer_items:
        raise HTTPException(status_code=400, detail="No transfer found for this payment.")
    transfer_id = transfer_items[0]["id"]

    razorpay_request("PATCH", f"/transfers/{transfer_id}", json_body={"on_hold": False})

    payment.razorpay_transfer_id = transfer_id
    payment.status = "released"
    payment.released_at = datetime.utcnow()
    session.add(payment)


# ============================================================================
# SOVEREIGN PASS SUBSCRIPTION — ₹20,000/month, drops commission from 7% to 3.5%
# ============================================================================
# Uses Razorpay Subscriptions (recurring billing), separate from Route (one-off
# escrow payments). Requires a Razorpay Plan to exist — created automatically
# on first use if RAZORPAY_SOVEREIGN_PLAN_ID isn't already set.
# ============================================================================

RAZORPAY_SOVEREIGN_PLAN_ID = os.getenv("RAZORPAY_SOVEREIGN_PLAN_ID", "")

def get_or_create_sovereign_plan() -> str:
    global RAZORPAY_SOVEREIGN_PLAN_ID
    if RAZORPAY_SOVEREIGN_PLAN_ID:
        return RAZORPAY_SOVEREIGN_PLAN_ID
    plan = razorpay_request("POST", "/plans", json_body={
        "period": "monthly",
        "interval": 1,
        "item": {
            "name": "SOCIA Sovereign Pass",
            "amount": int(round(SUBSCRIPTION_PRICE_INR * 100)),
            "currency": "INR",
            "description": f"Reduces SOCIA platform commission from {BASE_COMMISSION_PERCENT}% to {SUBSCRIBER_COMMISSION_PERCENT}% on all escrow transactions."
        }
    })
    RAZORPAY_SOVEREIGN_PLAN_ID = plan["id"]
    print(f"[SOVEREIGN PASS] Created Razorpay plan {plan['id']} — set RAZORPAY_SOVEREIGN_PLAN_ID in Railway Variables to reuse it instead of recreating on every restart.")
    return RAZORPAY_SOVEREIGN_PLAN_ID

@app.post("/api/subscription/create")
def create_subscription(current_user: UserAccount = Depends(get_current_user), session: Session = Depends(get_session)):
    if current_user.role != "sponsor":
        raise HTTPException(status_code=400, detail="Sovereign Pass is only available to sponsor accounts.")
    if current_user.is_subscribed and current_user.subscription_expires_at and current_user.subscription_expires_at > datetime.utcnow():
        raise HTTPException(status_code=400, detail="You already have an active subscription.")

    plan_id = get_or_create_sovereign_plan()
    subscription = razorpay_request("POST", "/subscriptions", json_body={
        "plan_id": plan_id,
        "customer_notify": 1,
        "total_count": 120,  # up to 10 years of monthly cycles; cancel anytime
        "notes": {"email": current_user.email}
    })

    current_user.subscription_id = subscription["id"]
    session.add(current_user)
    session.commit()
    log_audit(session, current_user.email, "subscription_checkout_created", f"subscription_id={subscription['id']}")

    return {"subscription_id": subscription["id"], "key_id": RAZORPAY_KEY_ID}

class VerifySubscriptionPayment(BaseModel):
    razorpay_subscription_id: str
    razorpay_payment_id: str
    razorpay_signature: str

@app.post("/api/subscription/verify")
def verify_subscription(payload: VerifySubscriptionPayment, current_user: UserAccount = Depends(get_current_user), session: Session = Depends(get_session)):
    payload_str = f"{payload.razorpay_payment_id}|{payload.razorpay_subscription_id}"
    expected_signature = hmac.new(RAZORPAY_KEY_SECRET.encode(), payload_str.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_signature, payload.razorpay_signature):
        raise HTTPException(status_code=400, detail="Payment signature verification failed.")

    current_user.is_subscribed = True
    current_user.subscription_expires_at = datetime.utcnow() + timedelta(days=32)  # renews monthly via webhook below
    session.add(current_user)
    session.commit()
    log_audit(session, current_user.email, "subscription_activated")

    return {"status": "success", "message": f"Sovereign Pass active. Your commission rate is now {SUBSCRIBER_COMMISSION_PERCENT}%."}

@app.post("/api/payments/razorpay/subscription-webhook")
async def razorpay_subscription_webhook(request: Request, session: Session = Depends(get_session)):
    """Handles subscription renewal/cancellation events so subscription_expires_at
    stays accurate without relying solely on the client-side verify call."""
    payload = await request.body()
    sig_header = request.headers.get("x-razorpay-signature", "")
    if RAZORPAY_SUBSCRIPTION_WEBHOOK_SECRET:
        expected = hmac.new(RAZORPAY_SUBSCRIPTION_WEBHOOK_SECRET.encode(), payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig_header):
            raise HTTPException(status_code=400, detail="Invalid webhook signature.")

    event = json.loads(payload)
    event_type = event.get("event", "")
    entity = event.get("payload", {}).get("subscription", {}).get("entity", {})
    subscription_id = entity.get("id")

    if subscription_id:
        user = session.exec(select(UserAccount).where(UserAccount.subscription_id == subscription_id)).first()
        if user:
            if event_type == "subscription.charged":
                user.is_subscribed = True
                user.subscription_expires_at = datetime.utcnow() + timedelta(days=32)
                session.add(user)
                session.commit()
                log_audit(session, user.email, "subscription_renewed")
            elif event_type in ("subscription.cancelled", "subscription.halted", "subscription.completed"):
                user.is_subscribed = False
                session.add(user)
                session.commit()
                log_audit(session, user.email, "subscription_ended", event_type)

    return {"status": "received"}

@app.post("/api/subscription/cancel")
def cancel_subscription(current_user: UserAccount = Depends(get_current_user), session: Session = Depends(get_session)):
    if not current_user.subscription_id:
        raise HTTPException(status_code=400, detail="No active subscription found.")
    razorpay_request("POST", f"/subscriptions/{current_user.subscription_id}/cancel", json_body={"cancel_at_cycle_end": 0})
    current_user.is_subscribed = False
    session.add(current_user)
    session.commit()
    log_audit(session, current_user.email, "subscription_cancelled_by_user")
    return {"status": "success", "message": "Subscription cancelled. Your commission rate reverts to the standard rate."}


# --- ADMIN: ALGORITHM DATA CENTER ---
@app.get("/api/admin/algorithm/listings")
def admin_view_all_listings(session: Session = Depends(get_session), _: bool = Depends(verify_admin)):
    """Raw view of every listing's structured matching data — lets you inspect
    exactly what the algorithm sees, not just the polished frontend view."""
    listings = session.exec(select(MarketplaceListing)).all()
    return listings

@app.get("/api/admin/algorithm/score-pair")
def admin_score_pair(viewer_listing_id: int, candidate_listing_id: int, session: Session = Depends(get_session), _: bool = Depends(verify_admin)):
    """Manually compute and inspect the match score between any two specific
    listings, with the FULL per-factor breakdown (weight/earned/applicable for every
    factor, plus the reliability signal used) — useful for verifying the algorithm
    behaves as expected on real or test data, and for debugging a surprising score."""
    viewer = session.get(MarketplaceListing, viewer_listing_id)
    candidate = session.get(MarketplaceListing, candidate_listing_id)
    if not viewer or not candidate:
        raise HTTPException(status_code=404, detail="One or both listings not found.")

    reliability_map = get_reliability_signals(session, {viewer.contact, candidate.contact})
    breakdown = compute_match_breakdown(viewer, candidate, reliability_map.get(candidate.contact))
    return {
        "viewer": {"id": viewer.id, "name": viewer.name, "role": viewer.role, "budget": [viewer.budget_min, viewer.budget_max], "audience_or_minimum": viewer.audience_size, "engagement_or_minimum": viewer.engagement_rate, "niches": viewer.niche_tags, "excluded_niches": viewer.excluded_niches, "location": viewer.location, "requires_local_presence": viewer.requires_local_presence, "interests": viewer.interests},
        "candidate": {"id": candidate.id, "name": candidate.name, "role": candidate.role, "budget": [candidate.budget_min, candidate.budget_max], "audience_or_minimum": candidate.audience_size, "engagement_or_minimum": candidate.engagement_rate, "niches": candidate.niche_tags, "location": candidate.location, "interests": candidate.interests, "verified": candidate.verified},
        "candidate_reliability_signal": reliability_map.get(candidate.contact),
        "breakdown": breakdown,
    }

@app.get("/api/admin/algorithm/stats")
def admin_algorithm_stats(session: Session = Depends(get_session), _: bool = Depends(verify_admin)):
    """High-level health check on the data actually feeding the algorithm —
    tells you how many listings have complete vs. missing matching data."""
    listings = session.exec(select(MarketplaceListing)).all()
    total = len(listings)
    with_full_data = sum(1 for l in listings if l.budget_max > 0 and l.audience_size > 0 and l.engagement_rate > 0 and l.niche_tags)
    with_location = sum(1 for l in listings if l.location.strip())
    with_interests = sum(1 for l in listings if l.interests.strip())
    anonymous_count = sum(1 for l in listings if l.is_anonymous)
    verified_count = sum(1 for l in listings if l.verified)
    with_brand_safety = sum(1 for l in listings if l.role == "sponsor" and l.excluded_niches.strip())
    requires_local = sum(1 for l in listings if l.role == "sponsor" and l.requires_local_presence)

    return {
        "total_listings": total,
        "listings_with_complete_mandatory_data": with_full_data,
        "listings_with_optional_location": with_location,
        "listings_with_optional_interests": with_interests,
        "anonymous_listings": anonymous_count,
        "verified_listings": verified_count,
        "unverified_listings": total - verified_count,
        "sponsors_with_brand_safety_exclusions": with_brand_safety,
        "sponsors_requiring_local_presence": requires_local,
        "sponsors": sum(1 for l in listings if l.role == "sponsor"),
        "influencers": sum(1 for l in listings if l.role == "influencer"),
    }

@app.post("/api/admin/listings/{listing_id}/verify")
def admin_set_listing_verified(listing_id: int, verified: bool = True, session: Session = Depends(get_session), _: bool = Depends(verify_admin)):
    """Explicitly grant (or revoke) SOCIA's 'Verified Reputator' badge on a listing.
    New listings default to verified=False (see MarketplaceListing.verified) — this is the
    only way a listing should become verified, replacing the old default-True behavior."""
    listing = session.get(MarketplaceListing, listing_id)
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found.")
    listing.verified = verified
    session.add(listing)
    session.commit()
    log_audit(session, listing.contact, "listing_verification_changed", f"listing_id={listing_id} verified={verified}")
    return {"status": "success", "listing_id": listing_id, "verified": listing.verified}
