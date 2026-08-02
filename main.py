import os
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlmodel import Field, SQLModel, Session, create_engine, select

# Environment Variables or Direct Fallbacks for Outlook Credentials
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./socia_database.db")
EMAIL_USER = os.getenv("EMAIL_USER", "socia2121@outlook.com")
EMAIL_PASS = os.getenv("EMAIL_PASS", "riaanisriaan21")

# Fix Postgres URL dialect for SQLModel/SQLAlchemy compatibility if needed
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, echo=True)

# --- DATABASE MODELS ---
class UserAccount(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    role: str # 'sponsor' or 'influencer'
    display_name: str
    handle: str
    is_verified: bool = Field(default=False)
    otp_code: Optional[str] = Field(default=None)

class MarketplaceListing(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    contact: str
    name: str
    role: str
    industry: str
    rates: str
    stats: str
    bio: str
    pre_conditions_str: str # comma separated
    match_score: int = Field(default=98)
    verified: bool = Field(default=True)

class DealLedgerRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    deal_ref: str
    counterparty: str
    amount: float
    status: str = Field(default="Pending")

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

app = FastAPI(title="SOCIA Protocol Institutional Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

# --- HELPER: REAL OUTLOOK SMTP EMAIL DISPATCHER ---
def send_otp_email(recipient_email: str, otp_code: str):
    smtp_server = "smtp-mail.outlook.com"
    smtp_port = 587
    
    message = MIMEMultipart("alternative")
    message["Subject"] = "Your SOCIA Protocol Verification Code"
    message["From"] = EMAIL_USER
    message["To"] = recipient_email
    
    text = f"Welcome to SOCIA Protocol.\n\nYour account verification code is: {otp_code}\n\nPlease enter this code to activate your institutional profile."
    html = f"""
    <div style="font-family: Arial, sans-serif; padding: 20px; background: #0f172a; color: #f8fafc; border-radius: 8px;">
        <h2 style="color: #38bdf8;">SOCIA Protocol Authentication</h2>
        <p>Your secure verification code is:</p>
        <div style="font-size: 32px; font-weight: bold; background: #1e293b; color: #38bdf8; padding: 12px 24px; display: inline-block; border-radius: 6px; letter-spacing: 4px;">{otp_code}</div>
        <p style="margin-top: 20px; font-size: 12px; color: #94a3b8;">If you did not request this verification, please ignore this transmission.</p>
    </div>
    """
    
    message.attach(MIMEText(text, "plain"))
    message.attach(MIMEText(html, "html"))
    
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, recipient_email, message.as_string())
        print(f"[SMTP SUCCESS] OTP email successfully sent to {recipient_email}")
    except Exception as e:
        print(f"[SMTP ERROR] Failed to send email via Outlook: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to dispatch verification email: {str(e)}")

# --- SCHEMAS ---
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    role: str
    display_name: str
    handle: str

class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp_code: str

class ListingCreate(BaseModel):
    contact: str
    name: str
    role: str
    industry: str
    rates: str
    stats: str
    bio: str
    pre_conditions: List[str]

class DealSimulationRequest(BaseModel):
    sponsor_contact: str
    influencer_name: str
    amount: float
    conditions: List[str]

# --- AUTHENTICATION & REGISTRATION ENDPOINTS ---
@app.post("/auth/register")
def register_user(payload: RegisterRequest, session: Session = Depends(get_session)):
    existing = session.exec(select(UserAccount).where(UserAccount.email == payload.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Account with this email already registered.")
    
    generated_otp = str(random.randint(100000, 999999))
    
    # Trigger actual Outlook email sending
    send_otp_email(payload.email, generated_otp)

    user = UserAccount(
        email=payload.email,
        hashed_password=payload.password,
        role=payload.role,
        display_name=payload.display_name,
        handle=payload.handle,
        is_verified=False,
        otp_code=generated_otp
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    
    return {
        "status": "pending_verification",
        "message": f"OTP verification code successfully dispatched via Outlook to {payload.email}."
    }

@app.post("/auth/verify-otp")
def verify_otp(payload: VerifyOTPRequest, session: Session = Depends(get_session)):
    user = session.exec(select(UserAccount).where(UserAccount.email == payload.email)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")
    
    if user.otp_code != payload.otp_code:
        raise HTTPException(status_code=400, detail="Invalid OTP verification code.")
    
    user.is_verified = True
    user.otp_code = None
    session.add(user)
    session.commit()
    
    return {"status": "success", "message": "Account successfully verified and activated."}

@app.post("/auth/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(UserAccount).where(UserAccount.email == form_data.username)).first()
    if not user or user.hashed_password != form_data.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"access_token": f"socia-token-{user.email}", "token_type": "bearer"}

# --- MARKETPLACE & LISTING REGISTRY ---
@app.post("/api/register")
def create_listing(payload: ListingCreate, session: Session = Depends(get_session)):
    cond_str = ", ".join(payload.pre_conditions)
    listing = MarketplaceListing(
        contact=payload.contact,
        name=payload.name,
        role=payload.role,
        industry=payload.industry,
        rates=payload.rates,
        stats=payload.stats,
        bio=payload.bio,
        pre_conditions_str=cond_str
    )
    session.add(listing)
    session.commit()
    return {"status": "success", "message": "Listing published successfully to protocol database."}

@app.get("/api/marketplace")
def get_marketplace_listings(role: str, session: Session = Depends(get_session)):
    results = session.exec(select(MarketplaceListing).where(MarketplaceListing.role == role)).all()
    formatted = []
    for r in results:
        formatted.append({
            "name": r.name,
            "role": r.role,
            "industry": r.industry,
            "rates": r.rates,
            "stats": r.stats,
            "bio": r.bio,
            "preConditions": [c.strip() for c in r.pre_conditions_str.split(",")],
            "match": r.match_score,
            "verified": r.verified
        })
    return formatted

# --- ESCROW & DEALS LEDGER ---
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
def get_deal_history(session: Session = Depends(get_session)):
    deals = session.exec(select(DealLedgerRecord)).all()
    return deals