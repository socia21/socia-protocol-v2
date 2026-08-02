Python
import os
import random
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlmodel import Field, SQLModel, Session, create_engine, select

# Environment Variables from Railway Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./socia_database.db")
EMAIL_USER = os.getenv("EMAIL_USER", "secure-dispatcher@socia.protocol")
EMAIL_PASS = os.getenv("EMAIL_PASS", "mock-smtp-password")

# Fix Postgres URL dialect for SQLModel/SQLAlchemy async/sync compatibility if needed
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
    
    # In production, dispatch email utilizing EMAIL_USER and EMAIL_PASS here via SMTP/SendGrid
    print(f"[SMTP DISPATCH MOCK] Sending OTP {generated_otp} to {payload.email} using account {EMAIL_USER}")

    user = UserAccount(
        email=payload.email,
        hashed_password=payload.password, # Note: Hash securely in production apps
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
        "message": f"OTP verification code dispatched to {payload.email}.",
        "debug_otp_hint": generated_otp
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