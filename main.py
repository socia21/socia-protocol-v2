import os
import random
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlmodel import Field, SQLModel, Session, create_engine, select
import resend

# Environment Variables
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./socia_database.db")
resend.api_key = os.getenv("RESEND_API_KEY", "re_your_api_key_here")

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, echo=True)

# --- DATABASE MODELS ---
class UserAccount(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    role: str  # 'sponsor' or 'influencer'
    display_name: str
    handle: str
    is_verified: bool = Field(default=False)
    otp_code: Optional[str] = Field(default=None)
    
    company_name: Optional[str] = Field(default=None)
    billing_address: Optional[str] = Field(default=None)
    tax_id: Optional[str] = Field(default=None)
    payout_details: Optional[str] = Field(default=None)
    notification_preferences: Optional[str] = Field(default="all")
    avatar_url: Optional[str] = Field(default=None)

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
    verified: bool = Field(default=True)

class DealLedgerRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    deal_ref: str
    counterparty: str
    amount: float
    status: str = Field(default="Pending")

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

app = FastAPI(title="SOCIA Protocol Institutional Backend", version="1.4.0")

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

# --- HELPER: HTTPS API EMAIL DISPATCHER WITH CONSOLE FALLBACK ---
def send_otp_email(recipient_email: str, otp_code: str):
    print(f"\n==========================================")
    print(f"[OTP DEBUG BACKUP] Code for {recipient_email}: {otp_code}")
    print(f"==========================================\n")
    
    try:
        params = {
            "from": "SOCIA Protocol <onboarding@resend.dev>",
            "to": [recipient_email],
            "subject": "Your SOCIA Protocol Verification Code",
            "html": f"""
            <div style="font-family: Arial, sans-serif; padding: 20px; background: #0f172a; color: #f8fafc; border-radius: 8px;">
                <h2 style="color: #38bdf8;">SOCIA Protocol Authentication</h2>
                <p>Your secure verification code is:</p>
                <div style="font-size: 32px; font-weight: bold; background: #1e293b; color: #38bdf8; padding: 12px 24px; display: inline-block; border-radius: 6px; letter-spacing: 4px;">{otp_code}</div>
                <p style="margin-top: 20px; font-size: 12px; color: #94a3b8;">If you did not request this verification, please ignore this transmission.</p>
            </div>
            """,
        }
        response = resend.Emails.send(params)
        print(f"[RESEND SUCCESS] OTP dispatched via HTTPS API to {recipient_email}: {response}")
    except Exception as e:
        print(f"[NETWORK WARNING] Could not reach external email server: {str(e)}. Continuing execution via console fallback.")

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

class PasswordChangeRequest(BaseModel):
    email: EmailStr
    old_password: str
    new_password: str

class UserSettingsUpdate(BaseModel):
    email: EmailStr
    new_email: Optional[EmailStr] = None
    display_name: Optional[str] = None
    handle: Optional[str] = None
    company_name: Optional[str] = None
    billing_address: Optional[str] = None
    tax_id: Optional[str] = None
    payout_details: Optional[str] = None
    notification_preferences: Optional[str] = None

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

# --- ENDPOINTS ---
@app.post("/auth/register")
def register_user(payload: RegisterRequest, session: Session = Depends(get_session)):
    existing = session.exec(select(UserAccount).where(UserAccount.email == payload.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Account with this email already registered.")
    
    generated_otp = str(random.randint(100000, 999999))
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
        "message": f"Verification code successfully initiated for {payload.email}. Check console/inbox."
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
    
    return {"status": "success", "message": "Account successfully verified and activated in database."}

@app.post("/auth/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(UserAccount).where(UserAccount.email == form_data.username)).first()
    if not user or user.hashed_password != form_data.password:
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
    return {"access_token": f"socia-token-{user.email}", "token_type": "bearer"}

@app.post("/auth/change-password")
def change_password(payload: PasswordChangeRequest, session: Session = Depends(get_session)):
    user = session.exec(select(UserAccount).where(UserAccount.email == payload.email)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")
    
    if user.hashed_password != payload.old_password:
        raise HTTPException(status_code=400, detail="Incorrect existing password.")
    
    user.hashed_password = payload.new_password
    session.add(user)
    session.commit()
    
    return {"status": "success", "message": "Password successfully updated."}

@app.get("/api/account/settings")
def get_account_settings(email: str, session: Session = Depends(get_session)):
    user = session.exec(select(UserAccount).where(UserAccount.email == email)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User registry record not found.")
    return {
        "email": user.email,
        "role": user.role,
        "display_name": user.display_name,
        "handle": user.handle,
        "is_verified": user.is_verified,
        "avatar_url": user.avatar_url,
        "private_details": {
            "company_name": user.company_name,
            "billing_address": user.billing_address,
            "tax_id": user.tax_id,
            "payout_details": user.payout_details,
            "notification_preferences": user.notification_preferences
        }
    }

@app.put("/api/account/settings")
def update_account_settings(payload: UserSettingsUpdate, session: Session = Depends(get_session)):
    user = session.exec(select(UserAccount).where(UserAccount.email == payload.email)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")
    
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
    if payload.billing_address is not None:
        user.billing_address = payload.billing_address
    if payload.tax_id is not None:
        user.tax_id = payload.tax_id
    if payload.payout_details is not None:
        user.payout_details = payload.payout_details
    if payload.notification_preferences is not None:
        user.notification_preferences = payload.notification_preferences
        
    session.add(user)
    session.commit()
    session.refresh(user)
    
    return {"status": "success", "message": "Private account settings updated successfully."}

@app.post("/api/account/upload-avatar")
async def upload_avatar(email: str, file: UploadFile = File(...), session: Session = Depends(get_session)):
    user = session.exec(select(UserAccount).where(UserAccount.email == email)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")
    
    upload_dir = "./uploads"
    os.makedirs(upload_dir, exist_ok=True)
    
    file_extension = file.filename.split(".")[-1]
    file_name = f"avatar_{user.id}_{random.randint(1000, 9999)}.{file_extension}"
    file_path = os.path.join(upload_dir, file_name)
    
    with open(file_path, "wb") as buffer:
        content = await file.read()
        buffer.write(content)
        
    user.avatar_url = f"/{file_path}"
    session.add(user)
    session.commit()
    
    return {"status": "success", "avatar_url": user.avatar_url, "message": "File uploaded and avatar updated successfully."}

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