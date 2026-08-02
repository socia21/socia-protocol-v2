import os
from typing import List
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3

app = FastAPI(title="SOCIA Protocol Institutional Backend", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "socia_protocol.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            name TEXT,
            role TEXT,
            industry TEXT,
            rates TEXT,
            stats TEXT,
            bio TEXT,
            pre_conditions TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS deals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            deal_ref TEXT,
            counterparty TEXT,
            amount REAL,
            status TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

class UserRegistration(BaseModel):
    contact: str
    name: str
    role: str
    industry: str
    rates: str
    stats: str
    bio: str
    pre_conditions: List[str]

class DealSimulation(BaseModel):
    sponsor_contact: str
    influencer_name: str
    amount: float
    conditions: List[str]

@app.get("/")
def read_root():
    return {"status": "online", "protocol": "SOCIA Sovereign Escrow Active (v2)"}

@app.post("/api/register")
def register_user(data: UserRegistration):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT OR REPLACE INTO users (email, name, role, industry, rates, stats, bio, pre_conditions)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.contact, data.name, data.role, data.industry,
            data.rates, data.stats, data.bio, ",".join(data.pre_conditions)
        ))
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()
    return {"success": True, "message": "User registered successfully."}

@app.get("/api/marketplace")
def get_marketplace(role: str = Query(...)):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT name, role, industry, rates, stats, bio, pre_conditions FROM users WHERE role = ?", (role,))
    rows = cursor.fetchall()
    conn.close()

    return [{
        "name": r[0], "role": r[1], "industry": r[2], "rates": r[3],
        "stats": r[4], "bio": r[5], "preConditions": r[6].split(",") if r[6] else [],
        "match": 98, "verified": True
    } for r in rows]

@app.post("/api/deals/simulate")
def simulate_deal(data: DealSimulation):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    deal_ref = f"SOCIA-ESCROW-{os.urandom(3).hex().upper()}"
    cursor.execute("""
        INSERT INTO deals (deal_ref, counterparty, amount, status)
        VALUES (?, ?, ?, ?)
    """, (deal_ref, data.influencer_name, data.amount, "Escrow Active"))
    conn.commit()
    conn.close()
    return {"success": True, "deal_ref": deal_ref}

@app.get("/api/deals/history")
def get_deal_history():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT deal_ref, counterparty, amount, status FROM deals")
    rows = cursor.fetchall()
    conn.close()

    return [{"deal_ref": r[0], "counterparty": r[1], "amount": r[2], "status": r[3]} for r in rows]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))

import os
import uvicorn

if __name__ == "__main__":
  port = int(os.environ.get("PORT", 8000))
  print(f"Starting application on host '::' and port {port}")
  uvicorn.run("main:app", host="::", port=port)