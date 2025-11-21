import os
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from email_validator import validate_email, EmailNotValidError
from bson import ObjectId

from database import db, create_document, get_documents

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utilities

def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def get_collection(name: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    return db[name]


# Auth models
class SignupBody(BaseModel):
    email: str
    password: str
    name: Optional[str] = None


class LoginBody(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    token: str
    role: str
    user_id: str
    email: str
    name: Optional[str] = None


class ValidateRequest(BaseModel):
    emails: List[str]


# Password hashing (simple pbkdf2)
import hashlib, secrets


def hash_password(password: str, salt: Optional[str] = None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200000)
    return dk.hex(), salt


# Token generation

def create_token() -> str:
    return secrets.token_urlsafe(32)


async def get_current_user(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    sessions = get_collection("session")
    s = sessions.find_one({"token": token, "revoked": False})
    if not s:
        raise HTTPException(status_code=401, detail="Invalid token")
    if s.get("expires_at") and datetime.utcnow() > s["expires_at"]:
        raise HTTPException(status_code=401, detail="Token expired")
    user = get_collection("appuser").find_one({"_id": s["user_id"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@app.get("/")
def read_root():
    return {"message": "Email Validator API"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        from database import db as _db

        if _db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = _db.name if hasattr(_db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = _db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"

    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    return response


# Auth endpoints
@app.post("/auth/signup", response_model=TokenResponse)
def signup(body: SignupBody):
    users = get_collection("appuser")
    if users.find_one({"email": body.email.lower()}):
        raise HTTPException(status_code=400, detail="Email already registered")
    pw_hash, salt = hash_password(body.password)
    user_doc = {
        "email": body.email.lower(),
        "name": body.name,
        "password_hash": pw_hash,
        "password_salt": salt,
        "role": "user",
        "is_active": True,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    result = users.insert_one(user_doc)
    token = create_token()
    get_collection("session").insert_one({
        "user_id": result.inserted_id,
        "token": token,
        "revoked": False,
        "expires_at": datetime.utcnow() + timedelta(days=7),
    })
    return TokenResponse(token=token, role="user", user_id=str(result.inserted_id), email=user_doc["email"], name=user_doc.get("name"))


@app.post("/auth/login", response_model=TokenResponse)
def login(body: LoginBody):
    users = get_collection("appuser")
    user = users.find_one({"email": body.email.lower()})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    calc_hash, _ = hash_password(body.password, user.get("password_salt"))
    if calc_hash != user.get("password_hash"):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token()
    get_collection("session").insert_one({
        "user_id": user["_id"],
        "token": token,
        "revoked": False,
        "expires_at": datetime.utcnow() + timedelta(days=7),
    })
    return TokenResponse(token=token, role=user.get("role", "user"), user_id=str(user["_id"]), email=user["email"], name=user.get("name"))


@app.post("/auth/logout")
def logout(user=Depends(get_current_user), authorization: Optional[str] = Header(default=None)):
    token = authorization.split(" ", 1)[1]
    get_collection("session").update_one({"token": token}, {"$set": {"revoked": True}})
    return {"ok": True}


# Email validation endpoints
@app.post("/validate")
def validate_emails(req: ValidateRequest, user=Depends(get_current_user)):
    results = []
    coll = get_collection("emailcheck")
    for e in req.emails:
        e_l = e.strip().lower()
        status = "unknown"
        result = {
            "email": e_l,
            "status": "unknown",
            "reason": None,
            "deliverable": None,
            "suggestions": None,
            "is_disposable": None,
        }
        try:
            v = validate_email(e_l, check_deliverability=True)
            result["email"] = v.email
            result["status"] = "valid"
            result["deliverable"] = True
            result["is_disposable"] = v.disposable
            if v.domain_suggest:
                result["suggestions"] = [v.domain_suggest]
        except EmailNotValidError as err:
            result["status"] = "invalid"
            result["deliverable"] = False
            result["reason"] = str(err)
        finally:
            doc = {
                "user_id": user["_id"],
                **result,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
            }
            coll.insert_one(doc)
            results.append({**result})
    return {"results": results}


@app.get("/my/validations")
def my_validations(user=Depends(get_current_user)):
    coll = get_collection("emailcheck")
    items = list(coll.find({"user_id": user["_id"]}).sort("created_at", -1).limit(200))
    for it in items:
        it["_id"] = str(it["_id"])    
        it["user_id"] = str(it["user_id"])    
    return {"items": items}


# Admin endpoints
@app.get("/admin/stats")
def admin_stats(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    users = get_collection("appuser").count_documents({})
    checks = get_collection("emailcheck").count_documents({})
    valid = get_collection("emailcheck").count_documents({"status": "valid"})
    invalid = get_collection("emailcheck").count_documents({"status": "invalid"})
    return {
        "users": users,
        "checks": checks,
        "valid": valid,
        "invalid": invalid,
    }


@app.get("/admin/users")
def admin_users(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    items = list(get_collection("appuser").find({}, {"password_hash": 0, "password_salt": 0}).sort("created_at", -1))
    for it in items:
        it["_id"] = str(it["_id"])    
    return {"items": items}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
