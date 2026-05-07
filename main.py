from fastapi import FastAPI, Depends, HTTPException, status, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from sqlalchemy import create_engine, Column, String, Text, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import pandas as pd
from fastapi.responses import StreamingResponse
import io
import jwt
import datetime
import bcrypt
import os
from dotenv import load_dotenv
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# --- 1. TẢI BIẾN MÔI TRƯỜNG ---
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("⛔ Thiếu SECRET_KEY trong file .env! Vui lòng tạo file .env từ .env.example")

ALGORITHM = "HS256"

# --- 2. CẤU HÌNH DATABASE ---
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("⛔ Thiếu DATABASE_URL trong môi trường!")

# Fix lỗi SQLAlchemy nếu url bắt đầu bằng postgres:// thay vì postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- 3. CẤU HÌNH RATE LIMITER ---
limiter = Limiter(key_func=get_remote_address)

# --- 4. ĐỊNH NGHĨA DATABASE ---
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    security_question = Column(String, nullable=True)  # Cột mới: Câu hỏi bảo mật
    security_answer = Column(String, nullable=True)    # Cột mới: Câu trả lời bảo mật

class MemberDB(Base):
    __tablename__ = "members"
    id = Column(String, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    name = Column(String)
    gender = Column(String)
    title = Column(String, nullable=True)
    birth = Column(String, nullable=True)
    death = Column(String, nullable=True)
    spouse = Column(String, nullable=True)
    desc = Column(Text, nullable=True)
    parentId = Column(String, nullable=True)
    avatar = Column(Text, nullable=True)  # Lưu ảnh dạng base64

Base.metadata.create_all(bind=engine)

app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# --- 5. HÀM HỖ TRỢ XÁC THỰC ---
def verify_password(plain_password, hashed_password):
    password_bytes = plain_password[:72].encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    try: return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception: return False

def get_password_hash(password):
    password_bytes = password[:72].encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(days=7)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(authorization: str = Header(None)):
    credentials_exception = HTTPException(status_code=401, detail="Token không hợp lệ")
    if not authorization or not authorization.startswith("Bearer "):
        raise credentials_exception
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None: raise credentials_exception
        return int(user_id)
    except jwt.PyJWTError:
        raise credentials_exception

# --- 6. SCHEMAS ---
class UserAuth(BaseModel):
    username: str
    password: str

class UserRegister(BaseModel):
    username: str
    password: str
    security_question: str
    security_answer: str

class UserReset(BaseModel):
    username: str
    new_password: str
    security_answer: str

class UserChangePassword(BaseModel):
    old_password: str
    new_password: str

class MemberCreate(BaseModel):
    id: str
    name: str
    gender: str
    title: Optional[str] = None
    birth: Optional[str] = None
    death: Optional[str] = None
    spouse: Optional[str] = None
    desc: Optional[str] = None
    parentId: Optional[str] = None
    avatar: Optional[str] = None

# --- 7. API ACCOUNT & XÁC THỰC ---
@app.post("/register")
@limiter.limit("5/minute")
def register(request: Request, user: UserRegister, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if db_user: raise HTTPException(status_code=400, detail="Tên đăng nhập đã tồn tại")
    
    hashed_pwd = get_password_hash(user.password)
    new_user = UserDB(
        username=user.username, 
        password_hash=hashed_pwd,
        security_question=user.security_question,
        security_answer=user.security_answer.lower().strip() # Lưu chữ thường để dễ bề so sánh sau này
    )
    db.add(new_user)
    db.commit()
    return {"message": "Đăng ký thành công!"}

@app.post("/login")
@limiter.limit("10/minute")  
def login(request: Request, user: UserAuth, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Sai tài khoản hoặc mật khẩu")
    token = create_access_token(data={"sub": str(db_user.id)})
    return {"access_token": token, "username": db_user.username}

@app.get("/security-question/{username}")
@limiter.limit("10/minute")
def get_security_question(request: Request, username: str, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.username == username).first()
    if not db_user: 
        raise HTTPException(status_code=404, detail="Tài khoản không tồn tại!")
    if not db_user.security_question:
        raise HTTPException(status_code=400, detail="Tài khoản này chưa cài đặt câu hỏi bảo mật!")
    return {"question": db_user.security_question}

@app.post("/reset-password")
@limiter.limit("5/minute")
def reset_password(request: Request, user_reset: UserReset, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.username == user_reset.username).first()
    if not db_user: 
        raise HTTPException(status_code=404, detail="Tài khoản không tồn tại!")
    
    # Kiểm tra câu trả lời (chuẩn hóa về chữ thường và bỏ khoảng trắng 2 đầu)
    if db_user.security_answer != user_reset.security_answer.lower().strip():
        raise HTTPException(status_code=400, detail="Câu trả lời bảo mật không chính xác!")
    
    # Mã hóa và cập nhật mật khẩu mới
    hashed_pwd = get_password_hash(user_reset.new_password)
    db_user.password_hash = hashed_pwd
    db.commit()
    
    return {"message": "Đổi mật khẩu thành công!"}

@app.post("/change-password")
@limiter.limit("5/minute")
def change_password(
    request: Request,
    payload: UserChangePassword,
    db: Session = Depends(get_db),
    current_user_id: int = Depends(get_current_user)
):
    db_user = db.query(UserDB).filter(UserDB.id == current_user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Tài khoản không tồn tại!")

    # Kiểm tra mật khẩu cũ
    if not verify_password(payload.old_password, db_user.password_hash):
        raise HTTPException(status_code=400, detail="Mật khẩu hiện tại không chính xác!")

    # Cập nhật mật khẩu mới
    db_user.password_hash = get_password_hash(payload.new_password)
    db.commit()
    return {"message": "Đổi mật khẩu thành công!"}

# --- 8. API GIA PHẢ ---
@app.get("/get-members", response_model=List[MemberCreate])
def get_members(db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user)):
    return db.query(MemberDB).filter(MemberDB.owner_id == current_user_id).all()

@app.post("/add-member")
def add_member(member: MemberCreate, db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user)):
    db_member = db.query(MemberDB).filter(MemberDB.id == member.id, MemberDB.owner_id == current_user_id).first()
    member_data = member.model_dump()
    if db_member:
        for key, value in member_data.items(): setattr(db_member, key, value)
    else:
        new_member = MemberDB(**member_data, owner_id=current_user_id)
        db.add(new_member)
    db.commit()
    return {"status": "Đã lưu"}

@app.delete("/delete-member/{member_id}")
def delete_member(member_id: str, db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user)):
    db_member = db.query(MemberDB).filter(MemberDB.id == member_id, MemberDB.owner_id == current_user_id).first()
    if not db_member: return {"error": "Không có quyền xóa"}
    db.delete(db_member)
    db.commit()
    return {"status": "Đã xóa"}

@app.get("/export-excel")
def export_excel(db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user)):
    members = db.query(MemberDB).filter(MemberDB.owner_id == current_user_id).all()
    data = [{"ID": m.id, "Họ và Tên": m.name, "Giới tính": "Nam" if m.gender == "M" else "Nữ", "Vai vế": m.title, "Năm sinh": m.birth, "Năm mất": m.death, "Vợ/Chồng": m.spouse, "Ghi chú": m.desc} for m in members]
    df = pd.DataFrame(data)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer: df.to_excel(writer, index=False, sheet_name='Gia_Pha')
    output.seek(0)
    return StreamingResponse(output, headers={'Content-Disposition': 'attachment; filename="Gia_Pha.xlsx"'}, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')