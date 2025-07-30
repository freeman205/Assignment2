"""
Complete Reward System API - All-in-One Server
Run with: python server.py
"""

import os
import secrets
import string
import smtplib
import hashlib
from datetime import datetime, timedelta
from decimal import Decimal
from typing import List, Optional
from enum import Enum
import pytz # Import pytz for timezone handling

# FastAPI and related imports
from fastapi import FastAPI, Depends, HTTPException, status, Request, Query
from fastapi.security import HTTPBearer
from fastapi.middleware.cors import CORSMiddleware

# Database imports
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, UniqueConstraint, create_engine, and_, or_, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, Session
from sqlalchemy.types import DECIMAL as SQLDecimal

# Authentication imports
from passlib.context import CryptContext
from jose import JWTError, jwt

# Email imports
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Pydantic imports
from pydantic import BaseModel, EmailStr, validator

# =============================================================================
# CONFIGURATION & CONSTANTS
# =============================================================================

# Database Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost:5432/reward_system")

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-jwt-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Email Configuration
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "your-email@gmail.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "your-app-password")
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USERNAME)
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")

# =============================================================================
# DATABASE MODELS
# =============================================================================

Base = declarative_base()

class UserStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    SUSPENDED = "suspended"
    REJECTED = "rejected"

class RedemptionStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    PROCESSED = "processed"

class RedemptionType(str, Enum):
    BITCOIN = "bitcoin"
    GIFT_CARD = "gift_card"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    pin_hash = Column(String, nullable=False)
    status = Column(String, default=UserStatus.PENDING)
    is_admin = Column(Boolean, default=False)
    is_agent = Column(Boolean, default=False)
    points_balance = Column(SQLDecimal(10, 2), default=0)
    referral_code = Column(String, unique=True, nullable=True)
    referred_by_code = Column(String, nullable=True)
    email_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    devices = relationship("UserDevice", back_populates="user")
    sent_transfers = relationship("PointTransfer", foreign_keys="PointTransfer.from_user_id", back_populates="from_user")
    received_transfers = relationship("PointTransfer", foreign_keys="PointTransfer.to_user_id", back_populates="to_user")
    redemptions = relationship("Redemption", back_populates="user", foreign_keys="Redemption.user_id")
    approvals = relationship("UserApproval", back_populates="user", foreign_keys="UserApproval.user_id")

class UserDevice(Base):
    __tablename__ = "user_devices"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    device_fingerprint = Column(String, nullable=False)
    ip_address = Column(String, nullable=False)
    user_agent = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    user = relationship("User", back_populates="devices")
    
    __table_args__ = (UniqueConstraint('user_id', 'device_fingerprint', name='unique_user_device'),)

class OTP(Base):
    __tablename__ = "otps"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, nullable=False)
    otp_code = Column(String, nullable=False)
    purpose = Column(String, nullable=False)  # signup, password_reset, pin_reset
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class PointTransfer(Base):
    __tablename__ = "point_transfers"
    
    id = Column(Integer, primary_key=True, index=True)
    from_user_id = Column(Integer, ForeignKey("users.id"))
    to_user_id = Column(Integer, ForeignKey("users.id"))
    amount = Column(SQLDecimal(10, 2), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    from_user = relationship("User", foreign_keys=[from_user_id], back_populates="sent_transfers")
    to_user = relationship("User", foreign_keys=[to_user_id], back_populates="received_transfers")

class Survey(Base):
    __tablename__ = "surveys"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    points_reward = Column(SQLDecimal(10, 2), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class UserSurvey(Base):
    __tablename__ = "user_surveys"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    survey_id = Column(Integer, ForeignKey("surveys.id"))
    points_earned = Column(SQLDecimal(10, 2), nullable=False)
    completed_at = Column(DateTime(timezone=True), server_default=func.now())
    
    __table_args__ = (UniqueConstraint('user_id', 'survey_id', name='unique_user_survey'),)

class Redemption(Base):
    __tablename__ = "redemptions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    type = Column(String, nullable=False)  # bitcoin, gift_card
    points_amount = Column(SQLDecimal(10, 2), nullable=False)
    equivalent_value = Column(SQLDecimal(10, 8), nullable=False)
    wallet_address = Column(String, nullable=True)  # For Bitcoin
    email_address = Column(String, nullable=True)  # For Gift Cards
    status = Column(String, default=RedemptionStatus.PENDING)
    processed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    processed_at = Column(DateTime(timezone=True), nullable=True)
    
    user = relationship("User", foreign_keys=[user_id], back_populates="redemptions")

class UserApproval(Base):
    __tablename__ = "user_approvals"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    status = Column(String, nullable=False)
    approval_token = Column(String, unique=True, nullable=True)  # For email approval
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    user = relationship("User", foreign_keys=[user_id], back_populates="approvals")

class SystemSettings(Base):
    __tablename__ = "system_settings"
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, nullable=False)
    value = Column(String, nullable=False)
    description = Column(Text)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class ActivityLog(Base):
    __tablename__ = "activity_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String, nullable=False)
    details = Column(Text)
    ip_address = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

# =============================================================================
# PYDANTIC SCHEMAS
# =============================================================================

# User Schemas
class UserBase(BaseModel):
    email: EmailStr
    name: str

class UserCreate(UserBase):
    password: str
    pin: str
    referral_code: Optional[str] = None
    device_fingerprint: str
    ip_address: str
    user_agent: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserPinVerify(BaseModel):
    pin: str

class UserResponse(UserBase):
    id: int
    status: UserStatus
    is_admin: bool
    is_agent: bool
    points_balance: Decimal
    referral_code: Optional[str]
    email_verified: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

# OTP Schemas
class OTPRequest(BaseModel):
    email: EmailStr
    purpose: str  # signup, password_reset, pin_reset

class OTPVerify(BaseModel):
    email: EmailStr
    otp_code: str
    purpose: str

# Point Transfer Schemas
class PointTransferCreate(BaseModel):
    to_email: EmailStr
    amount: Decimal
    
    @validator('amount')
    def amount_must_be_positive(cls, v):
        if v <= 0:
            raise ValueError('Amount must be positive')
        return v

class PointTransferResponse(BaseModel):
    id: int
    from_user_id: int
    to_user_id: int
    amount: Decimal
    created_at: datetime
    
    class Config:
        from_attributes = True

# Redemption Schemas
class RedemptionCreate(BaseModel):
    type: RedemptionType
    points_amount: Decimal
    wallet_address: Optional[str] = None
    email_address: Optional[EmailStr] = None
    
    @validator('wallet_address')
    def validate_bitcoin_address(cls, v, values):
        if values.get('type') == RedemptionType.BITCOIN and not v:
            raise ValueError('Wallet address required for Bitcoin redemption')
        return v
    
    @validator('email_address')
    def validate_gift_card_email(cls, v, values):
        if values.get('type') == RedemptionType.GIFT_CARD and not v:
            raise ValueError('Email address required for Gift Card redemption')
        return v

class RedemptionResponse(BaseModel):
    id: int
    type: RedemptionType
    points_amount: Decimal
    equivalent_value: Decimal
    status: RedemptionStatus
    created_at: datetime
    
    class Config:
        from_attributes = True

# Admin Schemas
class UserStatusUpdate(BaseModel):
    status: UserStatus

class AgentAssignment(BaseModel):
    user_id: int
    is_agent: bool

class SystemSettingUpdate(BaseModel):
    key: str
    value: str
    description: Optional[str] = None

# Survey Schemas
class SurveyCreate(BaseModel):
    title: str
    description: Optional[str] = None
    points_reward: Decimal

class SurveyResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    points_reward: Decimal
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

# Dashboard Schemas
class DashboardStats(BaseModel):
    points_balance: Decimal
    completed_surveys: int
    total_earned: Decimal
    pending_redemptions: int

class TransferHistory(BaseModel):
    transfers: List[PointTransferResponse]
    total_sent: Decimal
    total_received: Decimal

# =============================================================================
# DATABASE SETUP
# =============================================================================

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def create_tables():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =============================================================================
# AUTHENTICATION UTILITIES
# =============================================================================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
        return email
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

def generate_otp():
    return ''.join(secrets.choice(string.digits) for _ in range(6))

def generate_referral_code():
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

def generate_approval_token():
    return secrets.token_urlsafe(32)

# =============================================================================
# EMAIL SERVICE
# =============================================================================

class EmailService:
    def __init__(self):
        self.smtp_server = SMTP_SERVER
        self.smtp_port = SMTP_PORT
        self.smtp_username = SMTP_USERNAME
        self.smtp_password = SMTP_PASSWORD
        self.from_email = FROM_EMAIL

    def send_email(self, to_email: str, subject: str, body: str, is_html: bool = False):
        try:
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = to_email
            msg['Subject'] = subject

            msg.attach(MIMEText(body, 'html' if is_html else 'plain'))

            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.smtp_username, self.smtp_password)
            text = msg.as_string()
            server.sendmail(self.from_email, to_email, text)
            server.quit()
            return True
        except Exception as e:
            print(f"Failed to send email: {e}")
            return False

    def send_otp_email(self, to_email: str, otp_code: str, purpose: str):
        subject = f"Your OTP Code for {purpose.replace('_', ' ').title()}"
        body = f"""
        <html>
        <body>
            <h2>Your OTP Code</h2>
            <p>Your OTP code is: <strong>{otp_code}</strong></p>
            <p>This code will expire in 10 minutes.</p>
            <p>If you didn't request this code, please ignore this email.</p>
        </body>
        </html>
        """
        return self.send_email(to_email, subject, body, is_html=True)

    def send_agent_approval_email(self, agent_email: str, user_name: str, user_email: str, approval_token: str):
        approve_url = f"{BASE_URL}/api/agent/approve/{approval_token}?action=approve"
        reject_url = f"{BASE_URL}/api/agent/approve/{approval_token}?action=reject"
        
        subject = "New User Approval Request"
        body = f"""
        <html>
        <body>
            <h2>New User Approval Request</h2>
            <p>A new user has signed up with your referral code:</p>
            <ul>
                <li><strong>Name:</strong> {user_name}</li>
                <li><strong>Email:</strong> {user_email}</li>
            </ul>
            <p>Please choose an action:</p>
            <p>
                <a href="{approve_url}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Approve User</a>
                <a href="{reject_url}" style="background-color: #f44336; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-left: 10px;">Reject User</a>
            </p>
        </body>
        </html>
        """
        return self.send_email(agent_email, subject, body, is_html=True)

email_service = EmailService()

# =============================================================================
# FASTAPI APPLICATION SETUP
# =============================================================================

app = FastAPI(
    title="Reward System API",
    description="Complete User Registration and Reward System",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000", # For local development of your frontend
        "http://localhost:8000", # If your frontend is also served from the same origin as backend
        "http://127.0.0.1:5500", # Common for Live Server in VS Code
        "https://testmy.netlify.app", # IMPORTANT: Replace with your actual Vercel frontend domain
        "https://surveyplatformforreward.vercel.app", # Example based on your repo name
        "http://localhost:10000" # Add this line to allow frontend on port 10000
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def create_default_data(db: Session):
    """Create default admin user and system settings"""
    # Create default admin if not exists
    admin = db.query(User).filter(User.email == "admin@example.com").first()
    if not admin:
        admin = User(
            email="admin@example.com",
            name="System Admin",
            password_hash=get_password_hash("admin123"),
            pin_hash=get_password_hash("0000"),
            status=UserStatus.APPROVED,
            is_admin=True,
            email_verified=True
        )
        db.add(admin)
    
    # Create default system settings
    settings = [
        ("point_to_btc_rate", "0.00001", "Points to Bitcoin conversion rate"),
        ("point_to_gift_rate", "0.01", "Points to Gift Card conversion rate (USD)"),
        ("survey_default_points", "100", "Default points for completing surveys"),
        ("max_devices_per_user", "3", "Maximum devices allowed per user"),
    ]
    
    for key, value, description in settings:
        setting = db.query(SystemSettings).filter(SystemSettings.key == key).first()
        if not setting:
            setting = SystemSettings(key=key, value=value, description=description)
            db.add(setting)
    
    db.commit()

def log_activity(db: Session, user_id: Optional[int], action: str, details: str, ip_address: str):
    """Log user activity"""
    log = ActivityLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=ip_address
    )
    db.add(log)

def get_system_setting(db: Session, key: str, default: str = "0"):
    """Get system setting value"""
    setting = db.query(SystemSettings).filter(SystemSettings.key == key).first()
    return setting.value if setting else default

# =============================================================================
# DEPENDENCY FUNCTIONS
# =============================================================================

def get_current_user(token: str = Depends(security), db: Session = Depends(get_db)):
    """Get current authenticated user"""
    email = verify_token(token.credentials)
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def get_admin_user(current_user: User = Depends(get_current_user)):
    """Ensure current user is admin"""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

def get_agent_user(current_user: User = Depends(get_current_user)):
    """Ensure current user is agent or admin"""
    if not (current_user.is_agent or current_user.is_admin):
        raise HTTPException(status_code=403, detail="Agent access required")
    return current_user

# =============================================================================
# STARTUP EVENT
# =============================================================================

@app.on_event("startup")
def startup_event():
    """Initialize database and default data on startup"""
    create_tables()
    db = next(get_db())
    create_default_data(db)
    print("🚀 Reward System API Started Successfully!")
    print(f"📧 Default Admin: admin@example.com / admin123 (PIN: 0000)")
    print(f"🌐 API Documentation: http://localhost:8000/docs")

# =============================================================================
# AUTHENTICATION ENDPOINTS
# =============================================================================

@app.post("/api/auth/request-otp")
def request_otp(otp_request: OTPRequest, db: Session = Depends(get_db)):
    """Request OTP for email verification"""
    # Delete old OTPs for this email and purpose
    db.query(OTP).filter(
        and_(OTP.email == otp_request.email, OTP.purpose == otp_request.purpose)
    ).delete()
    
    otp_code = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    otp = OTP(
        email=otp_request.email,
        otp_code=otp_code,
        purpose=otp_request.purpose,
        expires_at=expires_at
    )
    db.add(otp)
    db.commit()
    
    # Send OTP email
    email_service.send_otp_email(otp_request.email, otp_code, otp_request.purpose)
    
    return {"message": "OTP sent successfully"}

@app.post("/api/auth/verify-otp")
def verify_otp(otp_verify: OTPVerify, db: Session = Depends(get_db)):
    """Verify OTP code"""
    utc = pytz.utc # Define utc timezone
    otp = db.query(OTP).filter(
        and_(
            OTP.email == otp_verify.email,
            OTP.otp_code == otp_verify.otp_code,
            OTP.purpose == otp_verify.purpose,
            OTP.used == False,
            OTP.expires_at > utc.localize(datetime.utcnow()) # Localize current UTC time
        )
    ).first()
    
    if not otp:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    
    otp.used = True
    db.commit()
    
    return {"message": "OTP verified successfully"}

@app.post("/api/auth/signup")
def signup(user_data: UserCreate, request: Request, db: Session = Depends(get_db)):
    """User registration with email OTP verification"""
    # Check if user already exists
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Verify OTP first
    utc = pytz.utc # Define utc timezone
    otp = db.query(OTP).filter(
        and_(
            OTP.email == user_data.email,
            OTP.purpose == "signup",
            OTP.used == True
        )
    ).order_by(OTP.created_at.desc()).first()
    
    # Ensure the OTP is recent enough (e.g., within 15 minutes of creation)
    # And that the OTP's created_at is also timezone-aware for comparison
    if not otp or otp.created_at < utc.localize(datetime.utcnow()) - timedelta(minutes=15):
        raise HTTPException(status_code=400, detail="Please verify your email with OTP first")
    
    # Check referral code if provided
    referring_agent = None
    if user_data.referral_code:
        referring_agent = db.query(User).filter(
            and_(User.referral_code == user_data.referral_code, User.is_agent == True)
        ).first()
        if not referring_agent:
            raise HTTPException(status_code=400, detail="Invalid referral code")
    
    # Create user
    user = User(
        email=user_data.email,
        name=user_data.name,
        password_hash=get_password_hash(user_data.password),
        pin_hash=get_password_hash(user_data.pin),
        referred_by_code=user_data.referral_code,
        email_verified=True
    )
    
    db.add(user)
    db.flush()  # Get user ID
    
    # Add device tracking
    device = UserDevice(
        user_id=user.id,
        device_fingerprint=user_data.device_fingerprint,
        ip_address=user_data.ip_address,
        user_agent=user_data.user_agent
    )
    db.add(device)
    
    # Create approval record
    approval_token = generate_approval_token()
    approval = UserApproval(
        user_id=user.id,
        status=UserStatus.PENDING,
        approval_token=approval_token
    )
    db.add(approval)
    
    db.commit()
    
    # Send approval email to agent if referral code was used
    if referring_agent:
        email_service.send_agent_approval_email(
            referring_agent.email,
            user.name,
            user.email,
            approval_token
        )
    
    log_activity(db, user.id, "USER_SIGNUP", f"User signed up with referral: {user_data.referral_code}", user_data.ip_address)
    
    return {"message": "Registration successful. Awaiting approval."}

@app.post("/api/auth/login")
def login(user_data: UserLogin, request: Request, db: Session = Depends(get_db)):
    """User login with email and password"""
    user = db.query(User).filter(User.email == user_data.email).first()
    
    if not user:
        print(f"DEBUG: Login failed for email {user_data.email}: User not found.") # Added debug print
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    if not verify_password(user_data.password, user.password_hash):
        print(f"DEBUG: Login failed for email {user_data.email}: Invalid password.") # Added debug print
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    if user.status != UserStatus.APPROVED:
        print(f"DEBUG: Login failed for email {user_data.email}: Account status is {user.status}.") # Added debug print
        raise HTTPException(status_code=400, detail=f"Account is {user.status}")
    
    access_token = create_access_token(data={"sub": user.email})
    
    client_ip = request.client.host
    log_activity(db, user.id, "USER_LOGIN", "User logged in", client_ip)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse.from_orm(user)
    }

@app.post("/api/auth/verify-pin")
def verify_pin(pin_data: UserPinVerify, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Verify user's 4-digit PIN for dashboard access"""
    if not verify_password(pin_data.pin, current_user.pin_hash):
        raise HTTPException(status_code=400, detail="Invalid PIN")
    
    return {"message": "PIN verified successfully"}

# =============================================================================
# USER DASHBOARD ENDPOINTS
# =============================================================================

@app.get("/api/dashboard/stats", response_model=DashboardStats)
def get_dashboard_stats(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get user dashboard statistics"""
    completed_surveys = db.query(UserSurvey).filter(UserSurvey.user_id == current_user.id).count()
    total_earned = db.query(func.sum(UserSurvey.points_earned)).filter(UserSurvey.user_id == current_user.id).scalar() or 0
    pending_redemptions = db.query(Redemption).filter(
        and_(Redemption.user_id == current_user.id, Redemption.status == RedemptionStatus.PENDING)
    ).count()
    
    return DashboardStats(
        points_balance=current_user.points_balance,
        completed_surveys=completed_surveys,
        total_earned=total_earned,
        pending_redemptions=pending_redemptions
    )

@app.post("/api/points/transfer")
def transfer_points(transfer_data: PointTransferCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Transfer points to another user"""
    if current_user.points_balance < transfer_data.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    to_user = db.query(User).filter(User.email == transfer_data.to_email).first()
    if not to_user:
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    if to_user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot transfer to yourself")
    
    # Create transfer record
    transfer = PointTransfer(
        from_user_id=current_user.id,
        to_user_id=to_user.id,
        amount=transfer_data.amount
    )
    db.add(transfer)
    
    # Update balances
    current_user.points_balance -= transfer_data.amount
    to_user.points_balance += transfer_data.amount
    
    db.commit()
    
    return {"message": "Transfer successful"}

@app.get("/api/points/history", response_model=TransferHistory)
def get_transfer_history(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get user's point transfer history"""
    sent_transfers = db.query(PointTransfer).filter(PointTransfer.from_user_id == current_user.id).all()
    received_transfers = db.query(PointTransfer).filter(PointTransfer.to_user_id == current_user.id).all()
    
    all_transfers = sent_transfers + received_transfers
    total_sent = sum(t.amount for t in sent_transfers)
    total_received = sum(t.amount for t in received_transfers)
    
    return TransferHistory(
        transfers=[PointTransferResponse.from_orm(t) for t in all_transfers],
        total_sent=total_sent,
        total_received=total_received
    )

# =============================================================================
# REDEMPTION ENDPOINTS
# =============================================================================

@app.get("/api/redemption/rates")
def get_redemption_rates(db: Session = Depends(get_db)):
    """Get current redemption rates"""
    btc_rate = Decimal(get_system_setting(db, "point_to_btc_rate", "0.00001"))
    gift_rate = Decimal(get_system_setting(db, "point_to_gift_rate", "0.01"))
    
    return {
        "bitcoin_rate": btc_rate,
        "gift_card_rate": gift_rate,
        "description": "Rates show equivalent value per point"
    }

@app.post("/api/redemption/request")
def request_redemption(redemption_data: RedemptionCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Request points redemption"""
    if current_user.points_balance < redemption_data.points_amount:
        raise HTTPException(status_code=400, detail="Insufficient points balance")
    
    # Calculate equivalent value
    if redemption_data.type == RedemptionType.BITCOIN:
        rate = Decimal(get_system_setting(db, "point_to_btc_rate", "0.00001"))
    else:
        rate = Decimal(get_system_setting(db, "point_to_gift_rate", "0.01"))
    
    equivalent_value = redemption_data.points_amount * rate
    
    # Create redemption request
    redemption = Redemption(
        user_id=current_user.id,
        type=redemption_data.type,
        points_amount=redemption_data.points_amount,
        equivalent_value=equivalent_value,
        wallet_address=redemption_data.wallet_address,
        email_address=redemption_data.email_address
    )
    db.add(redemption)
    
    # Deduct points from user balance
    current_user.points_balance -= redemption_data.points_amount
    
    db.commit()
    
    return {"message": "Redemption request submitted successfully", "redemption_id": redemption.id}

@app.get("/api/redemption/history", response_model=List[RedemptionResponse])
def get_redemption_history(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get user's redemption history"""
    redemptions = db.query(Redemption).filter(Redemption.user_id == current_user.id).all()
    return [RedemptionResponse.from_orm(r) for r in redemptions]

# =============================================================================
# AGENT ENDPOINTS
# =============================================================================

@app.get("/api/agent/approve/{token}")
def agent_approve_user(token: str, action: str = Query(...), db: Session = Depends(get_db)):
    """Agent approval via email link"""
    approval = db.query(UserApproval).filter(UserApproval.approval_token == token).first()
    if not approval:
        raise HTTPException(status_code=404, detail="Invalid approval token")
    
    user = db.query(User).filter(User.id == approval.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if action == "approve":
        user.status = UserStatus.APPROVED
        approval.status = UserStatus.APPROVED
        message = f"User {user.name} has been approved successfully!"
    elif action == "reject":
        user.status = UserStatus.REJECTED
        approval.status = UserStatus.REJECTED
        message = f"User {user.name} has been rejected."
    else:
        raise HTTPException(status_code=400, detail="Invalid action")
    
    db.commit()
    
    return {"message": message}

# =============================================================================
# ADMIN ENDPOINTS
# =============================================================================

@app.get("/api/admin/users", response_model=List[UserResponse])
def get_all_users(admin_user: User = Depends(get_admin_user), db: Session = Depends(get_db)):
    """Get all users (Admin only)"""
    users = db.query(User).all()
    return [UserResponse.from_orm(user) for user in users]

@app.put("/api/admin/users/{user_id}/status")
def update_user_status(user_id: int, status_update: UserStatusUpdate, admin_user: User = Depends(get_admin_user), db: Session = Depends(get_db)):
    """Update user status (Admin only)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.status = status_update.status
    db.commit()
    
    return {"message": f"User status updated to {status_update.status}"}

@app.put("/api/admin/users/{user_id}/agent")
def assign_agent_role(user_id: int, agent_data: AgentAssignment, admin_user: User = Depends(get_admin_user), db: Session = Depends(get_db)):
    """Assign or remove agent role (Admin only)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.is_agent = agent_data.is_agent
    if agent_data.is_agent and not user.referral_code:
        user.referral_code = generate_referral_code()
    
    db.commit()
    
    return {"message": f"Agent role {'assigned' if agent_data.is_agent else 'removed'}", "referral_code": user.referral_code}

@app.get("/api/admin/redemptions", response_model=List[RedemptionResponse])
def get_all_redemptions(admin_user: User = Depends(get_admin_user), db: Session = Depends(get_db)):
    """Get all redemption requests (Admin only)"""
    redemptions = db.query(Redemption).all()
    return [RedemptionResponse.from_orm(r) for r in redemptions]

@app.put("/api/admin/redemptions/{redemption_id}/process")
def process_redemption(redemption_id: int, action: str = Query(...), admin_user: User = Depends(get_admin_user), db: Session = Depends(get_db)):
    """Process redemption request (Admin only)"""
    redemption = db.query(Redemption).filter(Redemption.id == redemption_id).first()
    if not redemption:
        raise HTTPException(status_code=404, detail="Redemption not found")
    
    user = db.query(User).filter(User.id == redemption.user_id).first()
    
    if action == "approve":
        redemption.status = RedemptionStatus.APPROVED
        redemption.processed_by = admin_user.id
        redemption.processed_at = datetime.utcnow()
        message = "Redemption approved"
    elif action == "reject":
        redemption.status = RedemptionStatus.REJECTED
        redemption.processed_by = admin_user.id
        redemption.processed_at = datetime.utcnow()
        # Refund points to user
        user.points_balance += redemption.points_amount
        message = "Redemption rejected and points refunded"
    else:
        raise HTTPException(status_code=400, detail="Invalid action")
    
    db.commit()
    
    return {"message": message}

@app.put("/api/admin/settings")
def update_system_setting(setting_data: SystemSettingUpdate, admin_user: User = Depends(get_admin_user), db: Session = Depends(get_db)):
    """Update system settings (Admin only)"""
    setting = db.query(SystemSettings).filter(SystemSettings.key == setting_data.key).first()
    if setting:
        setting.value = setting_data.value
        if setting_data.description:
            setting.description = setting_data.description
    else:
        setting = SystemSettings(
            key=setting_data.key,
            value=setting_data.value,
            description=setting_data.description
        )
        db.add(setting)
    
    db.commit()
    
    return {"message": "Setting updated successfully"}

# =============================================================================
# SURVEY MANAGEMENT ENDPOINTS
# =============================================================================

@app.post("/api/admin/surveys", response_model=SurveyResponse)
def create_survey(survey_data: SurveyCreate, admin_user: User = Depends(get_admin_user), db: Session = Depends(get_db)):
    """Create new survey (Admin only)"""
    survey = Survey(
        title=survey_data.title,
        description=survey_data.description,
        points_reward=survey_data.points_reward
    )
    db.add(survey)
    db.commit()
    db.refresh(survey)
    
    return SurveyResponse.from_orm(survey)

@app.get("/api/surveys", response_model=List[SurveyResponse])
def get_active_surveys(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get all active surveys"""
    surveys = db.query(Survey).filter(Survey.is_active == True).all()
    return [SurveyResponse.from_orm(survey) for survey in surveys]

@app.post("/api/surveys/{survey_id}/complete")
def complete_survey(survey_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Complete a survey and earn points"""
    survey = db.query(Survey).filter(Survey.id == survey_id).first()
    if not survey:
        raise HTTPException(status_code=404, detail="Survey not found")
    
    # Check if user already completed this survey
    existing = db.query(UserSurvey).filter(
        and_(UserSurvey.user_id == current_user.id, UserSurvey.survey_id == survey_id)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Survey already completed")
    
    # Record survey completion
    user_survey = UserSurvey(
        user_id=current_user.id,
        survey_id=survey_id,
        points_earned=survey.points_reward
    )
    db.add(user_survey)
    
    # Add points to user balance
    current_user.points_balance += survey.points_reward
    
    db.commit()
    
    return {"message": "Survey completed successfully", "points_earned": survey.points_reward}

# =============================================================================
# HEALTH CHECK ENDPOINT
# =============================================================================

@app.get("/")
def root():
    """Health check endpoint"""
    return {
        "message": "🎉 Reward System API is running!",
        "version": "1.0.0",
        "docs": "/docs",
        "admin_login": {
            "email": "admin@example.com",
            "password": "admin123",
            "pin": "0000"
        }
    }

@app.get("/health")
def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "database": "connected",
        "email_service": "configured"
    }

# =============================================================================
# RUN THE APPLICATION
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    print("=" * 60)
    print("🚀 STARTING REWARD SYSTEM API")
    print("=" * 60)
    print(f"📧 Admin Login: admin@example.com / admin123 (PIN: 0000)")
    print(f"🌐 API Documentation: http://localhost:10000/docs")  # Updated to port 10000
    print(f"💾 Database: {DATABASE_URL}")
    print("=" * 60)

    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=10000,  # ✅ Match your Render start command
        reload=False,  # 🔁 Turn off reload in production
        log_level="info"
    )
