from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from pydantic import BaseModel
from typing import Optional
from requests import Session
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta, timezone 
import auth


app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SECRET_KEY = "mysecretkey"  # This should be stored securely, e.g., in environment variables
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database setup using SQLAlchemy
DATABASE_URL = "sqlite:///./users.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models using SQLAlchemy ORM
class UserInDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

# Create tables in the database
Base.metadata.create_all(bind=engine)

# Pydantic models for request validation
class User(BaseModel):
    username: str
    password: str

class UserInDBSchema(BaseModel):
    username: str

    class Config:
        from_attributes = True

class ResetPassword(BaseModel):
    username: str
    new_password: str

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper functions
def create_user(db, username: str, password: str):
    hashed_password = auth.hash_password(password)
    db_user = UserInDB(username=username, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db, username: str, password: str) -> Optional[UserInDBSchema]:
    db_user = db.query(UserInDB).filter(UserInDB.username == username).first()
    if db_user and auth.verify_password(password, db_user.hashed_password):
        return UserInDBSchema(username=db_user.username, hashed_password=db_user.hashed_password)
    return None



def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire =  datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt



# Routes
@app.post("/signup")
def signup(user: User, db: Session = Depends(get_db)):
    # Check if user already exists
    if db.query(UserInDB).filter(UserInDB.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    db_user = create_user(db, user.username, user.password)
    return {"message": "User created successfully", "user": {"username": db_user.username}}

@app.post("/signin")
def signin(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    
    # Create and return JWT token
    access_token = create_access_token(data={"sub": user.username})
    return {"message": "Login successful", "token": access_token}

@app.post("/reset-password")
def reset_password(reset_data: ResetPassword, db: Session = Depends(get_db)):
    db_user = db.query(UserInDB).filter(UserInDB.username == reset_data.username).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")
    db_user.hashed_password = auth.hash_password(reset_data.new_password)
    db.commit()
    return {"message": "Password reset successful"}

@app.post("/logout")
def logout(token: str = Depends(oauth2_scheme)):
    try:
        # Decode the token, but we don't need the payload
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"message": "Logout successful"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
