from fastapi import FastAPI, Request, Response, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
import aiosqlite
import bcrypt
import uuid
from typing import Optional
import os
from datetime import datetime, timedelta

# Create FastAPI app
app = FastAPI(title="Computer Workshop Login System")

# Mount static files directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Setup templates
templates = Jinja2Templates(directory="templates")

# Database path
DATABASE_PATH = "workshop.db"

# Session settings
SESSION_COOKIE_NAME = "workshop_session"
SESSION_EXPIRY_DAYS = 7


# Models
class User(BaseModel):
    id: Optional[int] = None
    first_name: str
    last_name: str
    email: str
    phone: str
    password: str
    role: str
    created_at: Optional[datetime] = None


class UserLogin(BaseModel):
    email: str
    password: str
    remember_me: bool = False


class Session(BaseModel):
    id: str
    user_id: int
    expires_at: datetime


# Database initialization
async def init_db():
    async with aiosqlite.connect(DATABASE_PATH) as db:
        # Create users table
        await db.execute('''
                         CREATE TABLE IF NOT EXISTS users
                         (
                             id
                             INTEGER
                             PRIMARY
                             KEY
                             AUTOINCREMENT,
                             first_name
                             TEXT
                             NOT
                             NULL,
                             last_name
                             TEXT
                             NOT
                             NULL,
                             email
                             TEXT
                             UNIQUE
                             NOT
                             NULL,
                             phone
                             TEXT
                             NOT
                             NULL,
                             password
                             TEXT
                             NOT
                             NULL,
                             role
                             TEXT
                             NOT
                             NULL,
                             created_at
                             TIMESTAMP
                             DEFAULT
                             CURRENT_TIMESTAMP
                         )
                         ''')

        # Create sessions table
        await db.execute('''
                         CREATE TABLE IF NOT EXISTS sessions
                         (
                             id
                             TEXT
                             PRIMARY
                             KEY,
                             user_id
                             INTEGER
                             NOT
                             NULL,
                             expires_at
                             TIMESTAMP
                             NOT
                             NULL,
                             FOREIGN
                             KEY
                         (
                             user_id
                         ) REFERENCES users
                         (
                             id
                         )
                             )
                         ''')

        await db.commit()


# Helper functions
def hash_password(password: str) -> str:
    """Hash a password for storing."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify a stored password against a provided password."""
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))


async def create_session(user_id: int, remember_me: bool = False) -> str:
    """Create a new session for a user."""
    session_id = str(uuid.uuid4())

    # Set expiry time based on remember_me
    if remember_me:
        expires_at = datetime.now() + timedelta(days=SESSION_EXPIRY_DAYS)
    else:
        expires_at = datetime.now() + timedelta(hours=24)

    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
            (session_id, user_id, expires_at)
        )
        await db.commit()

    return session_id


async def get_user_by_session(session_id: str) -> Optional[dict]:
    """Get user by session ID."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        # First check if session exists and is not expired
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM sessions WHERE id = ? AND expires_at > ?",
            (session_id, datetime.now())
        )
        session = await cursor.fetchone()

        if not session:
            return None

        # Get user data
        cursor = await db.execute(
            "SELECT id, first_name, last_name, email, phone, role FROM users WHERE id = ?",
            (session["user_id"],)
        )
        user = await cursor.fetchone()

        if not user:
            return None

        return dict(user)


async def delete_session(session_id: str) -> None:
    """Delete a session."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        await db.commit()


# Dependency to get current user
async def get_current_user(request: Request) -> Optional[dict]:
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        return None

    user = await get_user_by_session(session_id)
    return user


# Routes
@app.on_event("startup")
async def startup_event():
    await init_db()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user: Optional[dict] = Depends(get_current_user)):
    return templates.TemplateResponse("index.html", {"request": request, "user": user})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, user: Optional[dict] = Depends(get_current_user)):
    if user:
        # Redirect to appropriate page based on role
        if user["role"] == "manager":
            return RedirectResponse(url="/manager")
        elif user["role"] == "mechanic":
            return RedirectResponse(url="/mechanic")
        else:
            return RedirectResponse(url="/")

    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login(
        response: Response,
        email: str = Form(...),
        password: str = Form(...),
        remember_me: bool = Form(False)
):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = await cursor.fetchone()

        if not user or not verify_password(user["password"], password):
            # Return to login page with error
            return templates.TemplateResponse(
                "login.html",
                {"request": Request, "error": "Noto'g'ri email yoki parol"}
            )

        # Create session
        session_id = await create_session(user["id"], remember_me)

        # Set cookie expiry based on remember_me
        if remember_me:
            max_age = 60 * 60 * 24 * SESSION_EXPIRY_DAYS  # 7 days in seconds
        else:
            max_age = 60 * 60 * 24  # 1 day in seconds

        # Create response with cookie
        if user["role"] == "manager":
            response = RedirectResponse(url="/manager", status_code=status.HTTP_303_SEE_OTHER)
        elif user["role"] == "mechanic":
            response = RedirectResponse(url="/mechanic", status_code=status.HTTP_303_SEE_OTHER)
        else:
            response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

        # Set the cookie
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session_id,
            max_age=max_age,
            httponly=True,
            samesite="lax"
        )

        return response


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, user: Optional[dict] = Depends(get_current_user)):
    if user:
        # Redirect to appropriate page based on role
        if user["role"] == "manager":
            return RedirectResponse(url="/manager")
        elif user["role"] == "mechanic":
            return RedirectResponse(url="/mechanic")
        else:
            return RedirectResponse(url="/")

    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register")
async def register(
        response: Response,
        first_name: str = Form(...),
        last_name: str = Form(...),
        email: str = Form(...),
        phone: str = Form(...),
        password: str = Form(...),
        confirm_password: str = Form(...),
        role: str = Form(...),
        terms: bool = Form(False)
):
    # Validate input
    if not terms:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You must accept the terms and conditions"
        )

    if password != confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match"
        )

    if role not in ["user", "mechanic", "manager"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role"
        )

    # Hash password
    hashed_password = hash_password(password)

    # Save user to database
    user_id = None
    async with aiosqlite.connect(DATABASE_PATH) as db:
        try:
            cursor = await db.execute(
                """
                INSERT INTO users (first_name, last_name, email, phone, password, role)
                VALUES (?, ?, ?, ?, ?, ?) RETURNING id
                """,
                (first_name, last_name, email, phone, hashed_password, role)
            )
            row = await cursor.fetchone()
            if row:
                user_id = row[0]
            await db.commit()
        except aiosqlite.IntegrityError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

    # Create session for the new user
    if user_id:
        session_id = await create_session(user_id)

        # Set cookie
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session_id,
            max_age=60 * 60 * 24,  # 1 day in seconds
            httponly=True,
            samesite="lax"
        )

        # Redirect based on role
        if role == "manager":
            response = RedirectResponse(url="/manager", status_code=status.HTTP_303_SEE_OTHER)
        elif role == "mechanic":
            response = RedirectResponse(url="/mechanic", status_code=status.HTTP_303_SEE_OTHER)

        return response

    # Fallback to login page if something went wrong
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/logout")
async def logout(response: Response, request: Request):
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        await delete_session(session_id)

    response = RedirectResponse(url="/")
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


@app.get("/manager", response_class=HTMLResponse)
async def manager_page(request: Request, user: Optional[dict] = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")

    if user["role"] != "manager":
        return RedirectResponse(url="/")

    return templates.TemplateResponse("manager.html", {"request": request, "user": user})


@app.get("/mechanic", response_class=HTMLResponse)
async def mechanic_page(request: Request, user: Optional[dict] = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")

    if user["role"] != "mechanic":
        return RedirectResponse(url="/")

    return templates.TemplateResponse("mechanic.html", {"request": request, "user": user})


# Run the application with uvicorn
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", reload=True)
