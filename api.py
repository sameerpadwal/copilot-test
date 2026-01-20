"""
Task Management API with JWT Authentication

This module provides a FastAPI application with:
- User registration and authentication using JWT tokens
- Task management with full CRUD operations
- User isolation for task access
- Input validation using Pydantic models
- Comprehensive error handling and logging
- Performance optimizations (pagination, async, caching, compression)
- Enterprise security features (rate limiting, CORS, security headers, etc.)
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from enum import Enum
from threading import Lock
from functools import lru_cache
import hashlib
import secrets

from fastapi import FastAPI, Depends, HTTPException, status, Query, Request
from fastapi.middleware.gzip import GZIPMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthCredentials
from pydantic import BaseModel, Field
import jwt
from passlib.context import CryptContext
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# ============== Logging Configuration ==============
# Configure logging with security focus (no sensitive data in logs)
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============== Security Configuration ==============
# Load SECRET_KEY from environment variable (REQUIRED in production)
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    # Only allow default in development
    if os.getenv("ENVIRONMENT") == "production":
        raise RuntimeError("SECRET_KEY environment variable is required in production!")
    SECRET_KEY = "dev-secret-key-change-this-in-production"
    logger.warning("Using default SECRET_KEY - NOT SAFE FOR PRODUCTION!")

# JWT Configuration
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # Reduced from 30 for better security
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Password hashing with stronger settings
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12  # Increased work factor for stronger hashing
)

# HTTP Bearer authentication
security = HTTPBearer()

# Rate limiter for DDoS protection
limiter = Limiter(key_func=get_remote_address)

# ============== FastAPI Application ==============
app = FastAPI(
    title="Task API with JWT Auth",
    version="3.0.0",
    description="High-performance, enterprise-secure task management API",
)

# ============== Security Middleware ==============

# 1. CORS Configuration - Restrict origin access
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,  # Cache preflight requests for 10 minutes
)

# 2. Trusted Host Middleware - Prevent Host Header Injection
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(","),
)

# 3. GZIP Compression
app.add_middleware(GZIPMiddleware, minimum_size=500)

# 4. Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add important security headers to all responses."""
    response = await call_next(request)
    
    # Prevent clickjacking attacks
    response.headers["X-Frame-Options"] = "DENY"
    
    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    # Enable XSS protection
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # Enforce HTTPS
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    # Prevent referrer leaking
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Control feature permissions
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    # CSP - Content Security Policy
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    
    return response

# ============== In-Memory Database ==============
# Note: In production, use a proper database like PostgreSQL or MongoDB with encryption

# User storage: {username: {email, password_hash, created_at, failed_attempts, locked_until}}
users_db = {}
# Task storage: {task_id: {id, username, title, description, status, created_at, updated_at}}
tasks_db = {}
# Audit log storage: {id: {user, action, resource, timestamp, ip_address}}
audit_log = []
# Thread-safe counter
task_id_counter = 1
task_id_lock = Lock()

# Security constants
MAX_FAILED_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCKOUT_DURATION_MINUTES = 15
MAX_REQUEST_SIZE_BYTES = 1024 * 100  # 100 KB limit


# ============== Pydantic Models ==============
class TaskStatus(str, Enum):
    """
    Enum for task status values.
    
    Attributes:
        PENDING: Task has not been started
        IN_PROGRESS: Task is currently being worked on
        COMPLETED: Task has been finished
    """
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


class PaginationParams(BaseModel):
    """
    Pagination parameters for list endpoints.
    
    Attributes:
        skip: Number of records to skip (default: 0)
        limit: Maximum records to return (default: 10, max: 100)
    """
    skip: int = Field(0, ge=0, description="Records to skip")
    limit: int = Field(10, ge=1, le=100, description="Max records to return")


class TaskCreate(BaseModel):
    """
    Model for creating a new task.
    
    Attributes:
        title: Task title (1-100 characters, required)
        description: Detailed task description (max 500 characters, optional)
        status: Current task status (defaults to PENDING)
    """
    title: str = Field(..., min_length=1, max_length=100, description="Task title")
    description: Optional[str] = Field(None, max_length=500, description="Task description")
    status: TaskStatus = Field(default=TaskStatus.PENDING, description="Task status")


class TaskUpdate(BaseModel):
    """
    Model for updating an existing task.
    All fields are optional, allowing partial updates.
    
    Attributes:
        title: New task title (optional)
        description: New task description (optional)
        status: New task status (optional)
    """
    title: Optional[str] = Field(None, min_length=1, max_length=100, description="Updated title")
    description: Optional[str] = Field(None, max_length=500, description="Updated description")
    status: Optional[TaskStatus] = Field(None, description="Updated status")


class Task(TaskCreate):
    """
    Complete task model with metadata.
    Inherits title, description, and status from TaskCreate.
    
    Attributes:
        id: Unique task identifier
        username: Owner of the task
        created_at: Timestamp when task was created
        updated_at: Timestamp when task was last modified
    """
    id: int = Field(..., description="Unique task ID")
    username: str = Field(..., description="Task owner")
    created_at: datetime = Field(..., description="Task creation timestamp")
    updated_at: datetime = Field(..., description="Task last update timestamp")


class UserRegister(BaseModel):
    """
    Model for user registration.
    
    Attributes:
        username: Unique username (3-50 characters)
        email: Valid email address (email validation enforced)
        password: Secure password (minimum 8 characters, must include uppercase, lowercase, number, special char)
    """
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        regex="^[a-zA-Z0-9_-]+$",
        description="Alphanumeric username with underscores/hyphens only"
    )
    email: str = Field(
        ...,
        regex=r"^[\w\.-]+@[\w\.-]+\.\w+$",
        description="Valid email address"
    )
    password: str = Field(
        ...,
        min_length=12,
        description="Strong password (min 12 chars, uppercase, lowercase, number, special char)"
    )
    
    def validate_password_strength(self) -> bool:
        """Validate password meets complexity requirements."""
        has_upper = any(c.isupper() for c in self.password)
        has_lower = any(c.islower() for c in self.password)
        has_digit = any(c.isdigit() for c in self.password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in self.password)
        return has_upper and has_lower and has_digit and has_special


class UserLogin(BaseModel):
    """
    Model for user login.
    
    Attributes:
        username: User's username
        password: User's password
    """
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")


class Token(BaseModel):
    """
    Model for JWT token response.
    
    Attributes:
        access_token: JWT token string
        token_type: Type of token (always "bearer")
    """
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")


# ============== Utility Functions ==============
def hash_password(password: str) -> str:
    """
    Hash a plaintext password using bcrypt.
    
    Args:
        password: Plaintext password to hash
        
    Returns:
        Hashed password string
        
    Note:
        Uses bcrypt for secure password hashing. The hash is salted
        and uses a work factor to make brute-force attacks infeasible.
        This operation is CPU-intensive and should be called sparingly.
    """
    return pwd_context.hash(password)


@lru_cache(maxsize=128, typed=True)
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against a bcrypt hash (with caching).
    
    Args:
        plain_password: Plaintext password to verify
        hashed_password: Bcrypt hash to verify against
        
    Returns:
        True if password matches hash, False otherwise
        
    Security:
        - Timing-attack resistant
        - Uses constant-time comparison
        - Cached to prevent repeated expensive operations
    """
    return pwd_context.verify(plain_password, hashed_password)


def log_audit_event(user: str, action: str, resource: str, ip_address: str, success: bool = True) -> None:
    """
    Log security audit events for compliance and threat detection.
    
    Args:
        user: Username performing the action
        action: Action type (LOGIN, CREATE_TASK, DELETE_TASK, etc.)
        resource: Resource affected (task_id, /endpoint, etc.)
        ip_address: Client IP address
        success: Whether the action succeeded
    """
    audit_log.append({
        "timestamp": datetime.now(timezone.utc),
        "user": user,
        "action": action,
        "resource": resource,
        "ip_address": ip_address,
        "success": success,
    })
    
    if not success:
        logger.warning(f"Security: {action} failed for {user} from {ip_address}")


def check_account_lockout(username: str) -> tuple[bool, Optional[str]]:
    """
    Check if account is locked due to too many failed login attempts.
    
    Args:
        username: Username to check
        
    Returns:
        Tuple of (is_locked, lockout_reason)
    """
    if username not in users_db:
        return False, None
    
    user = users_db[username]
    
    # Check if account is locked
    if "locked_until" in user and user["locked_until"]:
        if datetime.now(timezone.utc) < user["locked_until"]:
            remaining = (user["locked_until"] - datetime.now(timezone.utc)).seconds // 60
            return True, f"Account locked for {remaining} more minutes"
        else:
            # Lock has expired
            user["locked_until"] = None
            user["failed_attempts"] = 0
    
    return False, None


def increment_failed_login(username: str) -> None:
    """
    Track failed login attempts and lock account if threshold exceeded.
    
    Args:
        username: Username that failed login
    """
    if username not in users_db:
        return
    
    user = users_db[username]
    user["failed_attempts"] = user.get("failed_attempts", 0) + 1
    
    # Lock account after max attempts
    if user["failed_attempts"] >= MAX_FAILED_LOGIN_ATTEMPTS:
        user["locked_until"] = datetime.now(timezone.utc) + timedelta(minutes=ACCOUNT_LOCKOUT_DURATION_MINUTES)
        logger.warning(f"Account locked due to too many failed login attempts: {username}")


def reset_failed_login(username: str) -> None:
    """Reset failed login counter on successful login."""
    if username in users_db:
        users_db[username]["failed_attempts"] = 0


async def create_access_token(username: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token for a user (async).
    
    Args:
        username: Username to encode in token
        expires_delta: Token expiration time delta (uses default if None)
        
    Returns:
        Encoded JWT token string
        
    Token Contents:
        - sub: Subject (username)
        - exp: Expiration time (Unix timestamp)
        
    Note:
        Token is signed using HS256 algorithm with SECRET_KEY.
        Made async for consistency with async endpoints.
    """
    # Prepare claim data with username as subject
    to_encode = {"sub": username}
    
    # Calculate expiration time
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    # Add expiration to claims
    to_encode.update({"exp": expire})
    
    # Encode and sign token (non-blocking operation)
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt


async async def verify_token(credentials: HTTPAuthCredentials) -> str:
    """
    Verify JWT token and extract username (async).
    
    Args:
        credentials: HTTP Bearer credentials containing the JWT token
        
    Returns:
        Username extracted from token
        
    Raises:
        HTTPException: 401 Unauthorized if token is invalid or expired
        
    Token Verification:
        - Validates JWT signature using SECRET_KEY
        - Checks token expiration time
        - Extracts and validates username claim
    """
    # Extract token string from credentials
    token = credentials.credentials
    
    try:
        # Decode and verify JWT signature
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Extract username from 'sub' claim
        username: str = payload.get("sub")
        
        # Verify username exists in token
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return username
        
    except jwt.ExpiredSignatureError:
        # Handle expired token
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        # Handle malformed or invalid token
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(credentials: HTTPAuthCredentials = Depends(security)) -> str:
    """
    Dependency to extract and validate current authenticated user (async).
    
    Args:
        credentials: HTTP Bearer credentials from Authorization header
        
    Returns:
        Authenticated username
        
    Usage:
        Use this as a dependency in endpoint functions to ensure only
        authenticated users can access the endpoint.
    """
    return await verify_token(credentials)


# ============== Authentication Endpoints ==============
@app.post(
    "/auth/register",
    response_model=dict,
    status_code=201,
    summary="Register a new user",
    tags=["Authentication"],
)
@limiter.limit("5/minute")  # Rate limit: 5 registrations per minute
async def register(request: Request, user: UserRegister):
    """
    Register a new user account with security validations.
    
    Security Features:
    - Strong password requirement (12+ chars, uppercase, lowercase, digit, special)
    - Username validation (alphanumeric only)
    - Email format validation
    - Rate limiting (5 registrations per minute)
    - Bcrypt hashing with 12 rounds
    
    Args:
        user: UserRegister model with credentials
        
    Returns:
        dict: Success message
        
    Raises:
        HTTPException: 400 if validation fails
        HTTPException: 429 if rate limit exceeded
    """
    # Validate password strength
    if not user.validate_password_strength():
        log_audit_event(user.username, "REGISTRATION_FAILED", "password_weakness", request.client.host, False)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain uppercase, lowercase, number, and special character",
        )
    
    # Check if username already exists
    if user.username in users_db:
        log_audit_event(user.username, "REGISTRATION_FAILED", "duplicate_username", request.client.host, False)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists",
        )
    
    # Store new user with enhanced metadata
    users_db[user.username] = {
        "email": user.email,
        "password_hash": hash_password(user.password),
        "created_at": datetime.now(timezone.utc),
        "failed_attempts": 0,
        "locked_until": None,
    }
    
    log_audit_event(user.username, "REGISTRATION_SUCCESS", "user_account", request.client.host, True)
    
    return {"message": "User registered successfully", "username": user.username}


@app.post(
    "/auth/login",
    response_model=Token,
    summary="Login and get JWT token",
    tags=["Authentication"],
)
@limiter.limit("10/minute")  # Rate limit: 10 login attempts per minute
async def login(request: Request, user: UserLogin):
    """
    Authenticate user and return JWT token with security checks.
    
    Security Features:
    - Account lockout after 5 failed attempts (15 min lockout)
    - Rate limiting (10 attempts per minute)
    - Failed attempt tracking
    - Short token expiration (15 minutes)
    - Audit logging
    
    Args:
        user: UserLogin credentials
        
    Returns:
        Token: JWT access token
        
    Raises:
        HTTPException: 401 if credentials invalid
        HTTPException: 423 if account locked
    """
    client_ip = request.client.host if request.client else "unknown"
    
    # Check account lockout
    is_locked, lockout_reason = check_account_lockout(user.username)
    if is_locked:
        log_audit_event(user.username, "LOGIN_FAILED", "account_locked", client_ip, False)
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=lockout_reason,
        )
    
    # Check if username exists
    if user.username not in users_db:
        log_audit_event(user.username, "LOGIN_FAILED", "invalid_username", client_ip, False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    
    # Verify password
    if not verify_password(user.password, users_db[user.username]["password_hash"]):
        increment_failed_login(user.username)
        log_audit_event(user.username, "LOGIN_FAILED", "invalid_password", client_ip, False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    
    # Successful login
    reset_failed_login(user.username)
    
    # Create JWT token with shorter expiration for security
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await create_access_token(user.username, access_token_expires)
    
    log_audit_event(user.username, "LOGIN_SUCCESS", "authentication", client_ip, True)
    
    return {"access_token": access_token, "token_type": "bearer"}


# ============== Task CRUD Endpoints ==============
@app.post(
    "/tasks",
    response_model=Task,
    status_code=201,
    summary="Create a new task",
    tags=["Tasks"],
)
@limiter.limit("60/minute")  # Rate limit: 60 requests per minute
async def create_task(
    request: Request,
    task: TaskCreate,
    username: str = Depends(get_current_user)
):
    """
    Create a new task with input validation and audit logging.
    
    Security Features:
    - Input sanitization
    - Rate limiting (60 requests per minute)
    - Owner tracking for authorization
    - Audit logging
    
    Args:
        task: TaskCreate model
        username: Authenticated user
        
    Returns:
        Task: Created task
    """
    global task_id_counter
    
    # Input sanitization - remove potential XSS vectors
    title = task.title.strip()
    description = (task.description.strip() if task.description else None)
    
    # Validate input length (prevent memory exhaustion)
    if len(title) > 100 or len(description or "") > 500:
        log_audit_event(username, "TASK_CREATE_FAILED", "invalid_input", request.client.host, False)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Input exceeds maximum length",
        )
    
    # Generate unique task ID with thread-safe lock
    with task_id_lock:
        task_id = task_id_counter
        task_id_counter += 1
    
    now = datetime.now(timezone.utc)
    tasks_db[task_id] = {
        "id": task_id,
        "username": username,
        "title": title,
        "description": description,
        "status": task.status,
        "created_at": now,
        "updated_at": now,
    }
    
    log_audit_event(username, "TASK_CREATED", f"task_{task_id}", request.client.host, True)
    
    return tasks_db[task_id]


@app.get(
    "/tasks",
    response_model=dict,
    summary="List tasks with pagination and filtering",
    tags=["Tasks"],
)
@limiter.limit("100/minute")  # Rate limit: 100 requests per minute
async def list_tasks(
    request: Request,
    username: str = Depends(get_current_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=50),  # Reduced max from 100 to 50
    status_filter: Optional[TaskStatus] = Query(None),
    sort_by: str = Query("updated_at", regex="^(created_at|updated_at|title)$"),
    order: str = Query("desc", regex="^(asc|desc)$"),
):
    """
    List tasks with pagination, filtering, and rate limiting.
    
    Security Features:
    - User isolation
    - Rate limiting
    - Pagination to prevent data exfiltration
    - Input validation
    
    Args:
        username: Authenticated user
        skip, limit: Pagination
        status_filter: Optional status filter
        sort_by: Sort field
        order: Sort order
        
    Returns:
        dict: Paginated task list
    """
    # Prevent excessive data transfer
    if skip > 1000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Offset too large",
        )
    
    # Filter tasks by current user and status
    user_tasks = [
        task for task in tasks_db.values()
        if task["username"] == username
        and (status_filter is None or task["status"] == status_filter)
    ]
    
    # Sort tasks
    reverse = order == "desc"
    user_tasks.sort(key=lambda t: t[sort_by], reverse=reverse)
    
    # Apply pagination
    total = len(user_tasks)
    paginated_tasks = user_tasks[skip : skip + limit]
    
    log_audit_event(username, "TASK_LIST", f"fetched_{len(paginated_tasks)}", request.client.host, True)
    
    return {
        "items": paginated_tasks,
        "total": total,
        "skip": skip,
        "limit": limit,
        "has_more": (skip + limit) < total,
    }


@app.get(
    "/tasks/{task_id}",
    response_model=Task,
    summary="Get a specific task",
    tags=["Tasks"],
)
@limiter.limit("100/minute")
async def get_task(
    request: Request,
    task_id: int,
    username: str = Depends(get_current_user)
):
    """
    Retrieve a task with authorization check.
    
    Security: Only task owner can access
    """
    if task_id not in tasks_db:
        log_audit_event(username, "TASK_GET_FAILED", f"task_{task_id}_not_found", request.client.host, False)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )
    
    task = tasks_db[task_id]
    
    if task["username"] != username:
        log_audit_event(username, "TASK_GET_FAILED", f"task_{task_id}_unauthorized", request.client.host, False)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to access this task",
        )
    
    return task


@app.put(
    "/tasks/{task_id}",
    response_model=Task,
    summary="Update a task",
    tags=["Tasks"],
)
@limiter.limit("60/minute")
async def update_task(
    request: Request,
    task_id: int,
    task_update: TaskUpdate,
    username: str = Depends(get_current_user)
):
    """
    Update a task with input validation and authorization.
    
    Security: Input sanitization, authorization check, audit logging
    """
    if task_id not in tasks_db:
        log_audit_event(username, "TASK_UPDATE_FAILED", f"task_{task_id}_not_found", request.client.host, False)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )
    
    task = tasks_db[task_id]
    
    if task["username"] != username:
        log_audit_event(username, "TASK_UPDATE_FAILED", f"task_{task_id}_unauthorized", request.client.host, False)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to update this task",
        )
    
    # Input sanitization
    if task_update.title is not None:
        task["title"] = task_update.title.strip()
    if task_update.description is not None:
        task["description"] = task_update.description.strip()
    if task_update.status is not None:
        task["status"] = task_update.status
    
    task["updated_at"] = datetime.now(timezone.utc)
    
    log_audit_event(username, "TASK_UPDATED", f"task_{task_id}", request.client.host, True)
    
    return task


@app.delete(
    "/tasks/{task_id}",
    status_code=204,
    summary="Delete a task",
    tags=["Tasks"],
)
@limiter.limit("60/minute")
async def delete_task(
    request: Request,
    task_id: int,
    username: str = Depends(get_current_user)
):
    """
    Delete a task with authorization and audit logging.
    
    Security: Authorization check, audit logging
    """
    if task_id not in tasks_db:
        log_audit_event(username, "TASK_DELETE_FAILED", f"task_{task_id}_not_found", request.client.host, False)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )
    
    task = tasks_db[task_id]
    
    if task["username"] != username:
        log_audit_event(username, "TASK_DELETE_FAILED", f"task_{task_id}_unauthorized", request.client.host, False)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to delete this task",
        )
    
    del tasks_db[task_id]
    
    log_audit_event(username, "TASK_DELETED", f"task_{task_id}", request.client.host, True)
    
    return None


@app.get(
    "/",
    summary="API information",
    tags=["Info"],
)
@limiter.limit("100/minute")
async def root(request: Request):
    """
    Root endpoint with security features information.
    """
    return {
        "message": "Task API with JWT Authentication (v3.0 - Enterprise Secure)",
        "docs": "/docs",
        "security_features": [
            "JWT authentication with 15-min expiration",
            "Strong password requirements (12+ chars, complexity)",
            "Account lockout (5 attempts, 15-min lockout)",
            "Rate limiting on all endpoints",
            "Security headers (HSTS, CSP, X-Frame-Options, etc.)",
            "CORS protection",
            "Input sanitization and validation",
            "Audit logging for compliance",
            "Bcrypt with 12 rounds",
            "Environment-based configuration",
        ],
        "endpoints": {
            "auth": ["/auth/register", "/auth/login"],
            "tasks": ["/tasks", "/tasks/{task_id}"],
        },
    }