# FastAPI Task Management with JWT Authentication

A complete FastAPI application with JWT authentication and full CRUD operations for task management.

## Features

- **User Authentication**: Secure registration and login with JWT tokens
- **Password Security**: Bcrypt hashing for secure password storage
- **Task CRUD Operations**: Create, read, update, and delete tasks
- **User Isolation**: Each user can only access their own tasks
- **Input Validation**: Pydantic models for request validation
- **Error Handling**: Comprehensive error messages and HTTP status codes
- **Logging**: Detailed logging for debugging and monitoring
- **Interactive API Docs**: Swagger UI at `/docs`

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the Application

Start the server with:
```bash
uvicorn api:app --reload
```

The API will be available at `http://localhost:8000`

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## API Endpoints

### Authentication

#### Register User
```bash
POST /auth/register
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "securepass123"
}
```

#### Login
```bash
POST /auth/login
{
  "username": "john_doe",
  "password": "securepass123"
}

Response:
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

### Tasks

All task endpoints require authentication with a Bearer token.

#### Create Task
```bash
POST /tasks
Authorization: Bearer <access_token>

{
  "title": "Buy groceries",
  "description": "Milk, eggs, bread",
  "status": "pending"
}
```

#### List All Tasks
```bash
GET /tasks
Authorization: Bearer <access_token>
```

#### Get Task by ID
```bash
GET /tasks/{task_id}
Authorization: Bearer <access_token>
```

#### Update Task
```bash
PUT /tasks/{task_id}
Authorization: Bearer <access_token>

{
  "title": "Buy groceries",
  "description": "Updated description",
  "status": "completed"
}
```

#### Delete Task
```bash
DELETE /tasks/{task_id}
Authorization: Bearer <access_token>
```

## Task Status Values

- `pending`: Task has not been started
- `in_progress`: Task is currently being worked on
- `completed`: Task has been finished

## Running Tests

Execute the test suite:
```bash
pytest test_api.py -v
```

Test coverage includes:
- User registration and login
- Authentication validation
- Task CRUD operations
- Input validation
- Error handling
- Cross-user access control

## Security Notes

⚠️ **Important**: This is a demonstration application. For production use:

1. Change `SECRET_KEY` to a secure random value
2. Use a proper database (PostgreSQL, MongoDB, etc.)
3. Implement rate limiting
4. Use HTTPS/TLS
5. Add CORS configuration as needed
6. Store secrets in environment variables
7. Implement refresh token rotation
8. Add request logging and monitoring

## Technology Stack

- **FastAPI**: Modern web framework for building APIs
- **Pydantic**: Data validation using Python type hints
- **PyJWT**: JWT token creation and verification
- **passlib**: Password hashing and verification
- **pytest**: Testing framework
- **httpx**: HTTP client for testing