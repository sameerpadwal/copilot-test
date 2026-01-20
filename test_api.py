import pytest
from fastapi.testclient import TestClient
from api import app

client = TestClient(app)


class TestAuthentication:
    """Test authentication endpoints."""
    
    def test_register_success(self):
        """Test successful user registration."""
        response = client.post(
            "/auth/register",
            json={
                "username": "testuser",
                "email": "test@example.com",
                "password": "securepass123",
            },
        )
        assert response.status_code == 201
        assert response.json()["username"] == "testuser"
    
    def test_register_duplicate_username(self):
        """Test registration with duplicate username."""
        client.post(
            "/auth/register",
            json={
                "username": "duplicate",
                "email": "first@example.com",
                "password": "securepass123",
            },
        )
        response = client.post(
            "/auth/register",
            json={
                "username": "duplicate",
                "email": "second@example.com",
                "password": "securepass123",
            },
        )
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]
    
    def test_register_invalid_email(self):
        """Test registration with invalid email."""
        response = client.post(
            "/auth/register",
            json={
                "username": "testuser",
                "email": "invalid-email",
                "password": "securepass123",
            },
        )
        assert response.status_code == 422
    
    def test_register_short_password(self):
        """Test registration with short password."""
        response = client.post(
            "/auth/register",
            json={
                "username": "testuser",
                "email": "test@example.com",
                "password": "short",
            },
        )
        assert response.status_code == 422
    
    def test_login_success(self):
        """Test successful login."""
        client.post(
            "/auth/register",
            json={
                "username": "loginuser",
                "email": "login@example.com",
                "password": "securepass123",
            },
        )
        response = client.post(
            "/auth/login",
            json={"username": "loginuser", "password": "securepass123"},
        )
        assert response.status_code == 200
        assert "access_token" in response.json()
        assert response.json()["token_type"] == "bearer"
    
    def test_login_invalid_username(self):
        """Test login with non-existent user."""
        response = client.post(
            "/auth/login",
            json={"username": "nonexistent", "password": "securepass123"},
        )
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]
    
    def test_login_invalid_password(self):
        """Test login with wrong password."""
        client.post(
            "/auth/register",
            json={
                "username": "wrongpass",
                "email": "wrong@example.com",
                "password": "securepass123",
            },
        )
        response = client.post(
            "/auth/login",
            json={"username": "wrongpass", "password": "wrongpassword"},
        )
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]


class TestTaskCRUD:
    """Test task CRUD endpoints."""
    
    @pytest.fixture
    def auth_token(self):
        """Get authentication token for a test user."""
        client.post(
            "/auth/register",
            json={
                "username": "cruduser",
                "email": "crud@example.com",
                "password": "securepass123",
            },
        )
        response = client.post(
            "/auth/login",
            json={"username": "cruduser", "password": "securepass123"},
        )
        return response.json()["access_token"]
    
    def test_create_task(self, auth_token):
        """Test creating a task."""
        response = client.post(
            "/tasks",
            json={
                "title": "Test Task",
                "description": "This is a test task",
                "status": "pending",
            },
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert response.status_code == 201
        task = response.json()
        assert task["title"] == "Test Task"
        assert task["description"] == "This is a test task"
        assert task["status"] == "pending"
        assert "id" in task
    
    def test_create_task_without_auth(self):
        """Test creating a task without authentication."""
        response = client.post(
            "/tasks",
            json={
                "title": "Unauthorized Task",
                "description": "Should fail",
                "status": "pending",
            },
        )
        assert response.status_code == 403
    
    def test_create_task_invalid_title(self, auth_token):
        """Test creating task with invalid title."""
        response = client.post(
            "/tasks",
            json={
                "title": "",
                "description": "Empty title",
                "status": "pending",
            },
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert response.status_code == 422
    
    def test_list_tasks(self, auth_token):
        """Test listing tasks."""
        # Create a few tasks
        for i in range(3):
            client.post(
                "/tasks",
                json={
                    "title": f"Task {i}",
                    "description": f"Description {i}",
                    "status": "pending",
                },
                headers={"Authorization": f"Bearer {auth_token}"},
            )
        
        response = client.get(
            "/tasks",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert response.status_code == 200
        tasks = response.json()
        assert len(tasks) >= 3
    
    def test_get_task(self, auth_token):
        """Test getting a specific task."""
        create_response = client.post(
            "/tasks",
            json={
                "title": "Get Task Test",
                "description": "Test getting task",
                "status": "pending",
            },
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        task_id = create_response.json()["id"]
        
        response = client.get(
            f"/tasks/{task_id}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert response.status_code == 200
        assert response.json()["id"] == task_id
    
    def test_get_nonexistent_task(self, auth_token):
        """Test getting a non-existent task."""
        response = client.get(
            "/tasks/999999",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert response.status_code == 404
        assert "not found" in response.json()["detail"]
    
    def test_update_task(self, auth_token):
        """Test updating a task."""
        create_response = client.post(
            "/tasks",
            json={
                "title": "Original Title",
                "description": "Original Description",
                "status": "pending",
            },
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        task_id = create_response.json()["id"]
        
        response = client.put(
            f"/tasks/{task_id}",
            json={
                "title": "Updated Title",
                "status": "in_progress",
            },
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert response.status_code == 200
        updated_task = response.json()
        assert updated_task["title"] == "Updated Title"
        assert updated_task["status"] == "in_progress"
        assert updated_task["description"] == "Original Description"
    
    def test_update_nonexistent_task(self, auth_token):
        """Test updating a non-existent task."""
        response = client.put(
            "/tasks/999999",
            json={"title": "Updated Title"},
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert response.status_code == 404
    
    def test_delete_task(self, auth_token):
        """Test deleting a task."""
        create_response = client.post(
            "/tasks",
            json={
                "title": "Task to Delete",
                "description": "This will be deleted",
                "status": "pending",
            },
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        task_id = create_response.json()["id"]
        
        response = client.delete(
            f"/tasks/{task_id}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert response.status_code == 204
        
        # Verify task is deleted
        get_response = client.get(
            f"/tasks/{task_id}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert get_response.status_code == 404
    
    def test_delete_nonexistent_task(self, auth_token):
        """Test deleting a non-existent task."""
        response = client.delete(
            "/tasks/999999",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert response.status_code == 404
    
    def test_cross_user_access(self):
        """Test that users can't access other users' tasks."""
        # Create first user
        client.post(
            "/auth/register",
            json={
                "username": "user1",
                "email": "user1@example.com",
                "password": "securepass123",
            },
        )
        token1_response = client.post(
            "/auth/login",
            json={"username": "user1", "password": "securepass123"},
        )
        token1 = token1_response.json()["access_token"]
        
        # Create second user
        client.post(
            "/auth/register",
            json={
                "username": "user2",
                "email": "user2@example.com",
                "password": "securepass123",
            },
        )
        token2_response = client.post(
            "/auth/login",
            json={"username": "user2", "password": "securepass123"},
        )
        token2 = token2_response.json()["access_token"]
        
        # User1 creates task
        create_response = client.post(
            "/tasks",
            json={
                "title": "User1 Task",
                "description": "This belongs to user1",
                "status": "pending",
            },
            headers={"Authorization": f"Bearer {token1}"},
        )
        task_id = create_response.json()["id"]
        
        # User2 tries to access
        response = client.get(
            f"/tasks/{task_id}",
            headers={"Authorization": f"Bearer {token2}"},
        )
        assert response.status_code == 403
        assert "permission" in response.json()["detail"]


class TestRoot:
    """Test root endpoint."""
    
    def test_root_endpoint(self):
        """Test root endpoint returns API information."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "docs" in data
        assert "endpoints" in data
