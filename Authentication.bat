# Register
POST /api/auth/register
{
  "username": "myuser",
  "password": "password123",
  "email": "user@example.com"
}

# Login
POST /api/auth/login
{
  "username": "myuser",
  "password": "password123"
}