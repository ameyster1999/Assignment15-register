Sure, here's a basic README.md file for your project:

```
# User Registration and Authentication Server

This is a simple user registration and authentication server built with Go using the Gin web framework and PostgreSQL as the database.

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/ameyster1999/Assignment15-register.git
cd Assignment15-register.git
```

### 2. Set up the PostgreSQL database

Make sure you have PostgreSQL installed on your system. Then, create a new database and execute the SQL schema provided in `schema.sql` to create the required tables.



### 3. Install dependencies

```bash
go mod tidy
```

### 4. Build and run the server

```bash
go run main.go
```

The server will start running at `http://localhost:8080`.

## Usage

### Register a new user

To register a new user, send a POST request to `/register` endpoint with JSON payload containing the username, password, and optional invitation code.

Example:

```bash
curl -X POST http://localhost:8080/register -d '{"username":"exampleuser","password":"password123","invitation_code":"ABC123"}'
```

### Login

To login, send a POST request to `/login` endpoint with JSON payload containing the username and password.

Example:

```bash
curl -X POST http://localhost:8080/login -d '{"username":"exampleuser","password":"password123"}'
```

### Generate Invitation Code

To generate an invitation code, send a POST request to `/generate-code` endpoint.

Example:

```bash
curl -X POST http://localhost:8080/generate-code
```

### Resend Invitation Code

To resend an invitation code, send a POST request to `/resend-invitation-code` endpoint with JSON payload containing the username.

Example:

```bash
curl -X POST http://localhost:8080/resend-invitation-code -d '{"username":"exampleuser"}'
```

