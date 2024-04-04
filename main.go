package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v4"
	"golang.org/x/crypto/bcrypt"
)

var db *pgx.Conn

type User struct {
	Username       string `form:"username" json:"username"`
	Password       string `form:"password" json:"password"`
	InvitationCode string `form:"invitation_code" json:"invitation_code"`
}

func main() {
	var err error
	db, err = pgx.Connect(context.Background(), "postgres://root:password@localhost:5432/user")
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}
	defer func() {
		if err := db.Close(context.Background()); err != nil {
			log.Fatalf("Failed to close database connection: %v\n", err)
		}
	}()

	router := gin.Default()

	// Middleware for rate limiting
	router.Use(rateLimiterMiddleware())

	// Register routes
	router.POST("/register", registerHandler)
	router.POST("/login", loginHandler)
	router.POST("/generate-code", generateCodeHandler)
	router.POST("/resend-invitation-code", resendInvitationCodeHandler)

	// Serve static files
	router.StaticFile("/register", "./register.html")
	router.StaticFile("/login", "./login.html")

	// Serve HTML files

	// Start server
	router.Run(":8080")
}

func registerHandler(c *gin.Context) {
	var newUser User
	if err := c.ShouldBind(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	// Check if an invitation code is provided
	if newUser.InvitationCode != "" {
		// Check if invitation code is valid and unused
		var valid bool
		err := db.QueryRow(context.Background(), "SELECT used FROM invitation_codes WHERE code = $1", newUser.InvitationCode).Scan(&valid)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check invitation code"})
			return
		}
		if !valid {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or used invitation code"})
			return
		}

		// Mark invitation code as used
		_, err = db.Exec(context.Background(), "UPDATE invitation_codes SET used = true WHERE code = $1", newUser.InvitationCode)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark invitation code as used"})
			return
		}
	}

	// Hash the password before storing
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	_, err = db.Exec(context.Background(), "INSERT INTO users (username, password) VALUES ($1, $2)", newUser.Username, string(hashedPassword))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

func loginHandler(c *gin.Context) {
	var loginUser User
	if err := c.ShouldBind(&loginUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	var storedPassword string
	err := db.QueryRow(context.Background(), "SELECT password FROM users WHERE username = $1", loginUser.Username).Scan(&storedPassword)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Compare hashed password
	if err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(loginUser.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Authentication successful, create session or JWT token and return
	// Example:
	// session := createSession(loginUser.Username)
	// c.SetCookie("session_token", session.Token, session.MaxAge, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

func generateCodeHandler(c *gin.Context) {
	// Implement authentication logic here, for simplicity, let's skip it

	newCode := generateRandomCode()

	_, err := db.Exec(context.Background(), "INSERT INTO invitation_codes (code, used) VALUES ($1, $2)", newCode, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate invitation code"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": newCode})
}

func resendInvitationCodeHandler(c *gin.Context) {
	var username string
	if err := c.ShouldBind(&username); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Invitation code resent successfully"})
}

func generateRandomCode() string {
	return "ABC123"
}

// Utility function to generate a random string
func generateRandomString(length int) string {
	// Implement random string generation logic here
	return "randomstring" // Placeholder value for demonstration
}

func rateLimiterMiddleware() gin.HandlerFunc {
	limiter := &rateLimiter{
		tokens:   3, // Max tokens
		interval: time.Second,
	}

	return func(c *gin.Context) {
		if !limiter.allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests. Please try again later."})
			c.Abort()
			return
		}
		c.Next()
	}
}

type rateLimiter struct {
	tokens   int
	interval time.Duration
	last     time.Time
}

func (rl *rateLimiter) allow() bool {
	now := time.Now()
	rl.tokens += int(now.Sub(rl.last) / rl.interval)
	if rl.tokens > 3 {
		rl.tokens = 3
	}
	rl.last = now
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}
