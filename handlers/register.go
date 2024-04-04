package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v4"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	InvitationCode string `json:"invitation_code"`
}

func RegisterHandler(c *gin.Context, db *pgx.Conn) {
	var newUser User
	if err := c.ShouldBindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

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

	_, err = db.Exec(context.Background(), "UPDATE invitation_codes SET used = true WHERE code = $1", newUser.InvitationCode)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark invitation code as used"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}
