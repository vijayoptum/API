package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"github.com/prometheus/common/log"
)

var db *sql.DB
var sqlopen = sql.Open
var SQLStatement string
var jwtKey = []byte("jwtpassword")

type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

type Claims struct {
	Name string `json:"name"`
	jwt.StandardClaims
}

// InitDB - initializes the DB
// func InitDB() error {
// 	var err error

// 	db, err = sqlopen("mysql", "root:bUtter123$@tcp(localhost:3306)/database1")
// 	if err != nil {
// 		log.Error("sql.Open failed, error: " + err.Error())
// 		return err
// 	}
// 	log.Info("SQL Open did not fail.")

// 	return nil
// }

func InitDB() error {
	var err error

	db, err = sqlopen("oracle//", "vijay:vijay@localhost:1521/xe")
	if err != nil {
		log.Error("sql.Open failed, error: " + err.Error())
		return err
	}
	log.Info("SQL Open did not fail.")

	return nil
}

func logout(c *gin.Context) {

	var user User

	err := c.BindJSON(&user)

	if err != nil {
		fmt.Println("Bind JSON error")
	}

	SQLStatement := `UPDATE database1.User
					  SET Token = ''
					  WHERE Email = ?;`

	_, err = db.Exec(SQLStatement, &user.Email)

	if err != nil {
		panic(err)
	}

	c.JSON(http.StatusCreated, "JWT Token Successfully Deleted")

}

func login(c *gin.Context) {

	var user User
	var input User

	err := c.BindJSON(&input)

	if err != nil {
		fmt.Println("Bind JSON error")
	}

	SQLStatement := `SELECT Email, Id, Name, Password FROM database1.User
					WHERE Email = ?`

	row := db.QueryRow(SQLStatement, &input.Email)

	err = row.Scan(&user.Email, &user.ID, &user.Name, &user.Password)

	switch err {

	case sql.ErrNoRows:

		c.JSON(http.StatusBadRequest, "User Not found in Database")
		return

	case nil:

		if input.Name != strings.Trim(user.Name, " ") || input.Password != strings.Trim(user.Password, " ") {

			c.JSON(http.StatusUnauthorized, "Credentials don't match in Database")
			return
		}

		expirationTime := time.Now().Add(5 * time.Minute)

		claims := &Claims{
			Name: input.Name,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		tokenString, err := token.SignedString(jwtKey)

		if err != nil {
			c.JSON(http.StatusInternalServerError, "Error while creating JWT Token")
			return
		}

		SQLStatement := `UPDATE database1.User
						SET Token = ?
						WHERE Email = ?;`

		_, err = db.Exec(SQLStatement, tokenString, &user.Email)

		if err != nil {
			panic(err)
		}

		fmt.Println(tokenString)

	default:
		panic(err)
	}

}

func registerUser(c *gin.Context) {

	var user User

	err := c.BindJSON(&user)

	if err != nil {
		fmt.Println("Bind JSON error")
	}

	SQLStatement := `SELECT Email, Id, Name, Password FROM database1.User
					WHERE Email = ?`

	row := db.QueryRow(SQLStatement, &user.Email)

	err = row.Scan(&user.Email, &user.ID, &user.Name, &user.Password)

	switch err {

	case sql.ErrNoRows:

		SQLStatement := `INSERT INTO database1.User (Email, Id, Name, Password)
							VALUES (?, ?, ?, ?)`

		_, err = db.Exec(SQLStatement, &user.Email, &user.ID, &user.Name, &user.Password)

		if err != nil {
			panic(err)
		}

		c.JSON(http.StatusOK, "New User is successfully added")
		return

	case nil:
		c.JSON(http.StatusOK, "This User already exists in database")
		return

	default:
		panic(err)
	}
}

func ValidateToken(signedToken string) (err error) {

	token, err := jwt.ParseWithClaims(
		signedToken,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtKey), nil
		},
	)
	if err != nil {
		return
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		err = errors.New("couldn't parse claims")
		return
	}
	if claims.ExpiresAt < time.Now().Local().Unix() {
		err = errors.New("token expired")
		return
	}
	return
}

func getUserInfo(c *gin.Context) {

	var user User

	email := c.Param("email")

	SQLStatement := `SELECT Email, Id, Name, Password, Token FROM database1.User
					WHERE Email = ?`

	row := db.QueryRow(SQLStatement, email)

	err := row.Scan(&user.Email, &user.ID, &user.Name, &user.Password, &user.Token)

	user.Email = strings.Trim(user.Email, " ")
	user.ID = strings.Trim(user.ID, " ")
	user.Name = strings.Trim(user.Name, " ")
	user.Password = strings.Trim(user.Password, " ")
	user.Token = strings.Trim(user.Token, " ")

	switch err {

	case sql.ErrNoRows:

		c.JSON(http.StatusBadRequest, "User and Token Not found in Database")
		return

	case nil:

		tokenString := strings.Trim(user.Token, " ")

		err := ValidateToken(tokenString)

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, user)
		return

	default:
		panic(err)
	}

}

func main() {
	err := InitDB()
	if err != nil {
		fmt.Println("Error while performing InitDB")
	}

	r := gin.New()
	r.GET("/me/:email", getUserInfo)
	r.POST("/register", registerUser)
	r.POST("/login", login)
	r.POST("/logout", logout)
	r.Run(":8080")
}
