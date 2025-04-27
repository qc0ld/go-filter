package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
)

var (
	dbHost     = "127.0.0.1"
	dbPort     = "5432"
	dbUser     = "postgres"
	dbPassword = "postgres"
	dbName     = "blocked_ip_db"
	logger     = log.New(os.Stdout, "[DATABASE] ", log.Ltime)
)

func ConnectAndCheck() error {
	logger.Println("Connecting to database")

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logger.Println("Checking if table exists")

	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS blocked_ips (
		id SERIAL PRIMARY KEY,
		ip VARCHAR(15) NOT NULL UNIQUE
	)`)

	if err != nil {
		return fmt.Errorf("failed to create table blocked_ips: %v", err)
	}

	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS tor_blocked_ips (
		id SERIAL PRIMARY KEY,
		ip VARCHAR(15) NOT NULL UNIQUE
	)`)

	if err != nil {
		return fmt.Errorf("failed to create table tor_blocked_ips: %v", err)
	}

	logger.Println("Database connection and table creation successful")
	return nil
}

func IsIPBlocked(ip string) (bool, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	db, err := sql.Open("postgres", dsn)

	if err != nil {
		return false, fmt.Errorf("failed to connect to database: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)

	defer cancel()

	var exists bool
	err = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM blocked_ips WHERE ip = $1)", ip).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if IP is blocked: %v", err)
	}

	logger.Printf("IP %s blocked status: %v\n", ip, exists)
	return exists, nil
}

func TorIsIPBlocked(ip string) (bool, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	db, err := sql.Open("postgres", dsn)

	if err != nil {
		return false, fmt.Errorf("failed to connect to database: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)

	defer cancel()

	var exists bool
	err = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM tor_blocked_ips WHERE ip = $1)", ip).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if IP is blocked: %v", err)
	}

	logger.Printf("IP %s blocked status: %v\n", ip, exists)
	return exists, nil
}
