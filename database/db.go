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
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ltime)
}

func ConnectAndCheck() error {
	log.Println("Connecting to database")

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Println("Checking if table exists")

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

	log.Println("Database connection and table creation successful")
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

	log.Printf("IP %s blocked status: %v", ip, exists)
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

	log.Printf("IP %s blocked status: %v", ip, exists)
	return exists, nil
}

func AddBlockedIP(ip string) error {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	query := "INSERT INTO blocked_ips (ip) VALUES ($1) ON CONFLICT (ip) DO NOTHING"
	_, err = db.ExecContext(ctx, query, ip)
	if err != nil {
		return fmt.Errorf("failed to insert IP %s into blocked_ips: %w", ip, err)
	}
	log.Printf("Attempted to add IP %s to blocked_ips", ip)
	return nil
}

func RemoveBlockedIP(ip string) error {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	query := "DELETE FROM blocked_ips WHERE ip = $1"
	result, err := db.ExecContext(ctx, query, ip)
	if err != nil {
		return fmt.Errorf("failed to delete IP %s from blocked_ips: %w", ip, err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		log.Printf("Successfully removed IP %s from blocked_ips", ip)
	} else {
		log.Printf("IP %s not found in blocked_ips for removal or already removed", ip)
	}
	return nil
}

func AddTorBlockedIP(ip string) error {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	query := "INSERT INTO tor_blocked_ips (ip) VALUES ($1) ON CONFLICT (ip) DO NOTHING"
	_, err = db.ExecContext(ctx, query, ip)
	if err != nil {
		return fmt.Errorf("failed to insert IP %s into tor_blocked_ips: %w", ip, err)
	}
	log.Printf("Attempted to add IP %s to tor_blocked_ips", ip)
	return nil
}

func RemoveTorBlockedIP(ip string) error {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	query := "DELETE FROM tor_blocked_ips WHERE ip = $1"
	result, err := db.ExecContext(ctx, query, ip)
	if err != nil {
		return fmt.Errorf("failed to delete IP %s from tor_blocked_ips: %w", ip, err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		log.Printf("Successfully removed IP %s from tor_blocked_ips", ip)
	} else {
		log.Printf("IP %s not found in tor_blocked_ips for removal or already removed", ip)
	}
	return nil
}
