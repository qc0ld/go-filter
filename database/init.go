package database

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

const (
	BLACKLIST_FILE     = "./database/data/blacklist.txt"
	NEW_BLACKLIST_FILE = "./database/data/blacklist-new.txt"
	TOR_BLACKLIST_FILE = "./database/data/tor_blacklist.txt"
	batchSize          = 1000
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ltime)
}

func InitializeDatabase() error {
	log.Println("Starting database initialization")

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("database connection error: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := createTables(db, ctx); err != nil {
		return err
	}

	if err := processMainBlacklist(db, ctx); err != nil {
		return err
	}

	if err := processTorBlacklist(db, ctx); err != nil {
		return err
	}

	if err := finalizeUpdate(); err != nil {
		return err
	}

	log.Println("Database initialization completed successfully")
	return nil
}

func createTables(db *sql.DB, ctx context.Context) error {
	log.Println("Creating database tables")

	tables := []string{
		`CREATE TABLE IF NOT EXISTS blocked_ips (
			id SERIAL PRIMARY KEY,
			ip VARCHAR(15) NOT NULL UNIQUE
		)`,
		`CREATE TABLE IF NOT EXISTS tor_blocked_ips (
			id SERIAL PRIMARY KEY,
			ip VARCHAR(15) NOT NULL UNIQUE
		)`,
	}

	for _, table := range tables {
		if _, err := db.ExecContext(ctx, table); err != nil {
			return fmt.Errorf("table creation failed: %v", err)
		}
	}
	return nil
}

func processMainBlacklist(db *sql.DB, ctx context.Context) error {
	log.Println("Processing main blacklist")

	oldIPs, err := loadExistingIPs(BLACKLIST_FILE)
	if err != nil {
		return err
	}

	newIPs, err := loadNewIPs()
	if err != nil {
		return err
	}

	ipsToAdd := calculateIPDifference(newIPs, oldIPs)

	if err := batchInsert(db, ctx, ipsToAdd, "blocked_ips"); err != nil {
		return err
	}

	return nil
}

func processTorBlacklist(db *sql.DB, ctx context.Context) error {
	log.Println("Processing Tor blacklist")

	torIPs, err := loadTorIPs()
	if err != nil {
		return err
	}

	if err := batchInsert(db, ctx, torIPs, "tor_blocked_ips"); err != nil {
		return err
	}

	return nil
}

func loadExistingIPs(filename string) (map[string]struct{}, error) {
	ips := make(map[string]struct{})

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return ips, nil
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ips[strings.TrimSpace(scanner.Text())] = struct{}{}
	}

	return ips, scanner.Err()
}

func loadNewIPs() (map[string]struct{}, error) {
	if err := updateBlacklistFile(); err != nil {
		return nil, err
	}

	file, err := os.Open(NEW_BLACKLIST_FILE)
	if err != nil {
		return nil, fmt.Errorf("error opening new blacklist: %v", err)
	}
	defer file.Close()

	ips := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ips[strings.TrimSpace(scanner.Text())] = struct{}{}
	}

	return ips, scanner.Err()
}

func calculateIPDifference(newIPs, oldIPs map[string]struct{}) []string {
	var diff []string
	for ip := range newIPs {
		if _, exists := oldIPs[ip]; !exists {
			diff = append(diff, ip)
		}
	}
	return diff
}

func loadTorIPs() ([]string, error) {
	file, err := os.Open(TOR_BLACKLIST_FILE)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("Tor blacklist file not found, skipping")
			return nil, nil
		}
		return nil, fmt.Errorf("error opening Tor blacklist: %v", err)
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips, scanner.Err()
}

func batchInsert(db *sql.DB, ctx context.Context, ips []string, table string) error {
	if len(ips) == 0 {
		log.Printf("No new IPs to insert into %s", table)
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx,
		fmt.Sprintf(`INSERT INTO %s (ip) VALUES ($1) ON CONFLICT (ip) DO NOTHING`, table))
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, ip := range ips {
		if _, err := stmt.ExecContext(ctx, ip); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	log.Printf("Successfully inserted %d IPs into %s", len(ips), table)
	return nil
}

func updateBlacklistFile() error {
	log.Println("Updating blacklist")

	cmd := exec.Command("bash", "-c",
		"curl -s https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt | "+
			"grep -v '#' | cut -f 1 > "+NEW_BLACKLIST_FILE)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update blacklist: %v", err)
	}

	return nil
}

func finalizeUpdate() error {
	log.Println("Finalizing update process")

	if err := os.Remove(BLACKLIST_FILE); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error removing old blacklist: %v", err)
	}

	if err := os.Rename(NEW_BLACKLIST_FILE, BLACKLIST_FILE); err != nil {
		return fmt.Errorf("error finalizing blacklist update: %v", err)
	}

	return nil
}
