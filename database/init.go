package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

const (
	BLACKLIST_FILE = "../database/data/blacklist.txt"
	batchSize      = 1000
)

func InitializeDatabase() error {
	logger.Println("Initializing database")

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger.Println("Creating table if not exists")
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS blocked_ips (
		id SERIAL PRIMARY KEY,
		ip VARCHAR(15) NOT NULL UNIQUE
	)`)
	if err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	logger.Println("Updating blacklist")
	err = updateBlacklist()
	if err != nil {
		return fmt.Errorf("failed to update blacklist: %v", err)
	}

	var countBefore int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM blocked_ips").Scan(&countBefore)
	if err != nil {
		return fmt.Errorf("failed to get count of blocked IPs: %v", err)
	}
	logger.Printf("Number of IPs in database before update: %d", countBefore)

	oldIPs := make(map[string]struct{})
	if _, err := os.Stat(BLACKLIST_FILE); err == nil {
		file, err := os.Open(BLACKLIST_FILE)
		if err != nil {
			return fmt.Errorf("error opening old blacklist: %v", err)
		}
		defer file.Close()

		var ip string
		for {
			_, err := fmt.Fscanf(file, "%s\n", &ip)
			if err != nil {
				break
			}
			oldIPs[ip] = struct{}{}
		}
	}

	newBlacklistFile := "../database/data/blacklist-new.txt"
	fileNew, err := os.Open(newBlacklistFile)
	if err != nil {
		return fmt.Errorf("error opening new blacklist: %v", err)
	}
	defer fileNew.Close()

	newIPs := make(map[string]struct{})
	var ip string
	for {
		_, err := fmt.Fscanf(fileNew, "%s\n", &ip)
		if err != nil {
			break
		}
		newIPs[ip] = struct{}{}
	}

	newIPsToAdd := make([]string, 0)
	for ip := range newIPs {
		if _, exists := oldIPs[ip]; !exists {
			newIPsToAdd = append(newIPsToAdd, ip)
		}
	}

	if len(newIPsToAdd) > 0 {
		for i := 0; i < len(newIPsToAdd); i += batchSize {
			end := i + batchSize
			if end > len(newIPsToAdd) {
				end = len(newIPsToAdd)
			}

			batch := newIPsToAdd[i:end]
			if err := addIPsBatch(db, batch, ctx); err != nil {
				return fmt.Errorf("error adding IPs batch to database: %v", err)
			}
		}
	}

	var countAfter int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM blocked_ips").Scan(&countAfter)
	if err != nil {
		return fmt.Errorf("failed to get count of blocked IPs after update: %v", err)
	}
	logger.Printf("Number of IPs in database after update: %d", countAfter)

	err = os.Remove(BLACKLIST_FILE)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error removing old blacklist: %v", err)
	}
	err = os.Rename(newBlacklistFile, BLACKLIST_FILE)
	if err != nil {
		return fmt.Errorf("error renaming new blacklist: %v", err)
	}

	logger.Println("Database initialized and blacklist updated.")
	return nil
}

func addIPsBatch(db *sql.DB, ips []string, ctx context.Context) error {
	query := "INSERT INTO blocked_ips (ip) VALUES "
	args := make([]interface{}, 0, len(ips))
	values := make([]string, 0, len(ips))

	for i, ip := range ips {
		args = append(args, ip)
		values = append(values, fmt.Sprintf("($%d)", i+1))
	}

	query += strings.Join(values, ",") + " ON CONFLICT (ip) DO NOTHING"

	_, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to insert batch of IPs: %v", err)
	}

	return nil
}

func updateBlacklist() error {
	cmd := exec.Command("bash", "-c", "curl https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt 2>/dev/null | grep -v '#' | cut -f 1 > ../database/data/blacklist-new.txt")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error updating blacklist: %v", err)
	}
	return nil
}
