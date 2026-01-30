package main

import (
	"sync"
)

type Database struct {
	mu      sync.Mutex
	records map[int]string
	queries int
}

func main() {
	db := &Database{
		records: make(map[int]string),
	}
	var wg sync.WaitGroup
	wg.Add(20)

	// --- 10 Goroutines using Locks correctly ---
	go func() { defer wg.Done(); db.mu.Lock(); db.records[1] = "A"; db.mu.Unlock() }()
	go func() { defer wg.Done(); db.mu.Lock(); db.records[2] = "B"; db.mu.Unlock() }()
	go func() { defer wg.Done(); db.mu.Lock(); db.records[3] = "C"; db.mu.Unlock() }()
	go func() { defer wg.Done(); db.mu.Lock(); db.records[4] = "D"; db.mu.Unlock() }()
	go func() { defer wg.Done(); db.mu.Lock(); db.records[5] = "E"; db.mu.Unlock() }()
	go func() { defer wg.Done(); db.mu.Lock(); db.queries++; db.mu.Unlock() }()
	go func() { defer wg.Done(); db.mu.Lock(); db.queries++; db.mu.Unlock() }()
	go func() { defer wg.Done(); db.mu.Lock(); db.queries++; db.mu.Unlock() }()
	go func() { defer wg.Done(); db.mu.Lock(); db.queries++; db.mu.Unlock() }()
	go func() { defer wg.Done(); db.mu.Lock(); db.queries++; db.mu.Unlock() }()

	// --- 5 Goroutines with "Lazy" Locking (Read-Write Race) ---
	// These lock for the write, but read the 'queries' count outside the lock
	go func() { defer wg.Done(); _ = db.queries; db.mu.Lock(); db.records[6] = "F"; db.mu.Unlock() }()
	go func() { defer wg.Done(); _ = db.queries; db.mu.Lock(); db.records[7] = "G"; db.mu.Unlock() }()
	go func() { defer wg.Done(); _ = db.queries; db.mu.Lock(); db.records[8] = "H"; db.mu.Unlock() }()
	go func() { defer wg.Done(); _ = db.queries; db.mu.Lock(); db.records[9] = "I"; db.mu.Unlock() }()
	go func() { defer wg.Done(); _ = db.queries; db.mu.Lock(); db.records[10] = "J"; db.mu.Unlock() }()

	// --- 5 Goroutines that are totally "Rogue" (Direct Race) ---
	// These will likely cause a "fatal error: concurrent map iteration and map write"
	go func() { defer wg.Done(); db.records[99] = "Rogue1" }()
	go func() { defer wg.Done(); db.queries = 100 }()
	go func() { defer wg.Done(); _ = db.records[1] }()
	go func() { defer wg.Done(); db.records[1] = "Overwrite" }()
	go func() { defer wg.Done(); db.queries-- }()

	wg.Wait()
}
