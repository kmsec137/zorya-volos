package main

import (
	"fmt"
	"os"
	"strconv"
	"sync"
)

type Shard struct {
	mu      sync.Mutex
	data    map[int]string
	counter int
}

type Server struct {
	// Global lock for top-level operations
	adminMu sync.Mutex
	shards  []*Shard
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <iterations>")
		return
	}
	iterations, _ := strconv.Atoi(os.Args[1])

	srv := &Server{
		shards: []*Shard{
			{data: make(map[int]string)},
			{data: make(map[int]string)},
		},
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// --- Thread A: Holds the Shard Lock ---
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			shard := srv.shards[0]
			
			shard.mu.Lock() 
			// Thread A thinks it's safe because it's holding the Shard lock
			shard.counter++
			shard.data[i] = "Update From Shard Lock"
			shard.mu.Unlock()
		}
	}()

	// --- Thread B: Holds the Admin Lock (Nested/Mismatch) ---
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			// Thread B locks the WHOLE server instead of the specific shard
			srv.adminMu.Lock()
			
			// RACE CONDITION: Thread B is modifying shard[0] while 
			// holding adminMu, but Thread A is modifying shard[0] 
			// while holding shards[0].mu. 
			// The locksets {adminMu} and {shard.mu} do not intersect!
			srv.shards[0].counter--
			srv.shards[0].data[i] = "Update From Admin Lock"
			
			srv.adminMu.Unlock()
		}
	}()

	wg.Wait()
	fmt.Println("Finished. Run with -race to see the lockset violation.")
}
