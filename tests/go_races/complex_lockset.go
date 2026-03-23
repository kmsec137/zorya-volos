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
	adminMu sync.Mutex
	shards  []*Shard
}

func main() {
	// os.Args[0] = program name
	// os.Args[1] = first arg ('a')
	// os.Args[2] = second arg ('b')
	// os.Args[3] = third arg (iterations)
	if len(os.Args) != 4 {
		fmt.Println("Usage: go run main.go <a> <b> <iterations>")
		return
	}

	arg1 := os.Args[1]
	arg2 := os.Args[2]
	iterations, _ := strconv.Atoi(os.Args[3])

	// Logic check: only proceed if first arg is 'a' and second is 'b'
	shouldLock := (arg1 == "a" && arg2 == "b")

	if !shouldLock {
		fmt.Printf("Conditions not met (Args: %s, %s). Skipping execution.\n", arg1, arg2)
		return
	}

	fmt.Printf("Conditions met. Running with %d iterations...\n", iterations)

	srv := &Server{
		shards: []*Shard{
			{data: make(map[int]string)},
			{data: make(map[int]string)},
		},
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// --- Thread A: Shard Lock ---
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			shard := srv.shards[0]
			shard.mu.Lock()
			shard.counter++
			shard.data[i] = "Update From Shard Lock"
			shard.mu.Unlock()
		}
	}()

	// --- Thread B: Admin Lock (Mismatched Lockset) ---
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			srv.adminMu.Lock()
			srv.shards[0].counter--
			srv.shards[0].data[i] = "Update From Admin Lock"
			srv.adminMu.Unlock()
		}
	}()

	wg.Wait()
	fmt.Println("Finished. Run with -race to see the lockset violation.")
}
