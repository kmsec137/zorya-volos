package main

import (
	"fmt"
	"os"
	"strconv"
	"sync"
)

// Shared state
type Cluster struct {
	mu      sync.Mutex
	metrics map[string]int
}

func main() {
	// Usage: go run main.go <num_threads> <use_locks: 0 or 1>
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go [threads] [use_locks]")
		return
	}

	threads, _ := strconv.Atoi(os.Args[1])
	useLocks, _ := strconv.Atoi(os.Args[2])

	db := &Cluster{
		metrics: make(map[string]int),
	}
	var wg sync.WaitGroup

	// Stress test with 'threads' (e.g., 30)
	for i := 0; i < threads; i++ {
		wg.Add(1)
		
		// Level 1
		go func(id int) {
			defer wg.Done()

			// Access shared resource
			if useLocks == 1 {
				db.mu.Lock()
				db.metrics["total"]++
				db.mu.Unlock()
			} else {
				db.metrics["total"]++ // DATA RACE Level 1
			}

			// Level 2
			if id%2 == 0 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					
					// Level 3
					wg.Add(1)
					go func() {
						defer wg.Done()
						
						// Level 4
						wg.Add(1)
						go func() {
							defer wg.Done()
							
							// Level 5: The deep strike
							wg.Add(1)
							go func() {
								defer wg.Done()
								if useLocks == 1 {
									db.mu.Lock()
									db.metrics["deep_hit"] = id
									db.mu.Unlock()
								} else {
									db.metrics["deep_hit"] = id // DATA RACE Level 5
								}
							}()
							
							// Level 4 concurrent logic
							db.metrics["breadcrumb"] = 4
						}()
					}()
				}()
			}
		}(i)
	}

	wg.Wait()
	fmt.Println("Simulation complete. Metrics:", db.metrics["total"])
}
