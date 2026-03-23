package main

import (
	"fmt"
	"os"
	"strconv"
	"sync"
)

var (
	sharedCounter int
	mu            sync.Mutex
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <a|b|c> <iterations>")
		return
	}

	mode := os.Args[1]
	iterations, _ := strconv.Atoi(os.Args[2])
	var wg sync.WaitGroup

	switch mode {
	case "a":
		fmt.Println("Mode A: Single Level Nesting")
		wg.Add(1)
		go func() {
			defer wg.Done()
			runWork("T1", iterations)
		}()

	case "b":
		fmt.Println("Mode B: Two-Level Nesting (T1 -> T2)")
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			// Inner Nesting
			var innerWg sync.WaitGroup
			innerWg.Add(1)
			go func() {
				defer innerWg.Done()
				runWork("T2", iterations)
			}()
			
			runWork("T1", iterations)
			innerWg.Wait()
		}()

	case "c":
		fmt.Println("Mode C: Three-Level Nesting (T1 -> T2 -> T3)")
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			// Level 2
			var wg2 sync.WaitGroup
			wg2.Add(1)
			go func() {
				defer wg2.Done()
				
				// Level 3
				var wg3 sync.WaitGroup
				wg3.Add(1)
				go func() {
					defer wg3.Done()
					runWork("T3", iterations)
				}()
				
				runWork("T2", iterations)
				wg3.Wait()
			}()
			
			runWork("T1", iterations)
			wg2.Wait()
		}()

	default:
		fmt.Println("Unknown mode. Use a, b, or c.")
		return
	}

	wg.Wait()
	fmt.Printf("Final Result: %d\n", sharedCounter)
}

func runWork(label string, iters int) {
	for i := 0; i < iters; i++ {
		mu.Lock()
		sharedCounter++
		mu.Unlock()
	}
	fmt.Printf("[%s] Finished %d increments\n", label, iters)
}
