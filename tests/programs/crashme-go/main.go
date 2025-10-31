package main

import (
	"fmt"
	"os"
	"runtime"
)

func crash(arg byte) {
	if arg == 'K' {
		var p *int
		*p = 0
	}
}

func main() {
	runtime.GOMAXPROCS(1)
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./crashme [char]")
		return
	}
	arg := os.Args[1][0]
	crash(arg)
	fmt.Println("OK")
}
