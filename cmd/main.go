package main

import (
	"log"
)

// Not Implemented
func bootsrap() error {
	return nil
}

// Abstract
func main() {

	if err := bootsrap(); err != nil {
		log.Fatal(err)
	}
}
