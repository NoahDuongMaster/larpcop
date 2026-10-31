package main

import "os"

func main() {
	if _, err := os.Stat("config.yaml"); err != nil {
		panic(err)
	}
}
