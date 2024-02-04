package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

var verbose bool

func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

func performRequest(url, data, cookie string) (bool, string) {
	urlWithData := fmt.Sprintf("%s%s", url, data)
	startTime := time.Now()

	resp, err := http.Get(urlWithData)
	if err != nil {
		return false, fmt.Sprintf("\033[1;31mURL %s - Error: %s\033[0m", urlWithData, err)
	}
	defer resp.Body.Close()

	responseTime := time.Since(startTime).Seconds()

	if resp.StatusCode == http.StatusOK && responseTime > 20 {
		vulnerabilityMsg := fmt.Sprintf("\033[1;31mURL %s - %.2f seconds - Vulnerable\033[0m", urlWithData, responseTime)
		return true, vulnerabilityMsg
	} else if verbose {
		return false, fmt.Sprintf("\033[1;32mURL %s - %.2f seconds\033[0m", urlWithData, responseTime)
	}

	return false, ""
}

func main() {
	urlsFile := flag.String("u", "", "Text file with the URLs to which the GET request will be made.")
	dataFile := flag.String("d", "", "Text file with the data that will be appended to the URLs.")
	cookie := flag.String("C", "", "Cookie to include in the GET request.")
	flag.BoolVar(&verbose, "v", false, "Show detailed information during execution.")
	flag.Parse()

	if *urlsFile == "" || *dataFile == "" {
		log.Fatal("You must provide files for URLs and data.")
	}

	urls, err := readLines(*urlsFile)
	if err != nil {
		log.Fatalf("Error reading the URLs file.: %s", err)
	}

	data, err := readLines(*dataFile)
	if err != nil {
		log.Fatalf("Error reading the data file.: %s", err)
	}

	var wg sync.WaitGroup

	for _, url := range urls {
		vulnerabilityFound := false
		for _, d := range data {
			wg.Add(1)
			go func(url, d string) {
				defer wg.Done()
				if found, result := performRequest(url, d, *cookie); found {
					// Set a flag to skip remaining iterations for this URL
					vulnerabilityFound = true
					// Print the vulnerability message
					fmt.Println(result)
				}
			}(url, d)

			// Check if vulnerability found
			if vulnerabilityFound {
				break
			}
		}
	}

	// Wait for all goroutines to finish
	wg.Wait()
}

