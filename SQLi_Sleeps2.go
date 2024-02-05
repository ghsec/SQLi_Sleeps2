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

const (
	errorColor     = "\033[1;31m"
	successColor   = "\033[1;32m"
	resetColor     = "\033[0m"
	minResponseTime = 20.0
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

func performRequest(url, data, cookie string, ch chan<- string, maxResponseTime float64) {
	urlWithData := fmt.Sprintf("%s%s", url, data)
	startTime := time.Now()

	resp, err := http.Get(urlWithData)
	if err != nil {
		ch <- fmt.Sprintf("%sURL %s - Error: %s%s", errorColor, urlWithData, err, resetColor)
		return
	}
	defer resp.Body.Close()

	responseTime := time.Since(startTime).Seconds()

	if found, result := isVulnerable(resp, responseTime, urlWithData, verbose, maxResponseTime); found {
		ch <- result
	}
}

func isVulnerable(resp *http.Response, responseTime float64, urlWithData string, verbose bool, maxResponseTime float64) (bool, string) {
	if resp.StatusCode == http.StatusOK && isWithinResponseTimeRange(responseTime, maxResponseTime) {
		return true, fmt.Sprintf("%sURL %s - %.2f seconds - Vulnerable%s", errorColor, urlWithData, responseTime, resetColor)
	} else if verbose {
		return false, fmt.Sprintf("%sURL %s - %.2f seconds%s", successColor, urlWithData, responseTime, resetColor)
	}
	return false, ""
}

func isWithinResponseTimeRange(responseTime, maxResponseTime float64) bool {
	return responseTime >= minResponseTime && responseTime < maxResponseTime
}

func main() {
	urlsFile := flag.String("u", "", "Text file with the URLs to which the GET request will be made.")
	dataFile := flag.String("d", "", "Text file with the data that will be appended to the URLs.")
	cookie := flag.String("C", "", "Cookie to include in the GET request.")
	responseTimeFlag := flag.Float64("r", 22.0, "Maximum response time considered vulnerable.")
	flag.BoolVar(&verbose, "v", false, "Show detailed information during execution.")
	flag.Parse()

	if *urlsFile == "" || *dataFile == "" {
		log.Fatal("You must provide files for URLs and data.")
	}

	urls, err := readLines(*urlsFile)
	if err != nil {
		log.Fatalf("Error reading the URLs file: %s", err)
	}

	data, err := readLines(*dataFile)
	if err != nil {
		log.Fatalf("Error reading the data file: %s", err)
	}

	var wg sync.WaitGroup
	ch := make(chan string)

	for _, url := range urls {
		for _, d := range data {
			wg.Add(1)
			go func(url, d string) {
				defer wg.Done()
				performRequest(url, d, *cookie, ch, *responseTimeFlag)
			}(url, d)
		}
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for result := range ch {
		log.Println(result)
	}
}
