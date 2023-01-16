package main

import (
	"bufio"         // package for reading input from the command line
	"encoding/json" // package for encoding and decoding JSON
	"flag"          // package for parsing command line flags
	"fmt"           // package for formatting and printing output
	"io/ioutil"     // package for reading and writing files
	"net/http"      // package for making HTTP requests
	"os"            // package for interacting with the operating system
	"regexp"        // package for working with regular expressions
	"sync"          // package for synchronizing goroutines
)

// Matcher struct defines a struct for storing a regular expression and a string to print when a match is found
type Matcher struct {
	Regex       *regexp.Regexp // regular expression to match
	PrintString string         // string to print when a match is found
}

// Output struct defines a struct for storing the URL and matches found for a given URL
type Output struct {
	URL     string   // the URL that was searched
	Matches []string // the matches found for the URL
}

// flags that can be passed in through the command line
var jsonOutput = flag.Bool("json", false, "JSON output format")
var threadCount = flag.Int("t", 20, "Number of threads")

// checkMatches function takes in a URL, a string of the body of the URL, and a slice of Matcher structs
// it uses the regular expressions in the Matcher structs to find matches in the body of the URL
// it stores the matches in a slice and prints the matches in either JSON or plain text format
func checkMatches(url string, body string, matchers []Matcher) {
	matchedStrings := make(map[string]bool) // store matched strings to prevent duplicates
	matches := []string{}                   // slice to store matches
	for _, matcher := range matchers {
		match := matcher.Regex.FindAllStringSubmatch(body, -1)
		for _, submatches := range match {
			for i, submatch := range submatches {
				if !matchedStrings[submatch] {
					matchedStrings[submatch] = true
					if i == 0 {
						matches = append(matches, matcher.PrintString+submatch)
					} else {
						matches = append(matches, submatch)
					}
				}
			}
		}
	}
	// it prints JSON if -json is found
	if len(matches) > 0 {
		if *jsonOutput {
			output := Output{URL: url, Matches: matches}
			jsonData, _ := json.Marshal(output)
			fmt.Println(string(jsonData))
		} else {
			fmt.Println("\n[URL] " + url)
			for _, match := range matches {
				fmt.Println(match)
			}
		}
	}

}

// worker function is a goroutine that takes in a URL, a slice of Matcher structs, and a WaitGroup
// it makes an HTTP GET request to the given URL
// it reads the body of the response and passes the URL and body to the checkMatches function
// it decrements the WaitGroup when it finishes
func worker(url string, matchers []Matcher, wg *sync.WaitGroup) {
	defer wg.Done()
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	checkMatches(url, string(body), matchers)
}

func main() {
	flag.Parse() // parse command line flags

	scanner := bufio.NewScanner(os.Stdin) // create a scanner to read input from the command line

	// Matchers for Secrets or endpoints
	matchers := []Matcher{
		{
			Regex:       regexp.MustCompile("(?i)AIza[0-9A-Za-z-_]{35}|(?i)6L[0-9A-Za-z-_]{38}|(?i)^6[0-9a-zA-Z_-]{39}$"),
			PrintString: "[Found] [google_api] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)A[SK]IA[0-9A-Z]{16}"),
			PrintString: "[Found] [amazon_aws_access_key_id] ",
		},
	}

	var wg sync.WaitGroup                          // create a WaitGroup to wait for all goroutines to finish
	semaphore := make(chan struct{}, *threadCount) // create a semaphore to limit the number of concurrent goroutines

	for scanner.Scan() {
		url := scanner.Text()
		semaphore <- struct{}{}       // acquire a spot in the semaphore
		wg.Add(1)                     // increment the WaitGroup
		go worker(url, matchers, &wg) // start the worker goroutine
	}
	wg.Wait() // wait for all goroutines to finish
}
