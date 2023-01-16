package main

import (
	"bufio"         // package for reading input from the command line
	"encoding/json" // package for encoding and decoding JSON
	"flag"          // package for parsing command line flags
	"fmt"           // package for formatting and printing output
	"io"
	"io/ioutil" // package for reading and writing files
	"net/http"  // package for making HTTP requests
	"os"        // package for interacting with the operating system
	"regexp"    // package for working with regular expressions
	"sync"      // package for synchronizing goroutines
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
var outputFile = flag.String("o", "ja_analysis.txt", "File to save output")

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
						//matches = append(matches, submatch)
						matches = append(matches)
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
			outputStr := string(jsonData)
			fmt.Println(string(jsonData))

			// check -o argv
			if *outputFile != "" {
				f, _ := os.OpenFile(*outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				defer f.Close()
				io.WriteString(f, outputStr)
			}
		} else {
			// Prints ASCII output
			fmt.Println("\n[URL] " + url)

			// to save to output file
			outputStr := "\n[URL] " + url + "\n"

			for _, match := range matches {
				fmt.Println(match)

				// to save to output file
				outputStr += match + "\n"
			}
			// check -o argv
			if *outputFile != "" {
				f, _ := os.OpenFile(*outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				defer f.Close()
				io.WriteString(f, outputStr)
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

	//TODO Matchers to be loaded from JSON file

	// Matchers for Secrets or endpoints
	matchers := []Matcher{
		{
			Regex:       regexp.MustCompile("(?i)AIza[0-9A-Za-z-_]{35}|(?i)6L[0-9A-Za-z-_]{38}|(?i)^6[0-9a-zA-Z_-]{39}$"),
			PrintString: "[Secret] [google_api] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)A[SK]IA[0-9A-Z]{16}"),
			PrintString: "[Secret] [amazon_aws_access_key_id] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
			PrintString: "[Secret] [firebase] ",
		},
		{
			Regex:       regexp.MustCompile("6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$"),
			PrintString: "[Secret] [google_captcha] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)ya29\\.[0-9A-Za-z\\-_]+"),
			PrintString: "[Secret] [google_oauth] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)amzn\\\\.mws\\\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
			PrintString: "[Secret] [amazon_mws_auth_toke] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)s3\\.amazonaws\\.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws\\.com"),
			PrintString: "[Secret] [amazon_aws_url] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)EAACEdEose0cBA[0-9A-Za-z]+"),
			PrintString: "[Secret] [facebook_access_token] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)bearer[a-zA-Z0-9_\\-\\.=:_+/]{5,100}"),
			PrintString: "[Secret] [authorization_bearer] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)key-[0-9a-zA-Z]{32}"),
			PrintString: "[Secret] [mailgun_api_key] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"),
			PrintString: "[Secret] [paypal_braintree_access_token] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)sq0csp-[0-9A-Za-z\\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\\-_]{22,43}"),
			PrintString: "[Secret] [square_oauth_secret] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)sqOatp-[0-9A-Za-z\\-_]{22}|EAAA[a-zA-Z0-9]{60}"),
			PrintString: "[Secret] [square_access_token] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)sk_live_[0-9a-zA-Z]{24}"),
			PrintString: "[Secret] [stripe_standard_api] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)rk_live_[0-9a-zA-Z]{24}"),
			PrintString: "[Secret] [stripe_restricted_api] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*"),
			PrintString: "[Secret] [github_access_token] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)-----BEGINRSAPRIVATEKEY-----"),
			PrintString: "[Secret] [rsa_private_key] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)-----BEGINDSAPRIVATEKEY-----"),
			PrintString: "[Secret] [ssh_dsa_private_key] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)-----BEGINECPRIVATEKEY-----"),
			PrintString: "[Secret] [ssh_dc_private_key] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)-----BEGINPGPPRIVATEKEYBLOCK-----"),
			PrintString: "[Secret] [pgp_private_block] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)ey[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$"),
			PrintString: "[Secret] [json_web_token] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\""),
			PrintString: "[Secret] [slack_token] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)([-]+BEGIN[^\\s]+PRIVATEKEY[-]+[\\s]*[^-]*[-]+END[^\\s]+PRIVATEKEY[-]+)"),
			PrintString: "[Secret] [SSH_privKey] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)(password\\s*[`=:\"]+\\s*[^\\s]+|passwordis\\s*[`=:\"]*\\s*[^\\s]+|pwd\\s*[`=:\"]*\\s*[^\\s]+|passwd\\s*[`=:\"]+\\s*[^\\s]+)"),
			PrintString: "[Secret] [possible_Creds] ",
		},
		{
			Regex:       regexp.MustCompile(`(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\\[\\]]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\\?|#][^"|']{0,}|)))(?:"|')`),
			PrintString: "[Endpoint] ",
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
