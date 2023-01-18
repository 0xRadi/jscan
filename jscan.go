package main

import (
	"bufio" // package for reading input from the command line
	"crypto/tls"
	"encoding/json" // package for encoding and decoding JSON
	"flag"          // package for parsing command line flags
	"fmt"           // package for formatting and printing output
	"io"
	"io/ioutil" // package for reading and writing files
	"net"
	"net/http" // package for making HTTP requests
	"net/url"
	"os"     // package for interacting with the operating system
	"regexp" // package for working with regular expressions
	"strings"
	"sync" // package for synchronizing goroutines
	"time"
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
var verbose = flag.Bool("v", false, "Verbose mode")
var quite = flag.Bool("q", false, "start in silent mode with no stdout")
var threadCount = flag.Int("t", 20, "Number of threads")
var outputFile = flag.String("o", "", "File to save output")

// checkMatches function takes in a URL, a string of the body of the URL, and a slice of Matcher structs
// it uses the regular expressions in the Matcher structs to find matches in the body of the URL
// it stores the matches in a slice and prints the matches in either JSON or plain text format
func checkMatches(link string, body string, matchers []Matcher) {
	matchedStrings := make(map[string]bool) // store matched strings to prevent duplicates
	matches := []string{}                   // slice to store matches

	// to exclude some rubbish findings
	exclusionList := []string{"text", "w3", "video", "image", "application", "multipart", "d/y", "m/y"}

	for _, matcher := range matchers {
		match := matcher.Regex.FindAllStringSubmatch(body, -1)
		for _, submatches := range match {
			for i, submatch := range submatches {
				matchExcluded := false
				for _, excludedWord := range exclusionList {
					if strings.Contains(submatch, excludedWord) {
						matchExcluded = true
						break
					}
				}
				if !matchedStrings[submatch] && !matchExcluded {
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
			output := Output{URL: link, Matches: matches}
			jsonData, _ := json.Marshal(output)
			outputStr := string(jsonData)
			if !*quite {
				fmt.Println(string(jsonData))
			}
			// check -o argv
			if *outputFile != "" {
				f, _ := os.OpenFile(*outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				defer f.Close()
				io.WriteString(f, outputStr)
			}
		} else {
			if !*quite {
				// Prints ASCII output
				fmt.Println("\n[URL] " + link)
			}

			// to save to output file
			outputStr := "\n[URL] " + link + "\n"

			for _, match := range matches {
				if !*quite {
					fmt.Println(match)
				}
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
func worker(link string, matchers []Matcher, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		<-semaphore
	}()
	defer wg.Done()
	if *verbose {
		println("[DEBUG] " + link)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   time.Second * 10,
			KeepAlive: time.Second,
		}).DialContext,
	}
	client := &http.Client{Transport: transport}

	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:174.0) Gecko/20100101 Firefox/174.0"

	req, _ := http.NewRequest("GET", link, nil)
	req.Header.Set("User-Agent", userAgent)

	if _, err := url.Parse(link); err != nil {
		if *verbose {
			fmt.Println(err)
		}
		return
	}

	resp, err := client.Do(req)

	if err != nil {
		if *verbose {
			fmt.Println(err)
		}
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	if resp.StatusCode != 200 {
		return
	}
	checkMatches(link, string(body), matchers)
}

func main() {
	flag.Parse() // parse command line flags

	scanner := bufio.NewScanner(os.Stdin) // create a scanner to read input from the command line

	//TODO Matchers to be loaded from JSON file

	// Matchers for Secrets or endpoints
	matchers := []Matcher{
		{
			Regex:       regexp.MustCompile("(?i)[\"'(]AIza[0-9A-Za-z-_]{35}|(?i)[\"'(]6L[0-9A-Za-z-_]{38}|(?i)[\"'(]6[0-9a-zA-Z_-]{39}[\"')]"),
			PrintString: "[Found] [google_api] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)A[SK]IA[0-9A-Z]{16}"),
			PrintString: "[Potential] [amazon_aws_access_key_id] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
			PrintString: "[Found] [firebase] ",
		},
		{
			Regex:       regexp.MustCompile("[\"'(]6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}[\"')]"),
			PrintString: "[Potential] [google_captcha] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)ya29\\.[0-9A-Za-z\\-_]+"),
			PrintString: "[Found] [google_oauth] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)amzn\\\\.mws\\\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
			PrintString: "[Found] [amazon_mws_auth_toke] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)s3\\.amazonaws\\.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws\\.com"),
			PrintString: "[Potential] [amazon_aws_url] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)EAACEdEose0cBA[0-9A-Za-z]+"),
			PrintString: "[Found] [facebook_access_token] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)bearer[a-zA-Z0-9_\\-\\.=:_+/]{5,100}"),
			PrintString: "[Potential] [authorization_bearer] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)key-[0-9a-zA-Z]{32}"),
			PrintString: "[Found] [mailgun_api_key] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"),
			PrintString: "[Found] [paypal_braintree_access_token] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)[\"'(]sq0csp-[0-9A-Za-z\\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\\-_]{22,43}[\"')]"),
			PrintString: "[Found] [square_oauth_secret] ",
		},
		{
			Regex:       regexp.MustCompile("sqOatp-[0-9A-Za-z\\-_]{22}|EAAA[a-zA-Z0-9]{60}"),
			PrintString: "[Potential] [square_access_token] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)sk_live_[0-9a-zA-Z]{24}"),
			PrintString: "[Found] [stripe_standard_api] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)rk_live_[0-9a-zA-Z]{24}"),
			PrintString: "[Found] [stripe_restricted_api] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*"),
			PrintString: "[Found] [github_access_token] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)-----BEGINRSAPRIVATEKEY-----"),
			PrintString: "[Found] [rsa_private_key] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)-----BEGINDSAPRIVATEKEY-----"),
			PrintString: "[Found] [ssh_dsa_private_key] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)-----BEGINECPRIVATEKEY-----"),
			PrintString: "[Found] [ssh_dc_private_key] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)-----BEGINPGPPRIVATEKEYBLOCK-----"),
			PrintString: "[Found] [pgp_private_block] ",
		},
		{
			Regex:       regexp.MustCompile("(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"),
			PrintString: "[Found] [slack_token] ",
		},
		{
			Regex:       regexp.MustCompile("https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"),
			PrintString: "[Found] [slack webhook] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)([-]+BEGIN[^\\s]+PRIVATEKEY[-]+[\\s]*[^-]*[-]+END[^\\s]+PRIVATEKEY[-]+)"),
			PrintString: "[Found] [SSH_privKey] ",
		},
		//{
		//	Regex:       regexp.MustCompile("(?i)(password\\s*[`=:\"]+\\s*[^\\s]+|passwordis\\s*[`=:\"]*\\s*[^\\s]+|pwd\\s*[`=:\"]*\\s*[^\\s]+|passwd\\s*[`=:\"]+\\s*[^\\s]+)"),
		//	PrintString: "[Secret] [possible_Creds] ",
		//},

		// SecretScanner Regex
		//https://github.com/deepfence/SecretScanner/blob/bbc861dca497b01870d31a35d77ec51fc82f21a2/config.yaml
		{
			Regex:       regexp.MustCompile("(?i)appid=(\"|'|`)?[0-9a-f]{32}(\"|'|`)?"),
			PrintString: "[Found] [OpenWeather API Key] ",
		},
		{
			Regex:       regexp.MustCompile("oy2[a-z0-9]{43}"),
			PrintString: "[Found] [NuGet API Key] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)hockey.{0,50}(\"|'|`)?[0-9a-f]{32}(\"|'|`)?"),
			PrintString: "[Found] [HockeyApp] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)sonar.{0,50}(\"|'|`)?[0-9a-f]{40}(\"|'|`)?"),
			PrintString: "[Found] [SonarQube Docs API Key] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)hockey.{0,50}(\"|'|`)?[0-9a-f]{32}(\"|'|`)"),
			PrintString: "[Found] [HockeyApp] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)heroku(.{0,20})?[''\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[''\"]"),
			PrintString: "[Found] [Heroku API key] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)linkedin(.{0,20})?(?-i)[''\\\"][0-9a-z]{12}[''\\\"]"),
			PrintString: "[Found] [Linkedin Client ID] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)linkedin(.{0,20})?[''\"][0-9a-z]{16}[''\"]"),
			PrintString: "[Found] [LinkedIn Secret Key] ",
		},
		{
			Regex:       regexp.MustCompile("hawk\\.[0-9A-Za-z\\-_]{20}\\.[0-9A-Za-z\\-_]{20}"),
			PrintString: "[Found] [StackHawk API Key] ",
		},
		{
			Regex:       regexp.MustCompile("SG\\.[0-9A-Za-z\\-_]{22}\\.[0-9A-Za-z\\-_]{43}"),
			PrintString: "[Found] [SendGrid API Key] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)twitter(.{0,20})?[''\"][0-9a-z]{35,44}[''\"]"),
			PrintString: "[Found] [Twitter Secret Key] ",
		},
		{
			Regex:       regexp.MustCompile("sk_[live|test]_[0-9a-z]{32}"),
			PrintString: "[Found] [Picatic API key] ",
		},
		{
			Regex:       regexp.MustCompile("(?i)resumatorapi\\.com+"),
			PrintString: "[Found] [JazzHR] ",
		},
		{
			Regex:       regexp.MustCompile("[\"'(][0-9a-fA-F]{32}[\"')]"),
			PrintString: "[Potential] [API Key] ",
		},

		// js-miner Regex
		// https://github.com/PortSwigger/js-miner/blob/main/src/main/java/burp/utils/Constants.java
		{
			Regex:       regexp.MustCompile("secret[_-]?(key|token|secret)|api[_-]?(key|token|secret)|access[_-]?(key|token|secret)|auth[_-]?(key|token|secret)|session[_-]?(key|token|secret)|consumer[_-]?(key|token|secret)|client[_-]?(id|token|key)|ssh[_-]?key|encrypt[_-]?(secret|key)|decrypt[_-]?(secret|key)"),
			PrintString: "[Potential] [Secret] ",
		},
		{
			// Improved to ignore versions eg. tool@2.7.2
			Regex:       regexp.MustCompile("[a-zA-Z0-9_.+-]+@[a-zA-Z]{1}[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+"),
			PrintString: "[Found] [EMAIL] ",
		},
		{
			Regex:       regexp.MustCompile(`(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\[\\]]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\\?|#][^"|']{0,}|)))(?:"|')`),
			PrintString: "[Endpoint] ",
		},
	}

	var wg sync.WaitGroup // create a WaitGroup to wait for all goroutines to finish

	semaphore := make(chan struct{}, *threadCount) // create a semaphore to limit the number of concurrent goroutines

	for scanner.Scan() {
		link := scanner.Text()
		semaphore <- struct{}{}                   // acquire a spot in the semaphore
		wg.Add(1)                                 // increment the WaitGroup
		go worker(link, matchers, &wg, semaphore) // start the worker goroutine
	}
	wg.Wait() // wait for all goroutines to finish
}
