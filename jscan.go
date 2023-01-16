package main

import (
    "bufio"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "regexp"
    "sync"
	"encoding/json"
	"flag"
)

type Matcher struct {
    Regex *regexp.Regexp
    PrintString string
}

type Output struct {
    URL string
    Matches []string
}

var jsonOutput = flag.Bool("json", false, "JSON output format")


func checkMatches(url string, body string, matchers []Matcher) {
    matchedStrings := make(map[string]bool)
    matches := []string{}
    for _, matcher := range matchers {
        match := matcher.Regex.FindAllStringSubmatch(body, -1)
        for _, submatches := range match {
            for i, submatch := range submatches {
                if !matchedStrings[submatch] {
                    matchedStrings[submatch] = true
                    if i == 0 {
                        matches = append(matches, matcher.PrintString + submatch)
                    } else {
                        matches = append(matches, submatch)
                    }
                }
            }
        }
    }
	if  len(matches) > 0 {
		if *jsonOutput {
			output := Output{URL:url, Matches:matches}
			jsonData, _ := json.Marshal(output)
			fmt.Println(string(jsonData))
		} else{
				fmt.Println("\n[URL] " + url)
				for _, match := range matches {
					fmt.Println(match)
				}
		}
	}

}


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
	flag.Parse()
    scanner := bufio.NewScanner(os.Stdin)
matchers := []Matcher{
    {
        Regex: regexp.MustCompile("(?i)AIza[0-9A-Za-z-_]{35}|(?i)6L[0-9A-Za-z-_]{38}|(?i)^6[0-9a-zA-Z_-]{39}$"),
        PrintString: "[Found] [google_api] ",
    },
    {
        Regex: regexp.MustCompile("(?i)A[SK]IA[0-9A-Z]{16}"),
        PrintString: "[Found] [amazon_aws_access_key_id] ",
    },
}


    var wg sync.WaitGroup
    semaphore := make(chan struct{}, 20)

    for scanner.Scan() {
        url := scanner.Text()
        semaphore <- struct{}{}
        wg.Add(1)
        go worker(url, matchers, &wg)
    }
    wg.Wait()
}
