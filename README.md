# Overview
This tool is used to scan a list of URLs for sensitive information such as API keys, access tokens, and private keys. It uses regular expressions to search for specific patterns in the HTML of the URLs and can output the results in either plain text or JSON format.

# Install
```
go install github.com/0xRadi/jscan@latest
```

## Usage
To use this tool, provide a list of URLs to be scanned through stdin (e.g. by redirecting a file) and run the program with the desired flags.
- To increase the threads `-t 100`
- To output the results in JSON format, use the flag `-json`.
- To save results to specific file `-o results.json`
- For quite mode (no printing only save results to file) use `-q`
- To enable verbose mode, use the flag `-v`.

For example:
`cat urls.txt | jscan -json -v`




The program will then scan each URL in the provided list and output any sensitive information that is found in either plain text or JSON format, depending on the flags used.

## Customizing Matchers
The regular expressions used to search for sensitive information in the HTML can be customized by modifying the `matchers` variable in the main function. Each matcher is a struct containing two fields: `Regex` and `PrintString`. `Regex` is a regular expression used to search for a specific pattern and `PrintString` is the string that will be printed before the match when outputting results in plain text format.
