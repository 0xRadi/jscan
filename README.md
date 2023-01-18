# jScan
This tool is used to scan a list of URLs for sensitive information such as API keys, access tokens, and private keys. It uses regular expressions to search for specific patterns in the body conent of the URLs provided and can output the results in either plain text or JSON format.

**jScan was made mainly to scan JS files for Secrets, and endpoints.**

# Install
```
go install github.com/0xRadi/jscan@latest
```

## Usage
To use this tool, provide a list of URLs to be scanned through stdin (e.g. by redirecting a file) and run the program with the desired flags.
- `-t 100` to increase the threads.
- `-json` to output the results in JSON format, use the flag.
- `-o results.json` to save results to specific file.
- `-q` for quite mode (no printing only save results to file)
- `-v` to enable verbose mode for debugging

For example:
`cat javascript_urls.txt | jscan -json -o output.json`
`echo http://google.com/file.js | jscan`




The program will then scan each URL in the provided list and output any sensitive information that is found in either plain text or JSON format, depending on the flags used.

## Customizing Matchers
The regular expressions used to search for sensitive information in the HTML can be customized by modifying the `matchers` variable in the main function. Each matcher is a struct containing two fields: `Regex` and `PrintString`. `Regex` is a regular expression used to search for a specific pattern and `PrintString` is the string that will be printed before the match when outputting results in plain text format.
