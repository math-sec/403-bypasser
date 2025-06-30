package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/time/rate"
)

var (
	successColor = color.New(color.FgGreen).SprintFunc()
	warningColor = color.New(color.FgYellow).SprintFunc()
	infoColor    = color.New(color.FgCyan).SprintFunc()
)

type Config struct {
	URL                    string
	URLList                string
	HTTPMethodsFile        string
	HTTPHeadersFile        string
	UserAgentsFile         string
	HopByHopHeadersFile    string
	Concurrency            int
	Timeout                time.Duration
	Insecure               bool
	ModesToRun             map[string]bool
	FilterSizes            map[int]bool
	FalsePositiveThreshold int
	RunHTTP09              bool
	SuccessOnly            bool
	OutputFile             string
}

type Scanner struct {
	config           Config
	client           *http.Client
	limiter          *rate.Limiter
	sharedSignatures *SharedSignatureMap
	bar              *progressbar.ProgressBar
}

type Result struct {
	URL        string
	Technique  string
	Payload    string
	StatusCode int
	Size       int
	Reason     string
	Curl       string
}

type SharedSignatureMap struct {
	Signatures map[string]int
	Mutex      *sync.Mutex
}

func printInfo(msg string) {
	fmt.Fprintf(os.Stderr, "[%s] %s\n", infoColor("INFO"), msg)
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
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

func generateCurlCommand(req *http.Request, technique string) string {
	var command strings.Builder
	command.WriteString("curl -X ")
	command.WriteString(req.Method)
	command.WriteString(fmt.Sprintf(" '%s'", req.URL.String()))
	for key, values := range req.Header {
		lowerKey := strings.ToLower(key)
		if lowerKey == "host" || lowerKey == "content-length" {
			continue
		}
		if lowerKey == "user-agent" && technique != "User-Agent Fuzzing" {
			continue
		}
		for _, value := range values {
			command.WriteString(fmt.Sprintf(" -H '%s: %s'", key, value))
		}
	}
	if req.TLS != nil {
		command.WriteString(" -k")
	}
	return command.String()
}

func (s *Scanner) log(level int, format string, args ...interface{}) {
	// A função de log foi removida conforme solicitado para simplificar.
}

func newScanner(config Config, limiter *rate.Limiter, sharedSigs *SharedSignatureMap, bar *progressbar.ProgressBar) *Scanner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: config.Insecure},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Scanner{
		config:           config,
		client:           client,
		limiter:          limiter,
		sharedSignatures: sharedSigs,
		bar:              bar,
	}
}

func (s *Scanner) sendRequest(method, targetURL string, headers map[string]string) (*http.Response, *http.Request, error) {
	if s.limiter != nil {
		s.limiter.Wait(context.Background())
	}
	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if _, found := headers["Host"]; !found {
	} else if headers["Host"] == "" {
		req.Host = ""
	}
	if s.bar != nil {
		_ = s.bar.Add(1)
	}
	resp, err := s.client.Do(req)
	return resp, req, err
}

func (s *Scanner) scan(baseURL string, resultsChan chan<- Result) {
	if s.bar != nil {
		s.bar.Describe(fmt.Sprintf("Testing %s", baseURL))
	}
	resp, _, err := s.sendRequest("GET", baseURL, nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	initialStatusCode := resp.StatusCode
	initialBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	initialSize := len(initialBody)
	runAll := s.config.ModesToRun["all"]
	var testFuncs []func()
	if runAll || s.config.ModesToRun["path"] {
		testFuncs = append(testFuncs, func() { s.testPathPermutations(baseURL, initialStatusCode, initialSize, resultsChan) })
	}
	if runAll || s.config.ModesToRun["method"] {
		testFuncs = append(testFuncs, func() { s.testHTTPMethods(baseURL, initialStatusCode, initialSize, resultsChan) })
	}
	if runAll || s.config.ModesToRun["header"] {
		testFuncs = append(testFuncs, func() { s.testHeaderInjection(baseURL, initialStatusCode, initialSize, resultsChan) })
	}
	if s.config.ModesToRun["useragent"] {
		testFuncs = append(testFuncs, func() { s.testUserAgents(baseURL, initialStatusCode, initialSize, resultsChan) })
	}
	if runAll || s.config.ModesToRun["hbh"] {
		testFuncs = append(testFuncs, func() { s.testHopByHop(baseURL, initialStatusCode, resultsChan) })
	}
	if runAll || s.config.ModesToRun["version"] {
		testFuncs = append(testFuncs, func() { s.testHTTPVersions(baseURL, initialStatusCode, initialSize, resultsChan) })
	}
	var wg sync.WaitGroup
	wg.Add(len(testFuncs))
	for _, testFunc := range testFuncs {
		go func(f func()) {
			defer wg.Done()
			f()
		}(testFunc)
	}
	wg.Wait()
}

func (s *Scanner) checkAndReport(technique, payload, method, url string, headers map[string]string, initialStatus int, initialSize int, resultsChan chan<- Result) {
	resp, req, err := s.sendRequest(method, url, headers)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	currentSize := len(body)
	if _, found := s.config.FilterSizes[currentSize]; found {
		return
	}
	statusChanged := resp.StatusCode != initialStatus
	sizeChanged := currentSize != initialSize
	shouldReport := (statusChanged || sizeChanged) && resp.StatusCode != 404 && resp.StatusCode != 400
	if technique == "Method Fuzzing" && resp.StatusCode == 405 {
		shouldReport = false
	}
	if method == "HEAD" && !statusChanged && currentSize == 0 {
		shouldReport = false
	}
	if (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 307 || resp.StatusCode == 308) {
		location, err := resp.Location()
		if err == nil && (location.String() == url+"/" || location.String() == url) {
			shouldReport = false
		}
	}
	if shouldReport {
		reason := fmt.Sprintf("Status (%d -> %d), Size (%d -> %d)", initialStatus, resp.StatusCode, initialSize, currentSize)
		resultsChan <- Result{URL: url, Technique: technique, Payload: payload, StatusCode: resp.StatusCode, Size: currentSize, Curl: generateCurlCommand(req, technique), Reason: reason}
	}
}

func generateCasePermutations(s string) []string {
	if s == "" {
		return nil
	}
	perms := []string{strings.ToUpper(s), strings.Title(strings.ToLower(s))}
	if len(s) > 1 {
		perms = append(perms, strings.ToLower(string(s[0]))+strings.ToUpper(s[1:]))
	}
	var alt1, alt2 strings.Builder
	for i, r := range s {
		if i%2 == 0 {
			alt1.WriteString(strings.ToUpper(string(r)))
			alt2.WriteString(strings.ToLower(string(r)))
		} else {
			alt1.WriteString(strings.ToLower(string(r)))
			alt2.WriteString(strings.ToUpper(string(r)))
		}
	}
	perms = append(perms, alt1.String(), alt2.String())
	uniquePerms := make(map[string]bool)
	var result []string
	for _, p := range perms {
		if !uniquePerms[p] {
			uniquePerms[p] = true
			result = append(result, p)
		}
	}
	return result
}

func (s *Scanner) testPathPermutations(baseURL string, initialStatus int, initialSize int, resultsChan chan<- Result) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return
	}
	path := strings.Trim(u.Path, "/")
	pathParts := strings.Split(path, "/")
	if len(pathParts) == 0 || (len(pathParts) == 1 && pathParts[0] == "") {
		return
	}
	runTest := func(technique, payload, url string) {
		s.checkAndReport(technique, payload, "GET", url, nil, initialStatus, initialSize, resultsChan)
	}
	affixPayloads := []string{
		"..;", "/..;", ".;", "/.;", ";", "/;", "~", ".json", "/.json", ".html", ".css", "%00", "%20", "%09", "%0a", "%0d",
		"%25", "%26", "%3f", "../", "./", "/*", "/%2f", "/%2e", "..%3B/", `..\;/`,
	}
	for i, originalPart := range pathParts {
		if originalPart == "" {
			continue
		}
		for _, payload := range affixPayloads {
			tempParts := make([]string, len(pathParts))
			copy(tempParts, pathParts)
			tempParts[i] = originalPart + payload
			runTest("Segment Suffix", payload, u.Scheme+"://"+u.Host+"/"+strings.Join(tempParts, "/"))
			copy(tempParts, pathParts)
			tempParts[i] = payload + originalPart
			runTest("Segment Prefix", payload, u.Scheme+"://"+u.Host+"/"+strings.Join(tempParts, "/"))
		}
		casePermutations := generateCasePermutations(originalPart)
		for _, permutedPart := range casePermutations {
			if permutedPart == originalPart {
				continue
			}
			tempParts := make([]string, len(pathParts))
			copy(tempParts, pathParts)
			tempParts[i] = permutedPart
			runTest("Per-Segment Case", permutedPart, u.Scheme+"://"+u.Host+"/"+strings.Join(tempParts, "/"))
		}
		if len(originalPart) > 1 {
			midPoint := len(originalPart) / 2
			newPart := originalPart[:midPoint] + "+" + originalPart[midPoint:]
			tempParts := make([]string, len(pathParts))
			copy(tempParts, pathParts)
			tempParts[i] = newPart
			runTest("Character Insertion", "+", u.Scheme+"://"+u.Host+"/"+strings.Join(tempParts, "/"))
		}
	}
	wrappers := map[string]string{"//": "//", "///": "///", "./": "./"}
	for pre, suf := range wrappers {
		runTest("Path Wrapper", pre+"..."+suf, u.Scheme+"://"+u.Host+"/"+pre+path+suf)
	}
	globalSuffixes := []string{"?", "??", "/?", "/??", "/.", "/..", "/*", "/%2f/", "/%20/", "/%09/", "/°/", "/&", "/-", `/\//`, ";%2f..%2f..%2f"}
	for _, suffix := range globalSuffixes {
		runTest("Global Suffix", suffix, u.Scheme+"://"+u.Host+"/"+path+suffix)
	}
	runTest("Query Parameter", "?id=1", u.Scheme+"://"+u.Host+"/"+path+"?id=1")
	for i, originalPart := range pathParts {
		if originalPart == "" {
			continue
		}
		for j, char := range originalPart {
			if unicode.IsLetter(char) || unicode.IsDigit(char) {
				singleEncoded := fmt.Sprintf("%%%x", char)
				tempParts := make([]string, len(pathParts))
				copy(tempParts, pathParts)
				tempParts[i] = originalPart[:j] + singleEncoded + originalPart[j+1:]
				runTest("Single Char Encode", singleEncoded, u.Scheme+"://"+u.Host+"/"+strings.Join(tempParts, "/"))
				doubleEncoded := strings.Replace(singleEncoded, "%", "%25", 1)
				copy(tempParts, pathParts)
				tempParts[i] = originalPart[:j] + doubleEncoded + originalPart[j+1:]
				runTest("Double Char Encode", doubleEncoded, u.Scheme+"://"+u.Host+"/"+strings.Join(tempParts, "/"))
			}
		}
	}
}

func (s *Scanner) testHTTPMethods(baseURL string, initialStatus int, initialSize int, resultsChan chan<- Result) {
	methods, err := readLines(s.config.HTTPMethodsFile)
	if err != nil {
		return
	}
	for _, method := range methods {
		if method == "GET" {
			continue
		}
		s.checkAndReport("Method Fuzzing", method, method, baseURL, nil, initialStatus, initialSize, resultsChan)
	}
}

func (s *Scanner) testHeaderInjection(baseURL string, initialStatus int, initialSize int, resultsChan chan<- Result) {
	s.checkAndReport("Remove Host Header", "Host: <empty>", "GET", baseURL, map[string]string{"Host": ""}, initialStatus, initialSize, resultsChan)
	headers, err := readLines(s.config.HTTPHeadersFile)
	if err != nil {
		return
	}
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headerMap := map[string]string{strings.TrimSpace(parts[0]): strings.TrimSpace(parts[1])}
			s.checkAndReport("Header Injection", h, "GET", baseURL, headerMap, initialStatus, initialSize, resultsChan)
		}
	}
}

func (s *Scanner) testUserAgents(baseURL string, initialStatus int, initialSize int, resultsChan chan<- Result) {
	userAgents, err := readLines(s.config.UserAgentsFile)
	if err != nil {
		return
	}
	for _, ua := range userAgents {
		headerMap := map[string]string{"User-Agent": ua}
		s.checkAndReport("User-Agent Fuzzing", ua, "GET", baseURL, headerMap, initialStatus, initialSize, resultsChan)
	}
}

func (s *Scanner) testHopByHop(baseURL string, initialStatus int, resultsChan chan<- Result) {
	baseResp, _, err := s.sendRequest("GET", baseURL, nil)
	if err != nil {
		return
	}
	defer baseResp.Body.Close()
	baseBody, err := io.ReadAll(baseResp.Body)
	if err != nil {
		return
	}
	baseContentLength := len(baseBody)
	hbhHeaders, err := readLines(s.config.HopByHopHeadersFile)
	if err != nil {
		return
	}
	for _, header := range hbhHeaders {
		poisonedHeaders := map[string]string{"Connection": "keep-alive, " + header, header: "127.0.0.1"}
		poisonedResp, poisonedReq, err := s.sendRequest("GET", baseURL, poisonedHeaders)
		if err != nil {
			continue
		}
		defer poisonedResp.Body.Close()
		poisonedBody, err := io.ReadAll(poisonedResp.Body)
		if err != nil {
			continue
		}
		poisonedContentLength := len(poisonedBody)
		statusChanged := baseResp.StatusCode != poisonedResp.StatusCode
		sizeChanged := baseContentLength != poisonedContentLength
		if (statusChanged || sizeChanged) && poisonedResp.StatusCode != 400 && poisonedResp.StatusCode != 404 {
			reason := fmt.Sprintf("Status (%d -> %d), Size (%d -> %d)", baseResp.StatusCode, poisonedResp.StatusCode, baseContentLength, poisonedContentLength)
			resultsChan <- Result{URL: baseURL, Technique: "Hop-by-Hop Header", Payload: header, StatusCode: poisonedResp.StatusCode, Size: poisonedContentLength, Curl: generateCurlCommand(poisonedReq, "Hop-by-Hop Header"), Reason: reason}
		}
	}
}

func (s *Scanner) testHTTPVersions(baseURL string, initialStatus int, initialSize int, resultsChan chan<- Result) {
	req_1_0, err := http.NewRequest("GET", baseURL, nil)
	if err == nil {
		req_1_0.Proto = "HTTP/1.0"
		req_1_0.ProtoMajor = 1
		req_1_0.ProtoMinor = 0
		s.checkAndReport("HTTP Version", "HTTP/1.0", "GET", baseURL, nil, initialStatus, initialSize, resultsChan)
	}
	if s.config.RunHTTP09 {
		u, err := url.Parse(baseURL)
		if err == nil {
			host := u.Hostname()
			port := u.Port()
			if port == "" {
				if u.Scheme == "https" {
					port = "443"
				} else {
					port = "80"
				}
			}
			if s.limiter != nil {
				s.limiter.Wait(context.Background())
			}
			if s.bar != nil {
				_ = s.bar.Add(1)
			}
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), s.config.Timeout)
			if err == nil {
				defer conn.Close()
				_, err := conn.Write([]byte(fmt.Sprintf("GET %s\r\n", u.Path)))
				if err == nil {
					buffer := make([]byte, 1024)
					conn.SetReadDeadline(time.Now().Add(s.config.Timeout))
					n, _ := conn.Read(buffer)
					if n > 0 {
						curlCmd := fmt.Sprintf("curl --http0.9 '%s'", baseURL)
						resultsChan <- Result{URL: baseURL, Technique: "HTTP Version", Payload: "HTTP/0.9", StatusCode: 0, Size: n, Curl: curlCmd, Reason: "Received data on raw socket"}
					}
				}
			}
		}
	}
}

func calculateTotalRequests(config Config, targets []string) int {
	count := 0
	runAll := config.ModesToRun["all"]
	var tests []string
	if runAll || config.ModesToRun["path"] {
		tests = append(tests, "path")
	}
	if runAll || config.ModesToRun["method"] {
		tests = append(tests, "method")
	}
	if runAll || config.ModesToRun["header"] {
		tests = append(tests, "header")
	}
	if config.ModesToRun["useragent"] {
		tests = append(tests, "useragent")
	}
	if runAll || config.ModesToRun["hbh"] {
		tests = append(tests, "hbh")
	}
	if runAll || config.ModesToRun["version"] {
		tests = append(tests, "version")
	}
	for _, mode := range tests {
		switch mode {
		case "path":
			affixPayloads := []string{"..;", "/..;", ".;", "/.;", ";", "/;", "~", ".json", "/.json", ".html", ".css", "%00", "%20", "%09", "%0a", "%0d", "%25", "%26", "%3f", "../", "./", "/*", "/%2f", "/%2e", "..%3B/", `..\;/`}
			wrappers := map[string]string{"//": "//", "///": "///", "./": "./"}
			globalSuffixes := []string{"?", "??", "/?", "/??", "/.", "/..", "/*", "/%2f/", "/%20/", "/%09/", "/°/", "/&", "/-", `/\//`, ";%2f..%2f..%2f"}
			const avgPathSegments = 3
			const avgSegmentLen = 6
			pathCount := (len(affixPayloads) * 2 * avgPathSegments) + (len(generateCasePermutations("admin")) * avgPathSegments) + avgPathSegments + len(wrappers) + len(globalSuffixes) + 1 + (avgPathSegments * avgSegmentLen * 2)
			count += pathCount
		case "method":
			methods, _ := readLines(config.HTTPMethodsFile)
			count += len(methods)
		case "header":
			headers, _ := readLines(config.HTTPHeadersFile)
			count += len(headers) + 1
		case "useragent":
			userAgents, _ := readLines(config.UserAgentsFile)
			count += len(userAgents)
		case "hbh":
			hbhHeaders, _ := readLines(config.HopByHopHeadersFile)
			count += len(hbhHeaders) + 1
		case "version":
			count += 1
			if config.RunHTTP09 {
				count += 1
			}
		}
	}
	return (count + 2) * len(targets)
}

func processFinalResults(results []Result, config Config) {
	if len(results) > 0 {
		fmt.Fprint(os.Stderr, "\n\n--- Scan Finished. Results ---\n\n")
	} else {
		fmt.Fprint(os.Stderr, "\n\n--- Scan Finished ---\n")
		printInfo("No anomalies or bypasses found.")
		return
	}
	signatures := make(map[string]int)
	for _, r := range results {
		signature := fmt.Sprintf("status:%d,size:%d", r.StatusCode, r.Size)
		signatures[signature]++
	}
	var finalOutput []Result
	seenSignatures := make(map[string]bool)
	for _, r := range results {
		if config.SuccessOnly && (r.StatusCode < 200 || r.StatusCode >= 300) {
			continue
		}
		signature := fmt.Sprintf("status:%d,size:%d", r.StatusCode, r.Size)
		totalOccurrences := signatures[signature]
		if config.FalsePositiveThreshold > 0 && totalOccurrences >= config.FalsePositiveThreshold {
			if seenSignatures[signature] {
				continue
			}
		}
		seenSignatures[signature] = true
		finalOutput = append(finalOutput, r)
	}
	for _, r := range finalOutput {
		printFinalResult(r, signatures, config)
	}
}

func printFinalResult(r Result, signatures map[string]int, config Config) {
	signature := fmt.Sprintf("status:%d,size:%d", r.StatusCode, r.Size)
	totalOccurrences := signatures[signature]
	var sb strings.Builder
	plainMsg := fmt.Sprintf("URL: %s\n  ├── Technique: %s\n  ├── Payload: '%s'\n  ├── New Status: %d\n  ├── Reason: %s\n  └── CURL: %s",
		r.URL, r.Technique, r.Payload, r.StatusCode, r.Reason, r.Curl)
	
	if config.OutputFile != "" {
		sb.WriteString("-------------------------------------------------\n")
		if r.StatusCode >= 200 && r.StatusCode < 300 {
			sb.WriteString(fmt.Sprintf("[SUCCESS] %s\n", plainMsg))
		} else {
			sb.WriteString(fmt.Sprintf("[ANOMALY] %s\n", plainMsg))
		}
		if config.FalsePositiveThreshold > 0 && totalOccurrences >= config.FalsePositiveThreshold {
			sb.WriteString(fmt.Sprintf("[INFO]   └── This response pattern (%s) appeared %d times in total. Only this first instance is shown.\n", signature, totalOccurrences))
		}
		sb.WriteString("-------------------------------------------------\n")
	} else {
		sb.WriteString("-------------------------------------------------\n")
		if r.StatusCode >= 200 && r.StatusCode < 300 {
			sb.WriteString(fmt.Sprintf("%s %s\n", successColor("[SUCCESS]"), plainMsg))
		} else {
			sb.WriteString(fmt.Sprintf("%s %s\n", warningColor("[ANOMALY]"), plainMsg))
		}
		if config.FalsePositiveThreshold > 0 && totalOccurrences >= config.FalsePositiveThreshold {
			sb.WriteString(fmt.Sprintf("%s   └── This response pattern (%s) appeared %d times in total. Only this first instance is shown.\n", infoColor("[INFO]"), signature, totalOccurrences))
		}
		sb.WriteString("-------------------------------------------------\n")
	}
	
	if config.OutputFile != "" {
		f, err := os.OpenFile(config.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			f.WriteString(sb.String() + "\n")
		}
	} else {
		fmt.Fprint(os.Stderr, sb.String())
	}
}

func main() {
	color.Output = os.Stderr
	config := Config{}
	var testMode, filterSizesStr, outputFile string
	var rps, fpThreshold int
	var runHTTP09, noBar, successOnly bool

	flag.StringVar(&config.URL, "u", "", "Single URL to target.")
	flag.StringVar(&config.URLList, "l", "", "File containing a list of URLs to target.")
	flag.IntVar(&config.Concurrency, "c", 10, "Number of concurrent workers.")
	flag.DurationVar(&config.Timeout, "t", 10*time.Second, "Request timeout duration.")
	flag.BoolVar(&config.Insecure, "k", false, "Skip SSL/TLS certificate verification.")
	flag.StringVar(&testMode, "mode", "all", "Tests to run (comma-separated: all, path, method, header, useragent, hbh, version).")
	flag.IntVar(&rps, "rps", 0, "Max requests per second (0 for no limit).")
	flag.StringVar(&filterSizesStr, "fs", "", "Filter out responses with these sizes (comma-separated).")
	flag.IntVar(&fpThreshold, "fp-threshold", 3, "False positive threshold. Suppress anomaly after N occurrences (0 to disable).")
	flag.BoolVar(&runHTTP09, "run-http09", false, "Run the noisy HTTP/0.9 test.")
	flag.BoolVar(&noBar, "no-bar", false, "Disable the progress bar.")
	flag.BoolVar(&successOnly, "so", false, "Only output/save success (2xx) findings.")
	flag.StringVar(&outputFile, "o", "", "Output file to save results to (e.g., results.txt).")
	flag.StringVar(&config.HTTPMethodsFile, "http-methods", "wordlists/httpmethods.txt", "File with HTTP methods for fuzzing.")
	flag.StringVar(&config.HTTPHeadersFile, "http-headers", "wordlists/httpheaders.txt", "File with HTTP headers for injection.")
	flag.StringVar(&config.UserAgentsFile, "user-agent", "wordlists/useragents.txt", "File with User-Agents for fuzzing.")
	flag.StringVar(&config.HopByHopHeadersFile, "hbh-headers", "wordlists/hbh-headers.txt", "File with headers for Hop-by-Hop tests.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "403 Bypasser - A tool to test for 403 Forbidden bypass techniques.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if config.URL == "" && config.URLList == "" {
		flag.Usage()
		os.Exit(1)
	}

	var targets []string
	if config.URL != "" {
		targets = append(targets, config.URL)
	}
	if config.URLList != "" {
		file, err := os.Open(config.URLList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to open URL list file '%s': %v\n", config.URLList, err)
			os.Exit(1)
		}
		defer file.Close()
		fileScanner := bufio.NewScanner(file)
		for fileScanner.Scan() {
			targets = append(targets, fileScanner.Text())
		}
	}

	config.ModesToRun = make(map[string]bool)
	modes := strings.Split(strings.ToLower(testMode), ",")
	for _, m := range modes {
		config.ModesToRun[strings.TrimSpace(m)] = true
	}

	config.FalsePositiveThreshold = fpThreshold
	config.RunHTTP09 = runHTTP09
	config.SuccessOnly = successOnly
	config.OutputFile = outputFile

	config.FilterSizes = make(map[int]bool)
	if filterSizesStr != "" {
		sizes := strings.Split(filterSizesStr, ",")
		for _, s := range sizes {
			sizeInt, err := strconv.Atoi(strings.TrimSpace(s))
			if err == nil {
				config.FilterSizes[sizeInt] = true
			}
		}
	}

	totalRequests := calculateTotalRequests(config, targets)
	var bar *progressbar.ProgressBar
	if !noBar && totalRequests > 0 {
		bar = progressbar.NewOptions(totalRequests,
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionSetDescription("[cyan]Fuzzing...[reset]"),
			progressbar.OptionShowCount(),
			progressbar.OptionShowElapsedTimeOnFinish(),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "[green]=[reset]",
				SaucerHead:    "[green]>[reset]",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}))
	}

	var limiter *rate.Limiter
	if rps > 0 {
		limiter = rate.NewLimiter(rate.Limit(rps), 1)
	}

	resultsChan := make(chan Result, totalRequests)
	urlsChan := make(chan string, len(targets))

	for _, t := range targets {
		urlsChan <- t
	}
	close(urlsChan)

	sharedSignatures := &SharedSignatureMap{
		Signatures: make(map[string]int),
		Mutex:      &sync.Mutex{},
	}

	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urlsChan {
				s := newScanner(config, limiter, sharedSignatures, bar)
				s.scan(url, resultsChan)
			}
		}()
	}

	wg.Wait()
	close(resultsChan)

	if bar != nil {
		_ = bar.Finish()
	}

	var finalResults []Result
	for result := range resultsChan {
		finalResults = append(finalResults, result)
	}

	processFinalResults(finalResults, config)
}
