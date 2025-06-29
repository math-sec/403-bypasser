package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"403-bypasser/internal/utils"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/time/rate"
	// "github.com/quic-go/quic-go/http3"
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
	Verbosity              int
	ModesToRun             map[string]bool
	FilterSizes            map[int]bool
	FalsePositiveThreshold int
	RunHTTP09              bool
}

type SharedSignatureMap struct {
	Signatures map[string]int
	Mutex      *sync.Mutex
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

func (s *Scanner) log(level int, format string, args ...interface{}) {
	if s.config.Verbosity >= level {
		if s.bar != nil {
			s.bar.Describe(fmt.Sprintf(format, args...))
		} else {
			fmt.Fprintf(os.Stderr, "[VERBOSE] "+format+"\n", args...)
		}
	}
}

func NewScanner(config Config, limiter *rate.Limiter, sharedSigs *SharedSignatureMap, bar *progressbar.ProgressBar) *Scanner {
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

func (s *Scanner) Scan(baseURL string, resultsChan chan<- Result) {
	s.log(1, "Scanning: %s", baseURL)
	schemes := []string{"https"}
	httpURL := strings.Replace(baseURL, "https://", "http://", 1)
	if !strings.HasPrefix(httpURL, "http://") {
		httpURL = "http://" + baseURL
	}
	resp, _, err := s.sendRequest("GET", httpURL, nil)
	if err == nil && resp.StatusCode > 0 {
		schemes = append(schemes, "http")
		resp.Body.Close()
	}
	for _, scheme := range schemes {
		targetURL := strings.Replace(baseURL, "https://", scheme+"://", 1)
		targetURL = strings.Replace(targetURL, "http://", scheme+"://", 1)
		if !strings.Contains(targetURL, "://") {
			targetURL = scheme + "://" + targetURL
		}
		s.runAllTests(targetURL, resultsChan)
	}
}

func (s *Scanner) runAllTests(targetURL string, resultsChan chan<- Result) {
	resp, _, err := s.sendRequest("GET", targetURL, nil)
	if err != nil {
		s.log(1, "[ERROR] Initial request to %s failed: %v", targetURL, err)
		return
	}
	defer resp.Body.Close()
	initialStatusCode := resp.StatusCode
	initialBody, err := io.ReadAll(resp.Body)
	if err != nil {
		s.log(1, "[ERROR] Failed to read initial response body for %s: %v", targetURL, err)
		return
	}
	initialSize := len(initialBody)
	s.log(1, "Testing against %s (Initial Status: %d, Initial Size: %d bytes)", targetURL, initialStatusCode, initialSize)
	if initialStatusCode != 403 {
		s.log(1, "[WARNING] Initial status for %s is %d, not 403. Results may vary.", targetURL, initialStatusCode)
	}
	runAll := s.config.ModesToRun["all"]
	var testFuncs []func()
	if runAll || s.config.ModesToRun["path"] {
		testFuncs = append(testFuncs, func() { s.testPathPermutations(targetURL, initialStatusCode, initialSize, resultsChan) })
	}
	if runAll || s.config.ModesToRun["method"] {
		testFuncs = append(testFuncs, func() { s.testHTTPMethods(targetURL, initialStatusCode, initialSize, resultsChan) })
	}
	if runAll || s.config.ModesToRun["header"] {
		testFuncs = append(testFuncs, func() { s.testHeaderInjection(targetURL, initialStatusCode, initialSize, resultsChan) })
	}
	if s.config.ModesToRun["useragent"] {
		testFuncs = append(testFuncs, func() { s.testUserAgents(targetURL, initialStatusCode, initialSize, resultsChan) })
	}
	if runAll || s.config.ModesToRun["hbh"] {
		testFuncs = append(testFuncs, func() { s.testHopByHop(targetURL, initialStatusCode, resultsChan) })
	}
	if runAll || s.config.ModesToRun["version"] {
		testFuncs = append(testFuncs, func() { s.testHTTPVersions(targetURL, initialStatusCode, initialSize, resultsChan) })
	}
	if len(testFuncs) == 0 && !s.config.ModesToRun["all"] {
		s.log(1, "[ERROR] Invalid test mode specified.")
		return
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
	s.log(2, "Attempting: %s, Payload: '%s'", technique, payload)
	resp, req, err := s.sendRequest(method, url, headers)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.log(3, "Failed to read response body for '%s'", url)
		return
	}
	currentSize := len(body)
	if _, found := s.config.FilterSizes[currentSize]; found {
		s.log(3, "Response size %d matches filter, ignoring.", currentSize)
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
		resultsChan <- Result{URL: url, Technique: technique, Payload: payload, StatusCode: resp.StatusCode, Size: currentSize, Curl: utils.GenerateCurlCommand(req, technique), Reason: reason}
	} else {
		s.log(3, "No change for '%s' (Status: %d, Size: %d)", payload, resp.StatusCode, currentSize)
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
	s.log(1, "Starting Path Permutation tests...")
	u, err := url.Parse(baseURL)
	if err != nil {
		return
	}
	path := strings.Trim(u.Path, "/")
	pathParts := strings.Split(path, "/")
	if len(pathParts) == 0 || (len(pathParts) == 1 && pathParts[0] == "") {
		return
	}
	generatedTests := make(map[string]bool)
	runTest := func(technique, payload, url string) {
		if !generatedTests[url] {
			s.checkAndReport(technique, payload, "GET", url, nil, initialStatus, initialSize, resultsChan)
			generatedTests[url] = true
		}
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
	globalSuffixes := []string{
		"?", "??", "/?", "/??", "/.", "/..", "/*", "/%2f/", "/%20/", "/%09/", "/°/", "/&", "/-", `/\//`, ";%2f..%2f..%2f",
	}
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
	s.log(1, "Starting HTTP Method Fuzzing tests...")
	methods, err := utils.ReadLines(s.config.HTTPMethodsFile)
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
	s.log(1, "Starting Header Injection tests...")
	s.checkAndReport("Remove Host Header", "Host: <empty>", "GET", baseURL, map[string]string{"Host": ""}, initialStatus, initialSize, resultsChan)
	headers, err := utils.ReadLines(s.config.HTTPHeadersFile)
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
	s.log(1, "Starting User-Agent Fuzzing tests...")
	userAgents, err := utils.ReadLines(s.config.UserAgentsFile)
	if err != nil {
		return
	}
	for _, ua := range userAgents {
		headerMap := map[string]string{"User-Agent": ua}
		s.checkAndReport("User-Agent Fuzzing", ua, "GET", baseURL, headerMap, initialStatus, initialSize, resultsChan)
	}
}

func (s *Scanner) testHopByHop(baseURL string, initialStatus int, resultsChan chan<- Result) {
	s.log(1, "Starting Hop-by-Hop Header tests...")
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
	hbhHeaders, err := utils.ReadLines(s.config.HopByHopHeadersFile)
	if err != nil {
		return
	}
	for _, header := range hbhHeaders {
		poisonedHeaders := map[string]string{"Connection": "keep-alive, " + header, header: "127.0.0.1"}
		s.log(2, "Attempting Hop-by-Hop with header: %s", header)
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
			resultsChan <- Result{URL: baseURL, Technique: "Hop-by-Hop Header", Payload: header, StatusCode: poisonedResp.StatusCode, Size: poisonedContentLength, Curl: utils.GenerateCurlCommand(poisonedReq, "Hop-by-Hop Header"), Reason: reason}
		} else {
			s.log(3, "No change for Hop-by-Hop header: %s", header)
		}
	}
}

func (s *Scanner) testHTTPVersions(baseURL string, initialStatus int, initialSize int, resultsChan chan<- Result) {
	s.log(1, "Starting HTTP Version tests...")
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
			s.log(2, "Attempting Technique: HTTP Version, Payload: 'HTTP/0.9'")
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
					} else {
						s.log(3, "No change for 'HTTP/0.9' (no data received)")
					}
				}
			}
		}
	}
}

func CalculateTotalRequests(config Config) int {
	count := 2
	const avgPathSegments = 3
	const avgSegmentLen = 6
	runAll := config.ModesToRun["all"]
	pathCount := 0
	if runAll || config.ModesToRun["path"] {
		affixPayloads := []string{"..;", "/..;", ".;", "/.;", ";", "/;", "~", ".json", "/.json", ".html", ".css", "%00", "%20", "%09", "%0a", "%0d", "%25", "%26", "%3f", "../", "./", "/*", "/%2f", "/%2e", "..%3B/", `..\;/`}
		wrappers := map[string]string{"//": "//", "///": "///", "./": "./"}
		globalSuffixes := []string{"?", "??", "/?", "/??", "/.", "/..", "/*", "/%2f/", "/%20/", "/%09/", "/°/", "/&", "/-", `/\//`, ";%2f..%2f..%2f"}
		pathCount += (len(affixPayloads) * 2 * avgPathSegments)
		pathCount += (len(generateCasePermutations("admin")) * avgPathSegments)
		pathCount += avgPathSegments
		pathCount += len(wrappers)
		pathCount += len(globalSuffixes) + 1
		pathCount += (avgPathSegments * avgSegmentLen * 2)
	}
	if runAll || config.ModesToRun["method"] {
		methods, _ := utils.ReadLines(config.HTTPMethodsFile)
		count += len(methods)
	}
	if runAll || config.ModesToRun["header"] {
		headers, _ := utils.ReadLines(config.HTTPHeadersFile)
		count += len(headers) + 1
	}
	if config.ModesToRun["useragent"] {
		userAgents, _ := utils.ReadLines(config.UserAgentsFile)
		count += len(userAgents)
	}
	if runAll || config.ModesToRun["hbh"] {
		hbhHeaders, _ := utils.ReadLines(config.HopByHopHeadersFile)
		count += len(hbhHeaders) + 1
	}
	if runAll || config.ModesToRun["version"] {
		count += 1
		if config.RunHTTP09 {
			count += 1
		}
	}
	return count + pathCount
}

func ProcessFinalResults(results []Result, config Config) {
	if len(results) > 0 {
		fmt.Fprint(os.Stderr, "\n\n--- Scan Finished. Results ---\n\n")
	} else {
		fmt.Fprint(os.Stderr, "\n--- Scan Finished ---\n")
		utils.PrintInfo("No anomalies or bypasses found.")
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
		printFinalResult(r, signatures)
		signature := fmt.Sprintf("status:%d,size:%d", r.StatusCode, r.Size)
		if config.FalsePositiveThreshold > 0 && signatures[signature] >= config.FalsePositiveThreshold {
			utils.PrintInfo(fmt.Sprintf("  └── This response pattern (%s) appeared %d times. Only the first instance is shown.", signature, signatures[signature]))
		}
	}
}

func printFinalResult(r Result, signatures map[string]int) {
	msg := fmt.Sprintf("URL: %s\n  ├── Technique: %s\n  ├── Payload: '%s'\n  ├── New Status: %d\n  ├── Reason: %s\n  └── CURL: %s",
		r.URL, r.Technique, r.Payload, r.StatusCode, r.Reason, r.Curl)
	fmt.Fprintln(os.Stderr, "-------------------------------------------------")
	if r.StatusCode >= 200 && r.StatusCode < 300 {
		utils.PrintSuccess(msg)
	} else {
		utils.PrintWarning(msg)
	}
	fmt.Fprintln(os.Stderr, "-------------------------------------------------")
}
