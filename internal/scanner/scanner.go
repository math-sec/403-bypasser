package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"403-bypasser/internal/utils"
	"github.com/fatih/color"
	"golang.org/x/time/rate"
	// "github.com/quic-go/quic-go/http3"
)

type Config struct {
	URL                 string
	URLList             string
	HTTPMethodsFile     string
	HTTPHeadersFile     string
	UserAgentsFile      string
	HopByHopHeadersFile string
	Concurrency         int
	Timeout             time.Duration
	Insecure            bool
	Verbosity           int
	TestMode            string
	FilterSizes         map[int]bool
}

type Scanner struct {
	config  Config
	client  *http.Client
	limiter *rate.Limiter
}

type Result struct {
	URL        string
	Technique  string
	Payload    string
	StatusCode int
	Curl       string
	Reason     string
}

var printMutex sync.Mutex

func (s *Scanner) log(level int, format string, args ...interface{}) {
	if s.config.Verbosity >= level {
		printMutex.Lock()
		defer printMutex.Unlock()
		msg := fmt.Sprintf(format, args...)
		fmt.Printf("[%s] %s\n", color.New(color.FgBlue).SprintFunc()("VERBOSE"), msg)
	}
}

func NewScanner(config Config, limiter *rate.Limiter) *Scanner {
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
	return &Scanner{config: config, client: client, limiter: limiter}
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
	resp, err := s.client.Do(req)
	return resp, req, err
}

func (s *Scanner) Scan(baseURL string) {
	fmt.Println()
	utils.PrintInfo(fmt.Sprintf("Starting scan for: %s", baseURL))
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
		s.runAllTests(targetURL)
	}
}

func (s *Scanner) runAllTests(targetURL string) {
	resp, _, err := s.sendRequest("GET", targetURL, nil)
	if err != nil {
		utils.PrintError(fmt.Sprintf("Initial request to %s failed: %v", targetURL, err))
		return
	}
	defer resp.Body.Close()
	initialStatusCode := resp.StatusCode
	initialBody, err := io.ReadAll(resp.Body)
	if err != nil {
		utils.PrintError(fmt.Sprintf("Failed to read initial response body: %v", err))
		return
	}
	initialSize := len(initialBody)
	utils.PrintInfo(fmt.Sprintf("Testing against %s (Initial Status: %d, Initial Size: %d bytes)", targetURL, initialStatusCode, initialSize))
	if initialStatusCode != 403 {
		utils.PrintWarning(fmt.Sprintf("Initial status code is %d, not 403. Results may vary.", initialStatusCode))
	}
	testsToRun := make(map[string]func())
	if s.config.TestMode == "all" || s.config.TestMode == "path" {
		testsToRun["path"] = func() { s.testPathPermutations(targetURL, initialStatusCode, initialSize) }
	}
	if s.config.TestMode == "all" || s.config.TestMode == "method" {
		testsToRun["method"] = func() { s.testHTTPMethods(targetURL, initialStatusCode, initialSize) }
	}
	if s.config.TestMode == "all" || s.config.TestMode == "header" {
		testsToRun["header"] = func() { s.testHeaderInjection(targetURL, initialStatusCode, initialSize) }
	}
	if s.config.TestMode == "all" || s.config.TestMode == "useragent" {
		testsToRun["useragent"] = func() { s.testUserAgents(targetURL, initialStatusCode, initialSize) }
	}
	if s.config.TestMode == "all" || s.config.TestMode == "hbh" {
		testsToRun["hbh"] = func() { s.testHopByHop(targetURL, initialStatusCode) }
	}
	if s.config.TestMode == "all" || s.config.TestMode == "version" {
		testsToRun["version"] = func() { s.testHTTPVersions(targetURL, initialStatusCode, initialSize) }
	}
	if len(testsToRun) == 0 {
		utils.PrintError(fmt.Sprintf("Invalid test mode specified: %s", s.config.TestMode))
		return
	}
	var wg sync.WaitGroup
	wg.Add(len(testsToRun))
	for _, testFunc := range testsToRun {
		go func(f func()) {
			defer wg.Done()
			f()
		}(testFunc)
	}
	wg.Wait()
}

func (s *Scanner) checkAndReport(technique, payload, method, url string, headers map[string]string, initialStatus int, initialSize int) {
	s.log(2, "Attempting Technique: %s, Payload: '%s', URL: %s", technique, payload, url)
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
	shouldReport := (statusChanged || sizeChanged) && resp.StatusCode != 404
	if technique == "Method Fuzzing" && resp.StatusCode == 405 {
		shouldReport = false
	}
	if shouldReport {
		var reason string
		if statusChanged && sizeChanged {
			reason = fmt.Sprintf("Status (%d -> %d) AND Size (%d -> %d) changed", initialStatus, resp.StatusCode, initialSize, currentSize)
		} else if statusChanged {
			reason = fmt.Sprintf("Status changed (%d -> %d)", initialStatus, resp.StatusCode)
		} else {
			reason = fmt.Sprintf("Size changed (%d -> %d)", initialSize, currentSize)
		}
		result := Result{URL: url, Technique: technique, Payload: payload, StatusCode: resp.StatusCode, Curl: utils.GenerateCurlCommand(req), Reason: reason}
		s.printResult(result)
	} else {
		s.log(3, "No change for '%s' (Status: %d, Size: %d)", payload, resp.StatusCode, currentSize)
	}
}

func (s *Scanner) printResult(r Result) {
	printMutex.Lock()
	defer printMutex.Unlock()
	msg := fmt.Sprintf("URL: %s | Technique: %s | Payload: '%s' | New Status: %d", r.URL, r.Technique, r.Payload, r.StatusCode)
	if r.StatusCode >= 200 && r.StatusCode < 300 {
		utils.PrintSuccess("Endpoint possibly bypassed successfully!")
		utils.PrintSuccess(msg)
	} else {
		utils.PrintWarning("Anomalous behavior detected!")
		utils.PrintWarning(msg)
	}
	utils.PrintInfo(fmt.Sprintf("  └── Reason: %s", r.Reason))
	fmt.Printf("   └── CURL: %s\n", r.Curl)
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

func (s *Scanner) testPathPermutations(baseURL string, initialStatus int, initialSize int) {
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
			s.checkAndReport(technique, payload, "GET", url, nil, initialStatus, initialSize)
			generatedTests[url] = true
		}
	}
	affixPayloads := []string{
		"..;", "/..;", ".;", "/.;", ";", "/;", "~", ".json", "/.json", ".html", ".css", "%00", "%20", "%09", "%0a", "%0d",
		"%25", "%23", "%26", "%3f", "#", "../", "./", "/*", "/%2f", "/%2e", "..%3B/", `..\;/`,
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
		"?", "??", "/?", "/??", "/.", "/..", "/*", "/%2f/", "/%20/", "/%09/", "/#", "/#/", "/#/./", "/°/", "/&", "/-", `/\//`, ";%2f..%2f..%2f",
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

func (s *Scanner) testHTTPMethods(baseURL string, initialStatus int, initialSize int) {
	s.log(1, "Starting HTTP Method Fuzzing tests...")
	methods, err := utils.ReadLines(s.config.HTTPMethodsFile)
	if err != nil {
		utils.PrintError(fmt.Sprintf("Could not read HTTP methods file: %v", err))
		return
	}
	for _, method := range methods {
		if method == "GET" {
			continue
		}
		s.checkAndReport("Method Fuzzing", method, method, baseURL, nil, initialStatus, initialSize)
	}
}

func (s *Scanner) testHeaderInjection(baseURL string, initialStatus int, initialSize int) {
	s.log(1, "Starting Header Injection tests...")
	headers, err := utils.ReadLines(s.config.HTTPHeadersFile)
	if err != nil {
		utils.PrintError(fmt.Sprintf("Could not read HTTP headers file: %v", err))
		return
	}
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headerMap := map[string]string{strings.TrimSpace(parts[0]): strings.TrimSpace(parts[1])}
			s.checkAndReport("Header Injection", h, "GET", baseURL, headerMap, initialStatus, initialSize)
		}
	}
}

func (s *Scanner) testUserAgents(baseURL string, initialStatus int, initialSize int) {
	s.log(1, "Starting User-Agent Fuzzing tests...")
	userAgents, err := utils.ReadLines(s.config.UserAgentsFile)
	if err != nil {
		utils.PrintError(fmt.Sprintf("Could not read User-Agents file: %v", err))
		return
	}
	for _, ua := range userAgents {
		headerMap := map[string]string{"User-Agent": ua}
		s.checkAndReport("User-Agent Fuzzing", ua, "GET", baseURL, headerMap, initialStatus, initialSize)
	}
}

func (s *Scanner) testHopByHop(baseURL string, initialStatus int) {
	s.log(1, "Starting Hop-by-Hop Header tests...")
	baseResp, _, err := s.sendRequest("GET", baseURL, nil)
	if err != nil {
		s.log(2, "Could not make base request for Hop-by-Hop test: %v", err)
		return
	}
	defer baseResp.Body.Close()
	baseBody, err := io.ReadAll(baseResp.Body)
	if err != nil {
		s.log(2, "Could not read base response body for Hop-by-Hop test: %v", err)
		return
	}
	baseContentLength := len(baseBody)
	hbhHeaders, err := utils.ReadLines(s.config.HopByHopHeadersFile)
	if err != nil {
		utils.PrintError(fmt.Sprintf("Could not read Hop-by-Hop headers file: %v", err))
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
		if statusChanged || sizeChanged {
			var reason string
			if statusChanged && sizeChanged {
				reason = fmt.Sprintf("Status changed (%d -> %d) AND Size changed (%d -> %d)", baseResp.StatusCode, poisonedResp.StatusCode, baseContentLength, poisonedContentLength)
			} else if statusChanged {
				reason = fmt.Sprintf("Status changed (%d -> %d)", baseResp.StatusCode, poisonedResp.StatusCode)
			} else {
				reason = fmt.Sprintf("Size changed (%d -> %d)", baseContentLength, poisonedContentLength)
			}
			s.printResult(Result{URL: baseURL, Technique: "Hop-by-Hop Header", Payload: header, StatusCode: poisonedResp.StatusCode, Curl: utils.GenerateCurlCommand(poisonedReq), Reason: reason})
		} else {
			s.log(3, "No change for Hop-by-Hop header: %s", header)
		}
	}
}

func (s *Scanner) testHTTPVersions(baseURL string, initialStatus int, initialSize int) {
	s.log(1, "Starting HTTP Version tests...")
	req_1_0, err := http.NewRequest("GET", baseURL, nil)
	if err == nil {
		req_1_0.Proto = "HTTP/1.0"
		req_1_0.ProtoMajor = 1
		req_1_0.ProtoMinor = 0
		s.log(2, "Attempting Technique: HTTP Version, Payload: 'HTTP/1.0'")
		resp_1_0, err_1_0 := s.client.Do(req_1_0)
		if err_1_0 == nil {
			body_1_0, _ := io.ReadAll(resp_1_0.Body)
			if (resp_1_0.StatusCode != initialStatus || len(body_1_0) != initialSize) && resp_1_0.StatusCode != 404 {
				s.printResult(Result{URL: baseURL, Technique: "HTTP Version", Payload: "HTTP/1.0", StatusCode: resp_1_0.StatusCode, Curl: utils.GenerateCurlCommand(req_1_0) + " --http1.0", Reason: "Status/Size changed"})
			} else {
				s.log(3, "No change for 'HTTP/1.0' (Status: %d)", resp_1_0.StatusCode)
			}
			resp_1_0.Body.Close()
		}
	}

	/*
	s.log(2, "Attempting Technique: HTTP Version, Payload: 'HTTP/3'")
	h3Client := http.Client{Transport: &http3.RoundTripper{TLSClientConfig: &tls.Config{InsecureSkipVerify: s.config.Insecure}}, Timeout: s.config.Timeout}
	resp_3, err_3 := h3Client.Get(baseURL)
	if err_3 == nil {
		body_3, _ := io.ReadAll(resp_3.Body)
		if (resp_3.StatusCode != initialStatus || len(body_3) != initialSize) && resp_3.StatusCode != 404 {
			s.printResult(Result{URL: baseURL, Technique: "HTTP Version", Payload: "HTTP/3", StatusCode: resp_3.StatusCode, Curl: fmt.Sprintf("curl --http3 '%s'", baseURL), Reason: "Status/Size changed"})
		} else {
			s.log(3, "No change for 'HTTP/3' (Status: %d)", resp_3.StatusCode)
		}
		resp_3.Body.Close()
	} else {
		s.log(3, "HTTP/3 test failed to connect (likely not supported by target): %v", err_3)
	}
	*/

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
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), s.config.Timeout)
		if err == nil {
			defer conn.Close()
			_, err := conn.Write([]byte(fmt.Sprintf("GET %s\r\n", u.Path)))
			if err == nil {
				buffer := make([]byte, 1024)
				conn.SetReadDeadline(time.Now().Add(s.config.Timeout))
				n, _ := conn.Read(buffer)
				if n > 0 {
					s.printResult(Result{URL: baseURL, Technique: "HTTP Version", Payload: "HTTP/0.9", StatusCode: 0, Curl: fmt.Sprintf("echo -ne 'GET %s\\r\\n' | nc %s %s", u.Path, host, port), Reason: "Received data on raw socket"})
				} else {
					s.log(3, "No change for 'HTTP/0.9' (no data received)")
				}
			}
		}
	}
}
