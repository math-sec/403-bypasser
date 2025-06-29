package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"403-bypasser/internal/scanner"
	"403-bypasser/internal/utils"
	"golang.org/x/time/rate"
)

func main() {
	config := scanner.Config{}
	var testMode, filterSizesStr string
	var rps int

	flag.StringVar(&config.URL, "u", "", "Single URL to target.")
	flag.StringVar(&config.URLList, "l", "", "File containing a list of URLs to target.")
	flag.IntVar(&config.Concurrency, "c", 10, "Number of concurrent workers.")
	flag.DurationVar(&config.Timeout, "t", 10*time.Second, "Request timeout duration.")
	flag.BoolVar(&config.Insecure, "k", false, "Skip SSL/TLS certificate verification.")
	flag.IntVar(&config.Verbosity, "v", 0, "Verbosity level (1, 2, or 3).")
	flag.StringVar(&testMode, "mode", "all", "Tests to run (comma-separated: all, path, method, header, useragent, hbh, version).")
	flag.IntVar(&rps, "rps", 0, "Max requests per second (0 for no limit).")
	flag.StringVar(&filterSizesStr, "fs", "", "Filter out responses with these sizes (comma-separated, e.g., 118,0,345).")
	flag.StringVar(&config.HTTPMethodsFile, "http-methods", "wordlists/httpmethods.txt", "File with HTTP methods for fuzzing.")
	flag.StringVar(&config.HTTPHeadersFile, "http-headers", "wordlists/httpheaders.txt", "File with HTTP headers for injection.")
	flag.StringVar(&config.UserAgentsFile, "user-agent", "wordlists/useragents.txt", "File with User-Agents for fuzzing.")
	flag.StringVar(&config.HopByHopHeadersFile, "hbh-headers", "wordlists/hbh-headers.txt", "File with headers for Hop-by-Hop tests.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "403 Bypasser - A tool to test for 403 Forbidden bypass techniques.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if config.URL == "" && config.URLList == "" {
		flag.Usage()
		os.Exit(1)
	}

	config.ModesToRun = make(map[string]bool)
	modes := strings.Split(strings.ToLower(testMode), ",")
	for _, m := range modes {
		config.ModesToRun[strings.TrimSpace(m)] = true
	}

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

	var limiter *rate.Limiter
	if rps > 0 {
		limiter = rate.NewLimiter(rate.Limit(rps), 1)
	}

	urls := make(chan string, config.Concurrency)
	var wg sync.WaitGroup

	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urls {
				s := scanner.NewScanner(config, limiter)
				s.Scan(url)
			}
		}()
	}

	if config.URL != "" {
		urls <- config.URL
	}

	if config.URLList != "" {
		file, err := os.Open(config.URLList)
		if err != nil {
			utils.PrintError(fmt.Sprintf("Failed to open URL list file '%s': %v", config.URLList, err))
			os.Exit(1)
		}
		defer file.Close()
		fileScanner := bufio.NewScanner(file)
		for fileScanner.Scan() {
			urls <- fileScanner.Text()
		}
	}

	close(urls)
	wg.Wait()
	fmt.Println()
	utils.PrintInfo("All tests completed.")
}
