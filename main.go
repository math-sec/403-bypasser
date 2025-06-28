package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"403-bypasser/internal/scanner"
	"403-bypasser/internal/utils"
)

func main() {
	config := scanner.Config{}
	var testMode string

	flag.StringVar(&config.URL, "u", "", "Single URL to target.")
	flag.StringVar(&config.URLList, "l", "", "File containing a list of URLs to target.")
	flag.IntVar(&config.Concurrency, "c", 10, "Number of concurrent workers.")
	flag.DurationVar(&config.Timeout, "t", 10*time.Second, "Request timeout duration.")
	flag.BoolVar(&config.Insecure, "k", false, "Skip SSL/TLS certificate verification.")
	flag.IntVar(&config.Verbosity, "v", 0, "Verbosity level (1, 2, or 3).")
	flag.StringVar(&testMode, "mode", "all", "Test mode to run. Options: all, path, method, header, useragent, hbh, version.")
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

	config.TestMode = strings.ToLower(testMode)

	urls := make(chan string, config.Concurrency)
	var wg sync.WaitGroup

	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urls {
				s := scanner.NewScanner(config)
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
