package utils

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
)

var (
	SuccessColor = color.New(color.FgGreen).SprintFunc()
	WarningColor = color.New(color.FgYellow).SprintFunc()
	ErrorColor   = color.New(color.FgRed).SprintFunc()
	InfoColor    = color.New(color.FgCyan).SprintFunc()
)

func PrintSuccess(msg string) {
	fmt.Printf("[%s] %s\n", SuccessColor("SUCCESS"), msg)
}

func PrintWarning(msg string) {
	fmt.Printf("[%s] %s\n", WarningColor("ANOMALY"), msg)
}

func PrintError(msg string) {
	fmt.Printf("[%s] %s\n", ErrorColor("ERROR"), msg)
}

func PrintInfo(msg string) {
	fmt.Printf("[%s] %s\n", InfoColor("INFO"), msg)
}

func ReadLines(path string) ([]string, error) {
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

func GenerateCurlCommand(req *http.Request) string {
	var command strings.Builder
	command.WriteString("curl -X ")
	command.WriteString(req.Method)
	command.WriteString(fmt.Sprintf(" '%s'", req.URL.String()))

	for key, values := range req.Header {
		if key == "Host" && len(values) > 0 {
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
