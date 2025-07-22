package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type Rule struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Pattern     string   `json:"pattern"`
	TargetFile  string   `json:"target_file"`
	Severity    string   `json:"severity"`
	Enabled     bool     `json:"enabled"`
	References  []string `json:"references"`
}

type Match struct {
	RuleName    string
	FilePath    string
	LineNumber  int
	LineContent string
	Severity    string
	References  []string
}

// CLI output coloring
func red(s string) string    { return "\033[31m" + s + "\033[0m" }
func green(s string) string  { return "\033[32m" + s + "\033[0m" }
func yellow(s string) string { return "\033[33m" + s + "\033[0m" }
func bold(s string) string   { return "\033[1m" + s + "\033[0m" }

func checkDependencies(tools []string) []string {
	var missing []string
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	return missing
}

func loadRules(ruleFile string) ([]Rule, error) {
	data, err := ioutil.ReadFile(ruleFile)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func applyRules(rules []Rule, targetDir string) ([]Match, error) {
	var matches []Match

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		fullTargetPath := filepath.Join(targetDir, rule.TargetFile)

		file, err := os.Open(fullTargetPath)
		if err != nil {
			fmt.Printf("⚠️ Could not open file: %s (Rule: %s)\n", fullTargetPath, rule.Name)
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNumber := 0
		re := regexp.MustCompile(rule.Pattern)

		for scanner.Scan() {
			lineNumber++
			line := scanner.Text()

			// Special logic for known patterns
			if rule.Name == "Exported Activity Without Permission" {
				if strings.Contains(line, "<activity") &&
					strings.Contains(line, `android:exported="true"`) &&
					!strings.Contains(line, "android:permission") {

					matches = append(matches, Match{
						RuleName:    rule.Name,
						FilePath:    fullTargetPath,
						LineNumber:  lineNumber,
						LineContent: strings.TrimSpace(line),
						Severity:    rule.Severity,
						References:  rule.References,
					})
				}
				continue
			}

			// General regex match
			if re.MatchString(line) {
				matches = append(matches, Match{
					RuleName:    rule.Name,
					FilePath:    fullTargetPath,
					LineNumber:  lineNumber,
					LineContent: strings.TrimSpace(line),
					Severity:    rule.Severity,
					References:  rule.References,
				})
			}
		}
	}

	return matches, nil
}

func writeReport(matches []Match, reportPath string) error {
	f, err := os.Create(reportPath)
	if err != nil {
		return err
	}
	defer f.Close()
	writer := bufio.NewWriter(f)

	for _, match := range matches {
		fmt.Printf("%s [%s] %s:%d\n", bold(yellow(match.RuleName)), match.Severity, match.FilePath, match.LineNumber)
		fmt.Println("    " + match.LineContent)
		if len(match.References) > 0 {
			for _, ref := range match.References {
				fmt.Println("    ↪ " + bold(ref))
			}
		}
		fmt.Println()

		writer.WriteString(fmt.Sprintf("Rule: %s\n", match.RuleName))
		writer.WriteString(fmt.Sprintf("Severity: %s\n", match.Severity))
		writer.WriteString(fmt.Sprintf("File: %s\n", match.FilePath))
		writer.WriteString(fmt.Sprintf("Line %d: %s\n", match.LineNumber, match.LineContent))
		if len(match.References) > 0 {
			writer.WriteString("References:\n")
			for _, ref := range match.References {
				writer.WriteString(fmt.Sprintf("  - %s\n", ref))
			}
		}
		writer.WriteString("---\n")
	}

	return writer.Flush()
}

func removeDir(dir string) {
	os.RemoveAll(dir)
}

func main() {
	requiredTools := []string{"apktool", "jadx", "aapt", "java"}
	fmt.Println("🔍 Checking dependencies...")
	missing := checkDependencies(requiredTools)
	if len(missing) > 0 {
		fmt.Println("❌ Missing tools:")
		for _, tool := range missing {
			fmt.Printf(" - %s\n", tool)
		}
		return
	}
	fmt.Println("✅ All required tools available.\n")

	apkFile := flag.String("f", "", "Path to the APK file")
	flag.Parse()

	if *apkFile == "" {
		fmt.Println("❌ No APK file provided. Use -f flag.")
		return
	}

	apkName := strings.TrimSuffix(filepath.Base(*apkFile), filepath.Ext(*apkFile))
	decompiled := "decompiled_apk"
	reportPath := fmt.Sprintf("%s_analysis.txt", apkName)

	fmt.Printf("📦 Decompiling %s...\n", *apkFile)
	cmd := exec.Command("apktool", "d", *apkFile, "-o", decompiled, "-f")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println("❌ Decompilation failed:", err)
		return
	}

	rules, err := loadRules("rules.json")
	if err != nil {
		fmt.Println("❌ Could not load rules.json:", err)
		return
	}

	fmt.Printf("✅ Loaded %d rule(s)\n", len(rules))
	matches, err := applyRules(rules, decompiled)
	if err != nil {
		fmt.Println("❌ Error applying rules:", err)
		return
	}

	fmt.Printf("🔍 Found %d issue(s)\n", len(matches))
	err = writeReport(matches, reportPath)
	if err != nil {
		fmt.Println("❌ Error writing report:", err)
		return
	}

	fmt.Printf("📄 Report written to: %s\n", reportPath)
	removeDir(decompiled)
}
