package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var DEBUG = false

type Config struct {
	URL          string        `yaml:"url"`
	ChromePath   string        `yaml:"chrome_path"`
	DatabasePath string        `yaml:"database_path"`   // SQLite database path for historical data
	WebhookURL   string        `yaml:"webhook_url"`     // optional: POST here on change
	RequestTO    time.Duration `yaml:"request_timeout"` // timeout for the whole chrome run
	ExtraArgs    []string      `yaml:"extra_args"`      // extra flags to pass to Chrome
	HTTPAddr     string        `yaml:"http_addr"`       // HTTP server listen address

	ChromeUpdateEvery time.Duration `yaml:"chrome_update_every"` // how often to check for Chrome updates
	ChromeVersionAPI  string        `yaml:"chrome_version_api"`  // API endpoint for Chrome version info
}

// Chrome version API response structures
type ChromeVersionResponse struct {
	Releases      []ChromeRelease `json:"releases"`
	NextPageToken string          `json:"nextPageToken"`
}

type ChromeRelease struct {
	Name          string        `json:"name"`
	Serving       ChromeServing `json:"serving"`
	Fraction      float64       `json:"fraction"`
	Version       string        `json:"version"`
	FractionGroup string        `json:"fractionGroup"`
	Pinnable      bool          `json:"pinnable"`
	RolloutData   []RolloutData `json:"rolloutData"`
}

type ChromeServing struct {
	StartTime string `json:"startTime"`
	EndTime   string `json:"endTime,omitempty"`
}

type RolloutData struct {
	RolloutName string   `json:"rolloutName"`
	Tag         []string `json:"tag"`
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func isWindows() bool {
	return strings.Contains(strings.ToLower(os.Getenv("OS")), "windows") ||
		strings.Contains(strings.ToLower(os.Getenv("ComSpec")), "cmd.exe")
}

func defaultChromePath() string {
	if isWindows() {
		// Common Chrome path on Windows:
		return `C:\Program Files\Google\Chrome\Application\chrome.exe`
	}
	return "/usr/bin/chromium-browser"
}

func splitArgs(s string) []string {
	fields := []string{}
	cur := strings.Builder{}
	inQuote := rune(0)
	for _, r := range s {
		switch {
		case (r == '"' || r == '\'') && inQuote == 0:
			inQuote = r
		case r == inQuote && inQuote != 0:
			inQuote = 0
		case r == ' ' && inQuote == 0:
			if cur.Len() > 0 {
				fields = append(fields, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		fields = append(fields, cur.String())
	}
	return fields
}

func loadConfig() Config {
	// Default configuration
	cfg := Config{
		URL:        "https://tls.peet.ws/api/all",
		ChromePath: defaultChromePath(),

		DatabasePath: "C:\\app\\data\\fingerprints.db",
		RequestTO:    30 * time.Second,
		HTTPAddr:     ":8080",

		ChromeUpdateEvery: 24 * time.Hour,
		ChromeVersionAPI:  "https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions/all/releases?filter=fraction=1",
	}

	// Try to load from YAML config file
	configPath := getenv("CONFIG_PATH", "config.yaml")
	if data, err := os.ReadFile(configPath); err == nil {
		var yamlCfg Config
		if err := yaml.Unmarshal(data, &yamlCfg); err != nil {
			log.Printf("WARN: Failed to parse config file %q: %v. Using defaults.", configPath, err)
		} else {
			if yamlCfg.URL != "" {
				cfg.URL = yamlCfg.URL
			}
			if yamlCfg.ChromePath != "" {
				cfg.ChromePath = yamlCfg.ChromePath
			}

			if yamlCfg.DatabasePath != "" {
				cfg.DatabasePath = yamlCfg.DatabasePath
			}
			if yamlCfg.WebhookURL != "" {
				cfg.WebhookURL = yamlCfg.WebhookURL
			}
			if yamlCfg.RequestTO != 0 {
				cfg.RequestTO = yamlCfg.RequestTO
			}
			if yamlCfg.HTTPAddr != "" {
				cfg.HTTPAddr = yamlCfg.HTTPAddr
			}
			if len(yamlCfg.ExtraArgs) > 0 {
				cfg.ExtraArgs = yamlCfg.ExtraArgs
			}
			if yamlCfg.ChromeVersionAPI != "" {
				cfg.ChromeVersionAPI = yamlCfg.ChromeVersionAPI
			}
			log.Printf("INFO: Loaded configuration from %q", configPath)
		}
	} else {
		log.Printf("INFO: Config file %q not found, using defaults and environment variables", configPath)

		// Fallback to environment variables
		cfg.URL = getenv("TARGET_URL", cfg.URL)
		cfg.ChromePath = getenv("CHROME_PATH", cfg.ChromePath)
		cfg.HTTPAddr = getenv("HTTP_ADDR", cfg.HTTPAddr)

		if extra := strings.TrimSpace(os.Getenv("CHROME_EXTRA_ARGS")); extra != "" {
			cfg.ExtraArgs = splitArgs(extra)
		}
	}

	return cfg
}

func runChromeJSON(ctx context.Context, chromePath, url string, extra []string) ([]byte, error) {
	// Use a fresh, ephemeral user-data-dir each run to reflect stock TLS as closely as possible.
	ud, err := os.MkdirTemp("", "chrome-ud-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(ud)

	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-first-run",
		"--no-default-browser-check",
		"--no-sandbox",
		"--user-data-dir=" + ud,
		"--disable-features=NetworkServiceInProcess",
		"--disable-dev-shm-usage",
		"--dump-dom",
		url,
	}
	args = append(extra, args...)

	cmd := exec.CommandContext(ctx, chromePath, args...)
	var out bytes.Buffer
	var errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb

	if err := cmd.Run(); err != nil {
		// On JSON endpoints, --dump-dom typically writes JSON to stdout.
		// If this fails, surface stderr for debugging.
		return nil, fmt.Errorf("chrome run failed: %w; stderr: %s", err, errb.String())
	}

	raw := bytes.TrimSpace(out.Bytes())
	if len(raw) == 0 {
		return nil, errors.New("empty output from chrome --dump-dom")
	}

	if bytes.HasPrefix(raw, []byte("<html")) || bytes.HasPrefix(raw, []byte("<!DOCTYPE")) {
		jsonBytes, err := extractJSONFromHTML(raw)
		if err != nil {
			return nil, fmt.Errorf("failed to extract JSON from HTML: %w", err)
		}
		return jsonBytes, nil
	}

	return raw, nil
}

// extractJSONFromHTML extracts JSON content from HTML, typically from <pre> tags
func extractJSONFromHTML(htmlBytes []byte) ([]byte, error) {
	htmlStr := string(htmlBytes)

	preRegex := regexp.MustCompile(`<pre[^>]*>(.*?)</pre>`)
	matches := preRegex.FindStringSubmatch(htmlStr)
	if len(matches) > 1 {
		jsonStr := strings.TrimSpace(matches[1])
		if (strings.HasPrefix(jsonStr, "{") && strings.HasSuffix(jsonStr, "}")) ||
			(strings.HasPrefix(jsonStr, "[") && strings.HasSuffix(jsonStr, "]")) {
			return []byte(jsonStr), nil
		}
	}

	for _, prefix := range []string{"{", "["} {
		startIdx := strings.Index(htmlStr, prefix)
		if startIdx == -1 {
			continue
		}

		for i := len(htmlStr) - 1; i > startIdx; i-- {
			candidate := strings.TrimSpace(htmlStr[startIdx : i+1])

			if (strings.HasPrefix(candidate, "{") && strings.HasSuffix(candidate, "}")) ||
				(strings.HasPrefix(candidate, "[") && strings.HasSuffix(candidate, "]")) {
				var test interface{}
				if err := json.Unmarshal([]byte(candidate), &test); err == nil {
					return []byte(candidate), nil
				}
			}
		}
	}

	return nil, errors.New("no valid JSON found in HTML content")
}

// extractTLSFields extracts the specific TLS fingerprint fields from the JSON response
func extractTLSFields(v any) (ja3, ja3hash, ja4, ja4r, peetprint, peetprintHash string) {
	if obj, ok := v.(map[string]any); ok {
		if tls, ok := obj["tls"].(map[string]any); ok {
			if val, ok := tls["ja3"].(string); ok {
				ja3 = val
			}
			if val, ok := tls["ja3_hash"].(string); ok {
				ja3hash = val
			}
			if val, ok := tls["ja4"].(string); ok {
				ja4 = val
			}
			if val, ok := tls["ja4_r"].(string); ok {
				ja4r = val
			}
			if val, ok := tls["peetprint"].(string); ok {
				peetprint = val
			}
			if val, ok := tls["peetprint_hash"].(string); ok {
				peetprintHash = val
			}
		}
	}
	return
}

// extractPeetprintFromJSON extracts only the peetprint from a JSON string
func extractPeetprintFromJSON(jsonStr string) string {
	var decoded any
	if err := json.Unmarshal([]byte(jsonStr), &decoded); err != nil {
		return ""
	}

	if obj, ok := decoded.(map[string]any); ok {
		if tls, ok := obj["tls"].(map[string]any); ok {
			if val, ok := tls["peetprint"].(string); ok {
				return val
			}
		}
	}
	return ""
}

// getCurrentChromeVersion gets the version of the currently installed Chrome using PowerShell
func getCurrentChromeVersion(chromePath string) (string, error) {
	if _, err := os.Stat(chromePath); err != nil {
		return "", fmt.Errorf("chrome not found at %s: %w", chromePath, err)
	}

	psScript := fmt.Sprintf(`(Get-Command "%s").FileVersionInfo.FileVersion`, chromePath)
	cmd := exec.Command("powershell", "-Command", psScript)

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get Chrome version via PowerShell: %w", err)
	}

	versionStr := strings.TrimSpace(string(output))
	if versionStr == "" {
		return "", fmt.Errorf("empty version output from PowerShell")
	}
	return versionStr, nil
}

// getLatestChromeVersion fetches the latest Chrome version from the API
func getLatestChromeVersion(apiURL string) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch Chrome version API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("chrome version API returned status %d", resp.StatusCode)
	}

	var versionResp ChromeVersionResponse
	if err := json.NewDecoder(resp.Body).Decode(&versionResp); err != nil {
		return "", fmt.Errorf("failed to decode Chrome version response: %w", err)
	}

	if len(versionResp.Releases) == 0 {
		return "", errors.New("no Chrome releases found in API response")
	}

	// Find the latest version with no endTime (currently active)
	var latestVersion string
	var latestTime time.Time

	for _, release := range versionResp.Releases {
		if release.Serving.EndTime == "" { // Currently active release
			startTime, err := time.Parse(time.RFC3339, release.Serving.StartTime)
			if err != nil {
				continue
			}
			if latestTime.IsZero() || startTime.After(latestTime) {
				latestTime = startTime
				latestVersion = release.Version
			}
		}
	}

	if latestVersion == "" {
		return "", errors.New("no currently active Chrome release found")
	}

	return latestVersion, nil
}

// compareVersions compares two version strings (e.g., "139.0.7258.128")
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	if v1 == v2 {
		return 0
	}

	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	// Pad shorter version with zeros
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for len(parts1) < maxLen {
		parts1 = append(parts1, "0")
	}
	for len(parts2) < maxLen {
		parts2 = append(parts2, "0")
	}

	// Compare each part numerically
	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		fmt.Sscanf(parts1[i], "%d", &n1)
		fmt.Sscanf(parts2[i], "%d", &n2)

		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}

	return 0
}

// installChrome executes PowerShell commands to download and install Chrome
// Executes:
// curl.exe -L "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi" -o chrome.msi
// Start-Process msiexec.exe -Wait -ArgumentList '/i chrome.msi /quiet /norestart'
// Remove-Item chrome.msi
func installChrome() error {
	log.Printf("INFO: Starting Chrome installation via PowerShell...")

	// PowerShell commands to execute
	commands := []string{
		`curl.exe -L "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi" -o chrome.msi`,
		`Start-Process msiexec.exe -Wait -ArgumentList '/i chrome.msi /quiet /norestart'`,
		`Remove-Item chrome.msi`,
	}

	for i, command := range commands {
		log.Printf("INFO: Executing PowerShell step %d: %s", i+1, command)

		cmd := exec.Command("powershell", "-Command", command)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("PowerShell command failed at step %d (%s): %w", i+1, command, err)
		}

		log.Printf("INFO: PowerShell step %d completed successfully", i+1)
	}

	log.Printf("INFO: Chrome installation completed successfully")
	return nil
}

// uninstallChrome executes PowerShell commands to find and uninstall Chrome
// Executes:
// Get-WmiObject Win32_Product | Where-Object { $_.Name -like "*Chrome*" } | Select-Object Name, IdentifyingNumber
// Start-Process msiexec.exe -ArgumentList '/x {ProductCode} /quiet /norestart /l*v C:\chrome-uninstall.log' -Wait
func uninstallChrome() error {
	log.Printf("INFO: Starting Chrome uninstallation via PowerShell...")

	// Step 1: Find Chrome products and their product codes
	findCommand := `Get-WmiObject Win32_Product | Where-Object { $_.Name -like "*Chrome*" } | Select-Object Name, IdentifyingNumber`

	log.Printf("INFO: Finding Chrome installations...")
	log.Printf("INFO: Executing: %s", findCommand)

	cmd := exec.Command("powershell", "-Command", findCommand)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to find Chrome installations: %w", err)
	}

	log.Printf("INFO: Chrome products found:")
	log.Printf("%s", string(output))

	// Step 2: Get product codes and uninstall each Chrome installation
	// More robust approach: get just the IdentifyingNumber values
	getCodesCommand := `Get-WmiObject Win32_Product | Where-Object { $_.Name -like "*Chrome*" } | ForEach-Object { $_.IdentifyingNumber }`

	log.Printf("INFO: Getting Chrome product codes...")
	cmd = exec.Command("powershell", "-Command", getCodesCommand)
	codesOutput, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get Chrome product codes: %w", err)
	}

	productCodes := strings.Fields(strings.TrimSpace(string(codesOutput)))

	if len(productCodes) == 0 {
		log.Printf("INFO: No Chrome installations found to uninstall")
		return nil
	}

	log.Printf("INFO: Found %d Chrome product(s) to uninstall", len(productCodes))

	// Step 3: Uninstall each Chrome product
	for i, productCode := range productCodes {
		if productCode == "" {
			continue
		}

		uninstallCommand := fmt.Sprintf(`Start-Process msiexec.exe -ArgumentList '/x %s /quiet /norestart /l*v C:\chrome-uninstall.log' -Wait`, productCode)

		log.Printf("INFO: Uninstalling Chrome product %d/%d (Code: %s)", i+1, len(productCodes), productCode)
		log.Printf("INFO: Executing: %s", uninstallCommand)

		cmd := exec.Command("powershell", "-Command", uninstallCommand)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			log.Printf("ERROR: Failed to uninstall Chrome product %s: %v", productCode, err)
			continue
		}

		log.Printf("INFO: Chrome product %s uninstalled successfully", productCode)
	}

	log.Printf("INFO: Chrome uninstallation process completed")
	return nil
}

// checkAndUpdateChrome checks for Chrome updates and optionally installs them
func checkAndUpdateChrome(cfg Config) (bool, error) {
	log.Printf("INFO: Checking for Chrome updates...")
	currentVersion, err := getCurrentChromeVersion(cfg.ChromePath)
	if DEBUG {
		currentVersion = "137.0.0.0"
	}
	if err != nil {
		return false, fmt.Errorf("failed to get current Chrome version: %w", err)
	}

	log.Printf("INFO: Current Chrome version: %s", currentVersion)

	latestVersion, err := getLatestChromeVersion(cfg.ChromeVersionAPI)
	if err != nil {
		return false, fmt.Errorf("failed to get latest Chrome version: %w", err)
	}

	log.Printf("INFO: Latest Chrome version: %s", latestVersion)

	comparison := compareVersions(currentVersion, latestVersion)

	if comparison >= 0 {
		log.Printf("INFO: Chrome is up to date (current: %s, latest: %s)", currentVersion, latestVersion)
		return false, nil
	}

	log.Printf("INFO: Chrome update available! Current: %s, Latest: %s", currentVersion, latestVersion)

	if cfg.WebhookURL != "" {
		notify(cfg.WebhookURL, map[string]any{
			"type":            "chrome_update_available",
			"at":              time.Now().UTC().Format(time.RFC3339),
			"current_version": currentVersion,
			"latest_version":  latestVersion,
		})
	}

	log.Printf("INFO: Auto-update enabled, updating Chrome via uninstall + reinstall...")

	log.Printf("INFO: Uninstalling existing Chrome...")
	if err := uninstallChrome(); err != nil {
		log.Printf("WARN: Failed to uninstall existing Chrome: %v", err)
		// Continue anyway - maybe Chrome wasn't properly installed
	}

	log.Printf("INFO: Installing latest Chrome...")
	if err := installChrome(); err != nil {
		return false, fmt.Errorf("failed to install Chrome: %w", err)
	}

	newVersion, err := getCurrentChromeVersion(cfg.ChromePath)
	if err != nil {
		return false, fmt.Errorf("failed to verify Chrome version after installation: %w", err)
	}

	log.Printf("INFO: Chrome successfully updated from %s to %s", currentVersion, newVersion)

	if cfg.WebhookURL != "" {
		notify(cfg.WebhookURL, map[string]any{
			"type":        "chrome_update_completed",
			"at":          time.Now().UTC().Format(time.RFC3339),
			"old_version": currentVersion,
			"new_version": newVersion,
			"method":      "uninstall_reinstall",
		})
	}
	return true, nil
}

// SlackMessage represents a Slack webhook message
type SlackMessage struct {
	Text        string            `json:"text"`
	Username    string            `json:"username,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
}

type SlackAttachment struct {
	Color     string       `json:"color,omitempty"`
	Title     string       `json:"title,omitempty"`
	Text      string       `json:"text,omitempty"`
	Fields    []SlackField `json:"fields,omitempty"`
	Timestamp int64        `json:"ts,omitempty"`
}

type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

func notify(webhook string, payload any) {
	if webhook == "" {
		return
	}

	var requestBody []byte
	var err error

	if strings.Contains(webhook, "hooks.slack.com") {
		slackMsg := formatSlackMessage(payload)
		requestBody, err = json.Marshal(slackMsg)
	} else {
		requestBody, err = json.Marshal(payload)
	}

	if err != nil {
		log.Printf("WARN: failed to marshal webhook payload: %v", err)
		return
	}

	req, err := http.NewRequest("POST", webhook, bytes.NewReader(requestBody))
	if err != nil {
		log.Printf("WARN: failed to create webhook request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("WARN: webhook request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("WARN: webhook returned status %d", resp.StatusCode)
	} else {
		log.Printf("INFO: Webhook notification sent successfully")
	}
}

func formatSlackMessage(payload any) SlackMessage {
	data, ok := payload.(map[string]any)
	if !ok {
		return SlackMessage{
			Text:      "Chrome TLS Monitor Alert",
			Username:  "TLS Monitor",
			IconEmoji: ":warning:",
		}
	}

	msgType, _ := data["type"].(string)
	timestamp := time.Now().Unix()

	switch msgType {
	case "chrome_tls_fingerprint_changed":
		return formatTLSFingerprintMessage(data, timestamp)
	case "chrome_update_available":
		return formatChromeUpdateAvailableMessage(data, timestamp)
	case "chrome_update_completed":
		return formatChromeUpdateCompletedMessage(data, timestamp)
	default:
		return SlackMessage{
			Text:      fmt.Sprintf("Chrome TLS Monitor: %s", msgType),
			Username:  "TLS Monitor",
			IconEmoji: ":information_source:",
			Attachments: []SlackAttachment{{
				Color:     "warning",
				Text:      "Unknown notification type",
				Timestamp: timestamp,
			}},
		}
	}
}

func formatTLSFingerprintMessage(data map[string]any, timestamp int64) SlackMessage {
	chromeVersion, _ := data["chrome_version"].(string)
	currentPeetprint, _ := data["current_peetprint"].(string)
	prevPeetprint, _ := data["previous_peetprint"].(string)
	sourceURL, _ := data["source_url"].(string)

	var color string
	var title string
	var emoji string

	if prevPeetprint == "" {
		color = "good"
		title = "🆕 TLS Fingerprint - First Run"
		emoji = ":new:"
	} else {
		color = "danger"
		title = "🚨 TLS Fingerprint Changed!"
		emoji = ":warning:"
	}

	// Truncate peetprint for display
	displayCurrent := currentPeetprint
	if len(displayCurrent) > 50 {
		displayCurrent = displayCurrent[:50] + "..."
	}

	displayPrev := prevPeetprint
	if len(displayPrev) > 50 {
		displayPrev = displayPrev[:50] + "..."
	}

	fields := []SlackField{
		{Title: "Chrome Version", Value: chromeVersion, Short: true},
		{Title: "Source URL", Value: sourceURL, Short: true},
		{Title: "Current Peetprint", Value: "`" + displayCurrent + "`", Short: false},
	}

	if prevPeetprint != "" {
		fields = append(fields, SlackField{
			Title: "Previous Peetprint",
			Value: "`" + displayPrev + "`",
			Short: false,
		})
	}

	return SlackMessage{
		Text:      title,
		Username:  "TLS Monitor",
		IconEmoji: emoji,
		Attachments: []SlackAttachment{{
			Color:     color,
			Title:     "Chrome TLS Fingerprint Detection",
			Text:      "TLS fingerprint monitoring detected a change in the browser's TLS signature.",
			Fields:    fields,
			Timestamp: timestamp,
		}},
	}
}

func formatChromeUpdateAvailableMessage(data map[string]any, timestamp int64) SlackMessage {
	currentVersion, _ := data["current_version"].(string)
	latestVersion, _ := data["latest_version"].(string)

	return SlackMessage{
		Text:      "📥 Chrome Update Available",
		Username:  "TLS Monitor",
		IconEmoji: ":arrow_up:",
		Attachments: []SlackAttachment{{
			Color: "warning",
			Title: "Chrome Version Update Detected",
			Text:  "A new version of Chrome is available for download.",
			Fields: []SlackField{
				{Title: "Current Version", Value: currentVersion, Short: true},
				{Title: "Latest Version", Value: latestVersion, Short: true},
			},
			Timestamp: timestamp,
		}},
	}
}

func formatChromeUpdateCompletedMessage(data map[string]any, timestamp int64) SlackMessage {
	oldVersion, _ := data["old_version"].(string)
	newVersion, _ := data["new_version"].(string)
	method, _ := data["method"].(string)

	return SlackMessage{
		Text:      "✅ Chrome Update Completed",
		Username:  "TLS Monitor",
		IconEmoji: ":white_check_mark:",
		Attachments: []SlackAttachment{{
			Color: "good",
			Title: "Chrome Successfully Updated",
			Text:  fmt.Sprintf("Chrome has been updated using method: %s", method),
			Fields: []SlackField{
				{Title: "Previous Version", Value: oldVersion, Short: true},
				{Title: "New Version", Value: newVersion, Short: true},
			},
			Timestamp: timestamp,
		}},
	}
}

func runOnce(db *Database, cfg Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.RequestTO)
	defer cancel()

	raw, err := runChromeJSON(ctx, cfg.ChromePath, cfg.URL, cfg.ExtraArgs)
	if err != nil {
		return err
	}

	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return fmt.Errorf("invalid JSON from endpoint: %w", err)
	}

	chromeVersion, err := getCurrentChromeVersion(cfg.ChromePath)
	if err != nil {
		log.Printf("WARN: Could not get Chrome version for database: %v", err)
		chromeVersion = "unknown"
	}

	_, _, _, _, currentPeetprint, _ := extractTLSFields(decoded)
	if currentPeetprint == "" {
		log.Printf("WARN: No peetprint found in current response")
	}

	var prevPeetprint string
	if prevFingerprint, err := db.GetLatestFingerprint(chromeVersion); err == nil {
		prevPeetprint = extractPeetprintFromJSON(prevFingerprint.RawResponse)
		log.Printf("DEBUG: Found previous peetprint: %q", prevPeetprint)
	} else {
		log.Printf("DEBUG: No previous fingerprint found for Chrome version %s: %v", chromeVersion, err)
	}

	now := time.Now()

	changed := (currentPeetprint != "" && currentPeetprint != prevPeetprint) || (prevPeetprint == "" && currentPeetprint != "")

	if changed {
		if prevPeetprint == "" {
			log.Printf("TLS fingerprint FIRST RUN:")
		} else {
			log.Printf("TLS fingerprint CHANGED:")
		}
		log.Printf("  PEETPRINT: %q (prev: %q)", currentPeetprint, prevPeetprint)
		log.Printf("  Chrome Version: %s", chromeVersion)

		notify(cfg.WebhookURL, map[string]any{
			"type":               "chrome_tls_fingerprint_changed",
			"at":                 now.UTC().Format(time.RFC3339),
			"chrome_version":     chromeVersion,
			"current_peetprint":  currentPeetprint,
			"previous_peetprint": prevPeetprint,
			"source_url":         cfg.URL,
		})

		tlsFp := &TLSFingerprint{
			ChromeVersion: chromeVersion,
			RawResponse:   string(raw), // Store the original JSON response
			CollectedAt:   now,
		}

		log.Printf("INFO: Saving TLS fingerprint to database...")
		if err := db.SaveTLSFingerprint(tlsFp); err != nil {
			log.Printf("ERROR: Failed to save TLS fingerprint to database: %v", err)
		} else {
			log.Printf("INFO: TLS fingerprint saved to database successfully")
		}
	} else {
		log.Printf("TLS fingerprint unchanged (PEETPRINT=%q)", currentPeetprint)
	}

	return nil
}

// Minimal HTTP server so you can health-check quickly.
func startHTTP(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	go func() {
		log.Printf("HTTP: listening on %s (GET /healthz)", addr)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Fatalf("http server: %v", err)
		}
	}()
}

func main() {
	log.Printf("Chrome TLS fingerprint monitor started.")
	cfg := loadConfig()

	if _, err := os.Stat(cfg.ChromePath); err != nil {
		log.Printf("WARN: Chrome not found at %q (override with CHROME_PATH). Error: %v", cfg.ChromePath, err)
	}

	startHTTP(cfg.HTTPAddr)

	db, err := NewDatabase(cfg.DatabasePath)
	if err != nil {
		log.Printf("ERROR (NewDatabase): %v", err)
		return
	}
	defer func(db *Database) {
		err := db.Close()
		if err != nil {
			log.Printf("Error (db.Close) %v", err)
		}
	}(db)

	// Run TLS monitoring immediately at startup, then on a schedule.
	if err := runOnce(db, cfg); err != nil {
		log.Printf("ERROR (startup run): %v", err)
	}

	var chromeUpdateTicker *time.Ticker
	if _, err := checkAndUpdateChrome(cfg); err != nil {
		log.Printf("ERROR (Chrome version check): %v", err)
	}

	chromeUpdateTicker = time.NewTicker(cfg.ChromeUpdateEvery)
	defer chromeUpdateTicker.Stop()

	for {
		select {
		case <-chromeUpdateTicker.C:
			isUpdated, err := checkAndUpdateChrome(cfg)
			if err != nil {
				log.Printf("ERROR (Chrome version check): %v", err)
			}
			if isUpdated {
				log.Printf("INFO: Chrome was updated, running immediate TLS check...")
				if err := runOnce(db, cfg); err != nil {
					log.Printf("ERROR (post-update TLS run): %v", err)
				}
			}
		}
	}
}
