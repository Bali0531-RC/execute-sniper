package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
)

// Config represents the application configuration
type Config struct {
	MainToken        string `json:"main_token"`
	DebugMode        bool   `json:"debug_mode"`
	TokenFile        string `json:"token_file"`
	UserAgent        string `json:"user_agent"`
	DiscordAPI       string `json:"discord_api"`
	SuccessWebhook   string `json:"success_webhook_url"`
	InviteMinMembers int    `json:"invite_min_members"`
	InviteFile       string `json:"invite_file"`
}

const configFile = "config.json"

var (
	config           Config
	tokens           []string
	usernames        = make(map[string]string) // Map token -> username
	nitroRegex       = regexp.MustCompile("(discord.gift/|discordapp.com/gifts/|discord.com/gifts/)([a-zA-Z0-9]+)")
	inviteRegex      = regexp.MustCompile("(discord.gg/|discord.com/invite/)([a-zA-Z0-9]+)")
	giftLinkAttempts = make(map[string]bool)
	invitesLogged    = make(map[string]bool)
	attemptsMutex    sync.Mutex
	inviteMutex      sync.Mutex
	successfulClaims = 0
	failedClaims     = 0
	statsMutex       sync.Mutex
	activeSessions   = make([]*discordgo.Session, 0)
	serverCount      = make(map[string]int)  // Map token -> number of servers
	totalServers     = 0                     // Total unique servers across all tokens
	uniqueGuilds     = make(map[string]bool) // Track unique guild IDs
)

func init() {
	// Load configuration
	loadConfig()

	// Add main token to list of tokens
	tokens = append(tokens, config.MainToken)

	// Read additional tokens from file
	readTokensFromFile()
}

// loadConfig loads the configuration from file or creates a new one
func loadConfig() {
	// Try to read existing config
	data, err := ioutil.ReadFile(configFile)
	if err == nil {
		// Config exists, parse it
		err = json.Unmarshal(data, &config)
		if err != nil {
			fmt.Printf("Error parsing config file: %v\n", err)
			fmt.Println("Creating a new config file...")
			config = getDefaultConfig()
		}
	} else {
		// Config doesn't exist, create default
		fmt.Println("Config file not found. Creating a new one...")
		config = getDefaultConfig()
	}

	// Validate config and prompt for missing values
	validateConfig()

	// Save the config
	saveConfig()
}

// getDefaultConfig returns default configuration values
func getDefaultConfig() Config {
	return Config{
		DebugMode:        false,
		TokenFile:        "tokens.txt",
		UserAgent:        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36",
		DiscordAPI:       "https://discord.com/api/v9",
		SuccessWebhook:   "",
		InviteMinMembers: 150,
		InviteFile:       "invites.txt",
	}
}

// validateConfig checks all config values and prompts for missing ones
func validateConfig() {
	reader := bufio.NewReader(os.Stdin)

	// Validate main token
	if config.MainToken == "" {
		fmt.Println("Main Discord token is required.")
		fmt.Print("Please enter your Discord token: ")
		config.MainToken, _ = reader.ReadString('\n')
		config.MainToken = strings.TrimSpace(config.MainToken)
	}

	// Validate webhook URL (optional)
	if config.SuccessWebhook == "" {
		fmt.Println("\nA Discord webhook URL is recommended for successful Nitro claim notifications.")
		fmt.Print("Enter Discord webhook URL (leave empty to skip): ")
		config.SuccessWebhook, _ = reader.ReadString('\n')
		config.SuccessWebhook = strings.TrimSpace(config.SuccessWebhook)
	}

	// Validate invite member threshold
	if config.InviteMinMembers <= 0 {
		fmt.Println("\nSetting minimum server members for logging Discord invites.")
		fmt.Print("Enter minimum member count (default 150): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			config.InviteMinMembers = 150
		} else {
			val, err := strconv.Atoi(input)
			if err != nil || val < 0 {
				fmt.Println("Invalid number, using default (150)")
				config.InviteMinMembers = 150
			} else {
				config.InviteMinMembers = val
			}
		}
	}

	// Validate token file path
	if config.TokenFile == "" {
		config.TokenFile = "tokens.txt"
	}

	// Validate invite file path
	if config.InviteFile == "" {
		config.InviteFile = "invites.txt"
	}
}

// saveConfig saves the configuration to file
func saveConfig() {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		fmt.Printf("Error creating config file: %v\n", err)
		return
	}

	err = ioutil.WriteFile(configFile, data, 0644)
	if err != nil {
		fmt.Printf("Error writing config file: %v\n", err)
		return
	}

	fmt.Println("Configuration saved successfully!")
}

func readTokensFromFile() {
	file, err := os.Open(config.TokenFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("Info: %s file not found. Operating with main token only.\n", config.TokenFile)
			return
		}
		fmt.Printf("Error opening tokens file: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		token := strings.TrimSpace(scanner.Text())
		if token != "" && token != config.MainToken { // Skip empty lines and duplicates
			tokens = append(tokens, token)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading tokens file: %v\n", err)
	}

	fmt.Printf("Loaded %d tokens (including main token)\n", len(tokens))
}

func main() {
	fmt.Println("=== ExeCute Sniper (v0.0.2 beta) ===")
	if config.DebugMode {
		fmt.Println("Debug mode is enabled - all messages will be logged")
	}

	// Connect with each token
	var wg sync.WaitGroup
	for i, token := range tokens {
		// Connect with slight delay to avoid rate limiting
		time.Sleep(time.Duration(i*500) * time.Millisecond)
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			connectWithToken(t)
		}(token)
	}

	// Wait a bit for all connections to establish
	go func() {
		wg.Wait()
		time.Sleep(2 * time.Second) // Give time for server counts to be collected
		printServerStats()
	}()

	// Print stats every minute
	go func() {
		for {
			time.Sleep(600 * time.Second)
			printStats()
		}
	}()

	// Wait for CTRL-C
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM)
	<-sc

	// Close all Discord sessions
	fmt.Println("Shutting down connections...")
	for _, s := range activeSessions {
		s.Close()
	}
}

func printServerStats() {
	statsMutex.Lock()
	defer statsMutex.Unlock()

	fmt.Println("\n=== Server Coverage Stats ===")
	fmt.Printf("Total unique servers monitored: %d\n", totalServers)

	// Sort tokens by server count (most servers first)
	type tokenServerCount struct {
		username string
		token    string
		count    int
	}

	var sortedTokens []tokenServerCount
	for token, count := range serverCount {
		username := usernames[token]
		if username == "" {
			username = "Unknown"
		}
		sortedTokens = append(sortedTokens, tokenServerCount{
			username: username,
			token:    token,
			count:    count,
		})
	}

	// Sort by count (descending)
	for i := 0; i < len(sortedTokens)-1; i++ {
		for j := i + 1; j < len(sortedTokens); j++ {
			if sortedTokens[i].count < sortedTokens[j].count {
				sortedTokens[i], sortedTokens[j] = sortedTokens[j], sortedTokens[i]
			}
		}
	}

	// Print each token's server count
	for _, tc := range sortedTokens {
		lastChars := "test"
		if len(tc.token) >= 5 {
			lastChars = tc.token[len(tc.token)-5:]
		}
		fmt.Printf("- %s (token: %s): %d servers\n", tc.username, lastChars, tc.count)
	}

	fmt.Println("===========================")
}

func testInviteLinkDetection(inviteLink string) {
	fmt.Printf("Testing invite link detection for: %s\n", inviteLink)

	// Create a fake message
	message := &discordgo.MessageCreate{
		Message: &discordgo.Message{
			Content: fmt.Sprintf("Hey, join my server: %s", inviteLink),
			Author: &discordgo.User{
				ID:       "000000000000000000", // Fake ID
				Username: "TestUser",
			},
			ChannelID: "000000000000000000", // Fake channel ID
		},
	}

	// Process the fake message with nil session for test
	messageCreate(nil, message)
}

func connectWithToken(token string) {
	// Create a new Discord session using a user token (not a bot token)
	dg, err := discordgo.New(token)
	if err != nil {
		fmt.Printf("Error creating Discord session for token ending in %s: %v\n",
			token[len(token)-5:], err)
		return
	}

	// Modify the session to only use the supported fields in your version
	dg.Identify.Properties = discordgo.IdentifyProperties{
		OS:      "Windows",
		Browser: "Chrome",
		Device:  "",
	}

	// Apply additional headers directly to improve user token behavior
	dg.UserAgent = config.UserAgent

	// Set necessary intents to receive messages including message content
	dg.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsDirectMessages | discordgo.IntentMessageContent

	// Disable compression - this can sometimes help with message content
	dg.Identify.Compress = false

	// Register message handler
	dg.AddHandler(messageCreate)

	// Open websocket connection
	err = dg.Open()
	if err != nil {
		fmt.Printf("Error opening connection for token ending in %s: %v\n",
			token[len(token)-5:], err)
		return
	}

	// Store session for later cleanup
	activeSessions = append(activeSessions, dg)

	// Store username and discriminator for logging
	me, err := dg.User("@me")
	if err != nil {
		usernames[token] = "Unknown"
		fmt.Printf("Connected with token ending in %s (failed to get username)\n",
			token[len(token)-5:])
	} else {
		username := me.Username
		if me.Discriminator != "0" {
			username += "#" + me.Discriminator
		}
		usernames[token] = username
		fmt.Printf("Connected with token for %s (token ending: %s)\n",
			username, token[len(token)-5:])
	}

	// Get and store server count for this token
	// Fix for UserGuilds function signature - add false parameter
	guilds, err := dg.UserGuilds(0, "", "", false)
	if err != nil {
		fmt.Printf("Error fetching guilds for %s: %v\n", usernames[token], err)
		statsMutex.Lock()
		serverCount[token] = 0
		statsMutex.Unlock()
		return
	}

	statsMutex.Lock()
	defer statsMutex.Unlock()

	// Store server count for this token
	serverCount[token] = len(guilds)

	// Update the total unique servers count
	for _, g := range guilds {
		if !uniqueGuilds[g.ID] {
			uniqueGuilds[g.ID] = true
			totalServers++
		}
	}
}

func testGiftLinkDetection(giftLink string) {
	fmt.Printf("Testing gift link detection for: %s\n", giftLink)

	// Create a fake message
	message := &discordgo.MessageCreate{
		Message: &discordgo.Message{
			Content: fmt.Sprintf("Hey, check out this nitro: %s", giftLink),
			Author: &discordgo.User{
				ID:       "000000000000000000", // Fake ID
				Username: "TestUser",
			},
			ChannelID: "000000000000000000", // Fake channel ID
		},
	}

	// Process the fake message with nil session for test
	messageCreate(nil, message)
}

func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	// Start timing for message processing
	messageStartTime := time.Now()

	// Get username that received this message
	var username string
	if s != nil {
		username = usernames[s.Token]
		if username == "" {
			username = "Unknown"
		}
	} else {
		username = "TestAccount"
	}

	// Log all incoming messages in debug mode
	if config.DebugMode {
		fmt.Printf("DEBUG [%s]: Message received from %s: %s\n",
			username, m.Author.Username, m.Content)
	}

	// Ignore messages from the bot itself
	if s != nil && m.Author.ID == s.State.User.ID {
		if config.DebugMode {
			fmt.Printf("DEBUG [%s]: Ignoring own message\n", username)
		}
		return
	}

	// Process nitro gift links
	processNitroLinks(s, m, username, messageStartTime)

	// Process invite links
	processInviteLinks(s, m, username)
}

func processNitroLinks(s *discordgo.Session, m *discordgo.MessageCreate, username string, messageStartTime time.Time) {
	// Check if message contains a Nitro gift link - broader check
	detectionStartTime := time.Now()
	if strings.Contains(m.Content, "discord.gift/") {
		fmt.Printf("DEBUG [%s]: Potential gift link detected: %s\n", username, m.Content)
	}

	// Use regex to extract codes
	matches := nitroRegex.FindAllStringSubmatch(m.Content, -1)
	detectionDuration := time.Since(detectionStartTime)

	if config.DebugMode && len(matches) == 0 {
		fmt.Printf("DEBUG [%s]: No gift links matched in message: %s\n", username, m.Content)
		fmt.Printf("DEBUG [%s]: Detection took %s\n", username, detectionDuration)
	}

	for _, match := range matches {
		if len(match) >= 3 {
			code := match[2]

			// Log timing information for detection
			fmt.Printf("⏱️ [%s] Gift link detection time: %s\n", username, detectionDuration)

			// Log all detected codes regardless of length
			fmt.Printf("DEBUG [%s]: Detected code: %s (length: %d)\n", username, code, len(code))

			// Skip if we've already tried this code (using mutex for thread safety)
			attemptsMutex.Lock()
			alreadyAttempted := giftLinkAttempts[code]
			if !alreadyAttempted {
				giftLinkAttempts[code] = true
			}
			attemptsMutex.Unlock()

			if alreadyAttempted {
				fmt.Printf("DEBUG [%s]: Skipping already attempted code: %s\n", username, code)
				continue
			}

			// Get server and channel names for logging
			var guildName, channelName string
			if s != nil {
				guildName = getServerName(s, m.GuildID)
				channelName = getChannelName(s, m.ChannelID)
				fmt.Printf("🎁 [%s] Found gift link: discord.gift/%s in server: %s, channel: %s\n",
					username, code, guildName, channelName)
			} else {
				guildName = "Test Server"
				channelName = "Test Channel"
				fmt.Printf("🎁 [%s] Found gift link: discord.gift/%s (test message)\n", username, code)
			}

			// Check if code is too short (likely invalid)
			if len(code) < 16 {
				fmt.Printf("⚠️ [%s] Code %s appears too short to be valid (length: %d)\n",
					username, code, len(code))
			}

			// Try to actually claim the Nitro gift
			claimStartTime := time.Now()

			// For test messages, use simulation unless it's a potentially valid code
			if s == nil && len(code) < 16 {
				simulateClaimAttempt(code, username) // Simulate for obviously invalid test codes
			} else {
				// Always claim with the main token regardless of which account detected it
				claimNitroGift(code, username, guildName, channelName)
			}

			claimDuration := time.Since(claimStartTime)

			// Log timing information for claim attempt
			fmt.Printf("⏱️ [%s] Claim attempt time: %s\n", username, claimDuration)
		}
	}

	// Calculate total processing time
	totalDuration := time.Since(messageStartTime)
	if len(matches) > 0 {
		fmt.Printf("⏱️ [%s] Total processing time: %s\n", username, totalDuration)
	} else if config.DebugMode {
		fmt.Printf("DEBUG [%s]: Total message processing time: %s\n", username, totalDuration)
	}
}

func processInviteLinks(s *discordgo.Session, m *discordgo.MessageCreate, username string) {
	// Only process invites if we have a real session (not test)
	if s == nil {
		return
	}

	// Extract invite codes using regex
	matches := inviteRegex.FindAllStringSubmatch(m.Content, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			inviteCode := match[2]

			// Skip if we've already logged this invite
			inviteMutex.Lock()
			alreadyLogged := invitesLogged[inviteCode]
			if !alreadyLogged {
				invitesLogged[inviteCode] = true
			}
			inviteMutex.Unlock()

			if alreadyLogged {
				if config.DebugMode {
					fmt.Printf("DEBUG [%s]: Skipping already logged invite: %s\n", username, inviteCode)
				}
				continue
			}

			// Check invite details to see member count
			go checkAndLogInvite(s, inviteCode, username, m.GuildID, m.ChannelID)
		}
	}
}

func checkAndLogInvite(s *discordgo.Session, inviteCode string, username string, guildID string, channelID string) {
	// Get invite details from the API
	invite, err := s.InviteWithCounts(inviteCode)
	if err != nil {
		if config.DebugMode {
			fmt.Printf("DEBUG [%s]: Error checking invite %s: %v\n", username, inviteCode, err)
		}
		return
	}

	// Check if server member count meets minimum threshold
	if invite.ApproximateMemberCount >= config.InviteMinMembers {
		// Log to console
		fmt.Printf("🔗 [%s] Found server invite: %s (Members: %d, Server: %s)\n",
			username, inviteCode, invite.ApproximateMemberCount, invite.Guild.Name)

		// Create log entry
		logEntry := fmt.Sprintf("[%s] discord.gg/%s | Server: %s | Members: %d | Found in: %s/%s\n",
			time.Now().Format("2006-01-02 15:04:05"),
			inviteCode,
			invite.Guild.Name,
			invite.ApproximateMemberCount,
			getServerName(s, guildID),
			getChannelName(s, channelID))

		// Log to file
		f, err := os.OpenFile(config.InviteFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("Error opening invite log file: %v\n", err)
			return
		}
		defer f.Close()

		if _, err := f.WriteString(logEntry); err != nil {
			fmt.Printf("Error writing to invite log file: %v\n", err)
		}
	} else if config.DebugMode {
		fmt.Printf("DEBUG [%s]: Ignoring invite %s (only %d members, minimum: %d)\n",
			username, inviteCode, invite.ApproximateMemberCount, config.InviteMinMembers)
	}
}

// Function to check if a Nitro gift code is valid without claiming it
func checkGiftValidity(code string) (bool, string) {
	url := fmt.Sprintf("%s/entitlements/gift-codes/%s", config.DiscordAPI, code)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, fmt.Sprintf("Error creating request: %v", err)
	}

	req.Header.Set("User-Agent", config.UserAgent)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("Network error: %v", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	bodyString := string(body)

	if resp.StatusCode == 200 {
		// Check if the gift is already redeemed or expired
		if strings.Contains(bodyString, "\"consumed\":true") {
			return false, "Gift has already been claimed"
		}
		if strings.Contains(bodyString, "\"expired\":true") {
			return false, "Gift has expired"
		}

		// Extract gift information for logging
		var giftInfo string
		if strings.Contains(bodyString, "Nitro Classic") {
			giftInfo = "Nitro Classic"
		} else if strings.Contains(bodyString, "Nitro") {
			giftInfo = "Nitro"
		} else {
			giftInfo = "Unknown subscription"
		}

		return true, giftInfo
	} else if resp.StatusCode == 404 {
		return false, "Invalid gift code"
	} else if resp.StatusCode == 429 {
		return false, "Rate limited by Discord API"
	}

	return false, fmt.Sprintf("Unknown error (HTTP %d): %s", resp.StatusCode, bodyString)
}

// Function to actually claim a Nitro gift
func claimNitroGift(code string, detectorUsername string, guildName string, channelName string) {
	// Get the main username for logging
	claimUsername := usernames[config.MainToken]
	if claimUsername == "" {
		claimUsername = "MainAccount"
	}

	// Always log that we're using the main account, even if detector is the main account
	fmt.Printf("🔍 [%s] Attempting to claim code: %s (using main account: %s)\n",
		detectorUsername, code, claimUsername)

	// Start timing for the actual API call
	apiCallStart := time.Now()

	// First check if the gift is valid without claiming
	valid, giftInfo := checkGiftValidity(code)

	checkDuration := time.Since(apiCallStart)
	fmt.Printf("⏱️ [%s] Validity check time: %s\n", detectorUsername, checkDuration)

	if !valid {
		fmt.Printf("❌ [%s] Not attempting to claim invalid code: %s (%s)\n",
			detectorUsername, code, giftInfo)

		statsMutex.Lock()
		failedClaims++
		statsMutex.Unlock()

		return
	}

	fmt.Printf("✅ [%s] Valid gift detected: %s - Contains %s\n",
		detectorUsername, code, giftInfo)

	// Now actually try to claim the gift
	url := fmt.Sprintf("%s/entitlements/gift-codes/%s/redeem", config.DiscordAPI, code)

	// Empty JSON payload
	payload := []byte("{}")

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		fmt.Printf("❌ [%s] Error creating claim request: %v\n", detectorUsername, err)

		statsMutex.Lock()
		failedClaims++
		statsMutex.Unlock()

		return
	}

	// Always use the main token here
	req.Header.Set("Authorization", config.MainToken)
	req.Header.Set("User-Agent", config.UserAgent)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("❌ [%s] Network error during claiming: %v\n", detectorUsername, err)

		statsMutex.Lock()
		failedClaims++
		statsMutex.Unlock()

		return
	}
	defer resp.Body.Close()

	// Log API request time
	apiCallDuration := time.Since(apiCallStart)
	fmt.Printf("⏱️ [%s] API request time: %s\n", detectorUsername, apiCallDuration)

	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		statsMutex.Lock()
		successfulClaims++
		statsMutex.Unlock()

		fmt.Printf("🎉 [%s] Successfully claimed Nitro gift: %s for MAIN account %s\n",
			detectorUsername, code, claimUsername)

		// Try to parse the response to get more details
		var result map[string]interface{}
		var subscriptionType string

		if err := json.Unmarshal(body, &result); err == nil {
			if subscription, ok := result["subscription_plan"]; ok {
				if subMap, ok := subscription.(map[string]interface{}); ok {
					if name, ok := subMap["name"].(string); ok {
						subscriptionType = name
						fmt.Printf("   Subscription type: %s\n", name)
					}
				}
			}
		}

		// Send webhook notification for successful claim
		if config.SuccessWebhook != "" {
			sendWebhookNotification(code, detectorUsername, guildName, channelName, subscriptionType)
		}
	} else {
		statsMutex.Lock()
		failedClaims++
		statsMutex.Unlock()

		fmt.Printf("❌ [%s] Failed to claim code: %s (HTTP %d)\n",
			detectorUsername, code, resp.StatusCode)
		fmt.Printf("   Response: %s\n", string(body))
	}
}

func sendWebhookNotification(code string, detectorUsername string, guildName string, channelName string, subscriptionType string) {
	// Prepare webhook payload
	webhookData := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       "✅ Nitro Successfully Claimed!",
				"description": fmt.Sprintf("Successfully claimed Nitro gift code: `%s`", code),
				"color":       5763719, // Green color
				"fields": []map[string]interface{}{
					{
						"name":   "Subscription",
						"value":  subscriptionType,
						"inline": true,
					},
					{
						"name":   "Detected By",
						"value":  detectorUsername,
						"inline": true,
					},
					{
						"name":   "Source",
						"value":  fmt.Sprintf("%s / %s", guildName, channelName),
						"inline": true,
					},
					{
						"name":   "Claimed At",
						"value":  time.Now().Format("2006-01-02 15:04:05"),
						"inline": true,
					},
				},
				"footer": map[string]interface{}{
					"text": "ExeCute Nitro Sniper",
				},
				"timestamp": time.Now().Format(time.RFC3339),
			},
		},
	}

	// Convert to JSON
	webhookBytes, err := json.Marshal(webhookData)
	if err != nil {
		fmt.Printf("Error creating webhook payload: %v\n", err)
		return
	}

	// Send the webhook request
	req, err := http.NewRequest("POST", config.SuccessWebhook, bytes.NewBuffer(webhookBytes))
	if err != nil {
		fmt.Printf("Error creating webhook request: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending webhook: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("Webhook error (HTTP %d): %s\n", resp.StatusCode, string(body))
	} else if config.DebugMode {
		fmt.Println("Webhook notification sent successfully!")
	}
}

func simulateClaimAttempt(code string, username string) {
	// Used only for test messages with obviously invalid codes
	fmt.Printf("🔍 [%s] Simulating claim for test code: %s\n", username, code)

	// Start timing for the simulated API call
	apiCallStart := time.Now()

	// Simulate API response delay
	delay := 500 * time.Millisecond
	if len(code) > 16 {
		delay = 800 * time.Millisecond
	}
	time.Sleep(delay)

	// Log the API call time (simulated)
	apiCallDuration := time.Since(apiCallStart)
	fmt.Printf("⏱️ [%s] API request time (simulated): %s\n", username, apiCallDuration)

	// For short codes, always fail as they're definitely invalid
	if len(code) < 16 {
		statsMutex.Lock()
		failedClaims++
		statsMutex.Unlock()

		fmt.Printf("❌ [%s] Failed to claim code: %s (Invalid code - too short, minimum length is 16)\n",
			username, code)
		return
	}

	// Randomly succeed or fail (for demonstration)
	if time.Now().UnixNano()%5 == 0 { // 20% chance to "succeed"
		statsMutex.Lock()
		successfulClaims++
		statsMutex.Unlock()

		fmt.Printf("✅ [%s] Successfully claimed Nitro gift with code: %s (SIMULATION ONLY)\n",
			username, code)
	} else {
		statsMutex.Lock()
		failedClaims++
		statsMutex.Unlock()

		// Give more specific error based on code length
		if len(code) < 24 {
			fmt.Printf("❌ [%s] Failed to claim code: %s (Code invalid or already claimed)\n",
				username, code)
		} else {
			fmt.Printf("❌ [%s] Failed to claim code: %s (Code expired or already claimed)\n",
				username, code)
		}
	}
}

func printStats() {
	statsMutex.Lock()
	defer statsMutex.Unlock()

	fmt.Printf("\n=== Nitro Sniper Stats ===\n")
	fmt.Printf("Active tokens: %d\n", len(activeSessions))
	fmt.Printf("Total servers monitored: %d\n", totalServers)
	fmt.Printf("Attempted gift links: %d\n", len(giftLinkAttempts))
	fmt.Printf("Successful claims: %d\n", successfulClaims)
	fmt.Printf("Failed claims: %d\n", failedClaims)

	// Print account info
	fmt.Printf("\nConnected accounts:\n")
	for token, username := range usernames {
		count := serverCount[token]
		lastChars := "test"
		if len(token) >= 5 {
			lastChars = token[len(token)-5:]
		}
		fmt.Printf("- %s (token: %s): %d servers\n", username, lastChars, count)
	}

	fmt.Printf("=========================\n\n")
}

func getServerName(s *discordgo.Session, guildID string) string {
	if guildID == "" {
		return "DM"
	}

	guild, err := s.Guild(guildID)
	if err != nil {
		return "Unknown Server"
	}
	return guild.Name
}

func getChannelName(s *discordgo.Session, channelID string) string {
	channel, err := s.Channel(channelID)
	if err != nil {
		return "Unknown Channel"
	}
	return channel.Name
}
