package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wenlng/go-captcha-assets/resources/imagesv2"
	"github.com/wenlng/go-captcha-assets/resources/tiles"
	"github.com/wenlng/go-captcha/v2/slide"
)

type CharityServer struct {
	charityAddress    string
	charityWIF        string
	rpcClient         *KernelcoinRPCClient
	distributionMu    sync.Mutex
	distributions     []Distribution
	csvFile           string
	captchaMu         sync.Mutex
	captchaChallenges map[string]*captchaChallenge
	captchaTokens     map[string]time.Time
}

type captchaChallenge struct {
	data     []byte
	createAt time.Time
}

type Distribution struct {
	Timestamp       time.Time `json:"timestamp"`
	RecipientAddr   string    `json:"recipient_address"`
	ValidationToken string    `json:"validation_token,omitempty"`
	Mnemonic        string    `json:"mnemonic,omitempty"`
	PrivateKeyWIF   string    `json:"private_key_wif,omitempty"`
	TxHash          string    `json:"tx_hash,omitempty"`
	Amount          float64   `json:"amount"`
}

type BalanceResponse struct {
	Balance            float64 `json:"balance"`
	BalanceConfirmed   float64 `json:"balance_confirmed"`
	BalanceUnconfirmed float64 `json:"balance_unconfirmed"`
	Address            string  `json:"address"`
}

type RequestCoinRequest struct {
	CaptchaToken string `json:"captcha_token"`
}

type RequestCoinResponse struct {
	Success         bool    `json:"success"`
	Message         string  `json:"message"`
	ValidationToken string  `json:"validation_token,omitempty"`
	Mnemonic        string  `json:"mnemonic,omitempty"`
	PrivateKeyWIF   string  `json:"private_key_wif,omitempty"`
	RecipientAddr   string  `json:"recipient_address,omitempty"`
	TxHash          string  `json:"tx_hash,omitempty"`
	CharityBalance  float64 `json:"charity_balance,omitempty"`
	Error           string  `json:"error,omitempty"`
}

type ValidateTokenRequest struct {
	Token        string `json:"token"`
	CaptchaToken string `json:"captcha_token"`
}

type ValidatePasswordRequest struct {
	Password     string `json:"password"`
	CaptchaToken string `json:"captcha_token"`
}

type CaptchaGenerateResponse struct {
	Code        int    `json:"code"`
	CaptchaKey  string `json:"captcha_key,omitempty"`
	ImageBase64 string `json:"image_base64,omitempty"`
	TileBase64  string `json:"tile_base64,omitempty"`
	TileWidth   int    `json:"tile_width,omitempty"`
	TileHeight  int    `json:"tile_height,omitempty"`
	Message     string `json:"message,omitempty"`
}

type CaptchaVerifyRequest struct {
	Point string `json:"point"`
	Key   string `json:"key"`
}

type CaptchaVerifyResponse struct {
	Code         int    `json:"code"`
	Message      string `json:"message,omitempty"`
	CaptchaToken string `json:"captcha_token,omitempty"`
}

type ValidateTokenResponse struct {
	Success           bool     `json:"success"`
	Message           string   `json:"message"`
	ValidationToken   string   `json:"validation_token,omitempty"`
	RecipientAddr     string   `json:"recipient_address,omitempty"`
	DonatedAmount     float64  `json:"donated_amount"`
	TotalAmount       float64  `json:"total_amount,omitempty"`
	DistributionCount int      `json:"distribution_count,omitempty"`
	LastTimestamp     string   `json:"last_timestamp,omitempty"`
	Flags             []string `json:"flags,omitempty"`
	Messages          []string `json:"messages,omitempty"`
	Error             string   `json:"error,omitempty"`
}

type DistributionsResponse struct {
	Distributions []Distribution `json:"distributions"`
	TotalGiven    float64        `json:"total_given"`
	TotalRequests int            `json:"total_requests"`
}

type DonorEntry struct {
	Address      string  `json:"address"`
	TotalDonated float64 `json:"total_donated"`
	TxCount      int     `json:"tx_count"`
}

type LeaderboardResponse struct {
	Donors         []DonorEntry `json:"donors"`
	TotalDonations float64      `json:"total_donations"`
	UniqueDonors   int          `json:"unique_donors"`
}

var (
	slideCaptcha      slide.Captcha
	slideCaptchaOnce  sync.Once
	slideCaptchaError error
)

func initSlideCaptcha() error {
	slideCaptchaOnce.Do(func() {
		builder := slide.NewBuilder(
			slide.WithGenGraphNumber(1),
		)

		imgs, err := imagesv2.GetImages()
		if err != nil {
			slideCaptchaError = err
			return
		}

		graphs, err := tiles.GetTiles()
		if err != nil {
			slideCaptchaError = err
			return
		}

		newGraphs := make([]*slide.GraphImage, 0, len(graphs))
		for _, graph := range graphs {
			newGraphs = append(newGraphs, &slide.GraphImage{
				OverlayImage: graph.OverlayImage,
				MaskImage:    graph.MaskImage,
				ShadowImage:  graph.ShadowImage,
			})
		}

		builder.SetResources(
			slide.WithGraphImages(newGraphs),
			slide.WithBackgrounds(imgs),
		)

		slideCaptcha = builder.MakeDragDrop()
	})

	return slideCaptchaError
}

func NewCharityServer(charityAddress, charityWIF, rpcURL, rpcUser, rpcPass, csvPath string) (*CharityServer, error) {

	rpcClient := NewKernelcoinRPCClient(rpcURL, rpcUser, rpcPass)

	server := &CharityServer{
		charityAddress:    charityAddress,
		charityWIF:        charityWIF,
		rpcClient:         rpcClient,
		csvFile:           csvPath,
		distributions:     []Distribution{},
		captchaChallenges: make(map[string]*captchaChallenge),
		captchaTokens:     make(map[string]time.Time),
	}

	// Import the charity wallet's private key so the RPC wallet can track its UTXOs
	log.Printf("[INIT] Importing charity wallet private key...")
	_, err := rpcClient.ImportPrivateKey(charityWIF)
	if err != nil {
		log.Printf("[INIT] Warning: Failed to import private key: %v", err)
		// Don't fail - key might already be imported
	} else {
		log.Printf("[INIT] Successfully imported charity private key")
	}

	_ = server.loadDistributions()
	if err := initSlideCaptcha(); err != nil {
		return nil, fmt.Errorf("failed to initialize slide captcha: %w", err)
	}

	return server, nil
}

func generateValidationToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate validation token: %w", err)
	}
	return fmt.Sprintf("%x", buf), nil
}

func rewardTiersForAmount(amount float64) ([]string, []string) {
	type tier struct {
		threshold float64
		flag      string
		message   string
	}
        // Add flags here
	tiers := []tier{
		{threshold: 0.9, flag: "kernel{flag1}", message: "thanks for donating 1 coin"},
		{threshold: 50, flag: "kernel{flag2}", message: "thanks for donating 50 coin"},
		{threshold: 1000, flag: "kernel{flag3}", message: "thanks for donating 1000 coin"},
	}

	flags := make([]string, 0, len(tiers))
	messages := make([]string, 0, len(tiers))
	for _, tier := range tiers {
		if amount >= tier.threshold {
			flags = append(flags, tier.flag)
			messages = append(messages, tier.message)
		}
	}

	return flags, messages
}

func flagForPassword(password string) string {
	sum := md5.Sum([]byte(password))
	if fmt.Sprintf("%x", sum) == "511fcd29ea3975f2c294b62e2cf6f629" {
		return "kernel{flag4}"
	}
	return ""
}

func (cs *CharityServer) loadDistributions() error {
	cs.distributionMu.Lock()
	defer cs.distributionMu.Unlock()

	if _, err := os.Stat(cs.csvFile); os.IsNotExist(err) {
		f, _ := os.Create(cs.csvFile)
		w := csv.NewWriter(f)
		w.Write([]string{"timestamp", "recipient_address", "validation_token", "mnemonic", "private_key_wif", "tx_hash", "amount"})
		w.Flush()
		f.Close()
		return nil
	}

	f, err := os.Open(cs.csvFile)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(f)
	_, _ = r.Read()

	cs.distributions = []Distribution{}
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if len(row) < 6 {
			continue
		}
		var amt float64
		tokenIdx := 2
		mnemonicIdx := 3
		wifIdx := 4
		txIdx := 5
		amountIdx := 6
		if len(row) == 6 {
			tokenIdx = -1
			mnemonicIdx = 2
			wifIdx = 3
			txIdx = 4
			amountIdx = 5
		}
		fmt.Sscanf(row[amountIdx], "%f", &amt)

		t, _ := time.Parse(time.RFC3339, row[0])
		token := ""
		if tokenIdx >= 0 && tokenIdx < len(row) {
			token = row[tokenIdx]
		}
		cs.distributions = append(cs.distributions, Distribution{
			Timestamp:       t,
			RecipientAddr:   row[1],
			ValidationToken: token,
			Mnemonic:        row[mnemonicIdx],
			PrivateKeyWIF:   row[wifIdx],
			TxHash:          row[txIdx],
			Amount:          amt,
		})
	}

	return nil
}

func (cs *CharityServer) saveDistribution(dist Distribution) error {
	cs.distributionMu.Lock()
	defer cs.distributionMu.Unlock()

	f, err := os.OpenFile(cs.csvFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	w.Write([]string{
		dist.Timestamp.Format(time.RFC3339),
		dist.RecipientAddr,
		dist.ValidationToken,
		dist.Mnemonic,
		dist.PrivateKeyWIF,
		dist.TxHash,
		fmt.Sprintf("%f", dist.Amount),
	})
	w.Flush()

	cs.distributions = append(cs.distributions, dist)
	return nil
}

// -------------------- API Handlers --------------------

func (cs *CharityServer) HandleBalance(w http.ResponseWriter, r *http.Request) {
	log.Printf("[API] HandleBalance: Request from %s", r.RemoteAddr)
	log.Printf("[API] HandleBalance: Charity address: %s", cs.charityAddress)

	balanceInfo, err := cs.rpcClient.GetBalanceInfo(cs.charityAddress)
	if err != nil {
		log.Printf("[API] HandleBalance: ERROR getting balance: %v", err)
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	log.Printf("[API] HandleBalance: SUCCESS - Total: %.8f, Confirmed: %.8f, Unconfirmed: %.8f",
		balanceInfo.Total, balanceInfo.Confirmed, balanceInfo.Unconfirmed)
	response := BalanceResponse{
		Balance:            balanceInfo.Total,
		BalanceConfirmed:   balanceInfo.Confirmed,
		BalanceUnconfirmed: balanceInfo.Unconfirmed,
		Address:            cs.charityAddress,
	}
	log.Printf("[API] HandleBalance: Sending response: %+v", response)
	json.NewEncoder(w).Encode(response)
}

func (cs *CharityServer) purgeExpiredCaptchaState() {
	now := time.Now()
	for key, challenge := range cs.captchaChallenges {
		if now.Sub(challenge.createAt) > 10*time.Minute {
			delete(cs.captchaChallenges, key)
		}
	}
	for token, expiresAt := range cs.captchaTokens {
		if now.After(expiresAt) {
			delete(cs.captchaTokens, token)
		}
	}
}

func (cs *CharityServer) issueCaptchaToken() string {
	token, err := generateValidationToken()
	if err != nil {
		token = fmt.Sprintf("captcha-%d", time.Now().UnixNano())
	}
	cs.captchaTokens[token] = time.Now().Add(10 * time.Minute)
	return token
}

func (cs *CharityServer) consumeCaptchaToken(token string) bool {
	cs.captchaMu.Lock()
	defer cs.captchaMu.Unlock()

	cs.purgeExpiredCaptchaState()

	expiresAt, ok := cs.captchaTokens[token]
	if !ok || time.Now().After(expiresAt) {
		return false
	}

	delete(cs.captchaTokens, token)
	return true
}

func (cs *CharityServer) HandleCaptchaGenerate(w http.ResponseWriter, r *http.Request) {
	log.Printf("[API] HandleCaptchaGenerate: Request from %s", r.RemoteAddr)

	if r.Method != "GET" {
		w.WriteHeader(405)
		json.NewEncoder(w).Encode(map[string]string{"error": "GET only"})
		return
	}

	cs.captchaMu.Lock()
	defer cs.captchaMu.Unlock()
	cs.purgeExpiredCaptchaState()

	captData, err := slideCaptcha.Generate()
	if err != nil {
		log.Printf("[API] HandleCaptchaGenerate: ERROR generating captcha: %v", err)
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(CaptchaGenerateResponse{
			Code:    1,
			Message: "Failed to generate captcha",
		})
		return
	}

	blockData := captData.GetData()
	if blockData == nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(CaptchaGenerateResponse{
			Code:    1,
			Message: "Failed to get captcha data",
		})
		return
	}

	masterImageBase64, err := captData.GetMasterImage().ToBase64Data()
	if err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(CaptchaGenerateResponse{
			Code:    1,
			Message: "Failed to encode master image",
		})
		return
	}

	tileImageBase64, err := captData.GetTileImage().ToBase64Data()
	if err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(CaptchaGenerateResponse{
			Code:    1,
			Message: "Failed to encode tile image",
		})
		return
	}

	blockBytes, err := json.Marshal(blockData)
	if err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(CaptchaGenerateResponse{
			Code:    1,
			Message: "Failed to encode captcha block",
		})
		return
	}

	key := strconv.FormatInt(time.Now().UnixNano(), 10)
	cs.captchaChallenges[key] = &captchaChallenge{
		data:     blockBytes,
		createAt: time.Now(),
	}

	json.NewEncoder(w).Encode(CaptchaGenerateResponse{
		Code:        0,
		CaptchaKey:  key,
		ImageBase64: masterImageBase64,
		TileBase64:  tileImageBase64,
		TileWidth:   blockData.Width,
		TileHeight:  blockData.Height,
	})
}

func (cs *CharityServer) HandleCaptchaVerify(w http.ResponseWriter, r *http.Request) {
	log.Printf("[API] HandleCaptchaVerify: Request from %s", r.RemoteAddr)

	if r.Method != "POST" {
		w.WriteHeader(405)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST only"})
		return
	}

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(CaptchaVerifyResponse{
			Code:    1,
			Message: "Failed to parse form",
		})
		return
	}

	point := r.Form.Get("point")
	key := r.Form.Get("key")
	if point == "" || key == "" {
		json.NewEncoder(w).Encode(CaptchaVerifyResponse{
			Code:    1,
			Message: "point or key param is empty",
		})
		return
	}

	cs.captchaMu.Lock()
	defer cs.captchaMu.Unlock()
	cs.purgeExpiredCaptchaState()

	challenge, exists := cs.captchaChallenges[key]
	if !exists {
		json.NewEncoder(w).Encode(CaptchaVerifyResponse{
			Code:    1,
			Message: "invalid key",
		})
		return
	}

	src := strings.Split(point, ",")
	if len(src) != 2 {
		json.NewEncoder(w).Encode(CaptchaVerifyResponse{
			Code:    1,
			Message: "invalid point format",
		})
		return
	}

	var blockData *slide.Block
	if err := json.Unmarshal(challenge.data, &blockData); err != nil {
		json.NewEncoder(w).Encode(CaptchaVerifyResponse{
			Code:    1,
			Message: "invalid cache data",
		})
		return
	}

	sx, _ := strconv.Atoi(src[0])
	sy, _ := strconv.Atoi(src[1])
	isValid := slide.Validate(sx, sy, blockData.X, blockData.Y, 5)

	log.Printf("[API] Validation attempt - Received: (%d, %d), Expected: (%d, %d), Valid: %v", sx, sy, blockData.X, blockData.Y, isValid)

	if !isValid {
		json.NewEncoder(w).Encode(CaptchaVerifyResponse{
			Code:    1,
			Message: "wrong position",
		})
		return
	}

	delete(cs.captchaChallenges, key)
	captchaToken := cs.issueCaptchaToken()

	json.NewEncoder(w).Encode(CaptchaVerifyResponse{
		Code:         0,
		CaptchaToken: captchaToken,
	})
}

func (cs *CharityServer) HandleRequestCoin(w http.ResponseWriter, r *http.Request) {
	log.Printf("[API] HandleRequestCoin: Request from %s", r.RemoteAddr)

	if r.Method != "POST" {
		log.Printf("[API] HandleRequestCoin: ERROR - Invalid method: %s", r.Method)
		w.WriteHeader(405)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST only"})
		return
	}

	// Parse request body
	var req RequestCoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[API] HandleRequestCoin: ERROR parsing request: %v", err)
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(RequestCoinResponse{
			Success: false,
			Error:   "Invalid request format",
		})
		return
	}

	if !cs.consumeCaptchaToken(req.CaptchaToken) {
		log.Printf("[API] HandleRequestCoin: ERROR - Invalid captcha token")
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(RequestCoinResponse{
			Success: false,
			Error:   "Invalid captcha. Please try again.",
		})
		return
	}

	log.Printf("[API] HandleRequestCoin: Captcha verified successfully")

	log.Printf("[API] HandleRequestCoin: Generating new wallet")
	wallet, err := GenerateNewWallet()
	if err != nil {
		log.Printf("[API] HandleRequestCoin: ERROR generating wallet: %v", err)
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	log.Printf("[API] HandleRequestCoin: Wallet generated: %s", wallet.LegacyAddress)

	log.Printf("[API] HandleRequestCoin: Checking charity balance")
	bal, err := cs.rpcClient.GetBalance(cs.charityAddress)
	if err != nil {
		log.Printf("[API] HandleRequestCoin: ERROR checking balance: %v", err)
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Insufficient charity balance"})
		return
	}
	log.Printf("[API] HandleRequestCoin: Charity balance: %.8f", bal)

	if bal < 1 {
		log.Printf("[API] HandleRequestCoin: ERROR - Insufficient balance (%.8f < 1.0)", bal)
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Insufficient charity balance"})
		return
	}

	log.Printf("[API] HandleRequestCoin: Sending transaction")
	txid, err := cs.rpcClient.SendTransaction(cs.charityWIF, wallet.LegacyAddress, 1.0)
	if err != nil {
		log.Printf("[API] HandleRequestCoin: ERROR sending transaction: %v", err)
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	log.Printf("[API] HandleRequestCoin: Transaction sent: %s", txid)

	validationToken, err := generateValidationToken()
	if err != nil {
		log.Printf("[API] HandleRequestCoin: ERROR generating validation token: %v", err)
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	dist := Distribution{
		Timestamp:       time.Now(),
		RecipientAddr:   wallet.LegacyAddress,
		ValidationToken: validationToken,
		Mnemonic:        wallet.Mnemonic,
		PrivateKeyWIF:   wallet.PrivateKeyWIF,
		TxHash:          txid,
		Amount:          1.0,
	}
	_ = cs.saveDistribution(dist)

	newBal, _ := cs.rpcClient.GetBalance(cs.charityAddress)
	log.Printf("[API] HandleRequestCoin: New balance: %.8f", newBal)

	json.NewEncoder(w).Encode(RequestCoinResponse{
		Success:         true,
		Message:         "Sent 1 KCN",
		ValidationToken: validationToken,
		Mnemonic:        wallet.Mnemonic,
		PrivateKeyWIF:   wallet.PrivateKeyWIF,
		RecipientAddr:   wallet.LegacyAddress,
		TxHash:          txid,
		CharityBalance:  newBal,
	})
	log.Printf("[API] HandleRequestCoin: SUCCESS")
}

func (cs *CharityServer) HandleValidateToken(w http.ResponseWriter, r *http.Request) {
	log.Printf("[API] HandleValidateToken: Request from %s", r.RemoteAddr)

	if r.Method != "POST" {
		w.WriteHeader(405)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST only"})
		return
	}

	var req ValidateTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(ValidateTokenResponse{
			Success: false,
			Error:   "Invalid request format",
		})
		return
	}

	if !cs.consumeCaptchaToken(req.CaptchaToken) {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(ValidateTokenResponse{
			Success: false,
			Error:   "Invalid captcha. Please try again.",
		})
		return
	}

	token := strings.TrimSpace(req.Token)
	if token == "" {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(ValidateTokenResponse{
			Success: false,
			Error:   "Token is required",
		})
		return
	}

	cs.distributionMu.Lock()
	list := append([]Distribution{}, cs.distributions...)
	cs.distributionMu.Unlock()

	var (
		matchCount    int
		latestTime    time.Time
		recipientAddr string
	)

	for _, dist := range list {
		if dist.ValidationToken != token {
			continue
		}
		matchCount++
		if recipientAddr == "" {
			recipientAddr = dist.RecipientAddr
		}
		if dist.Timestamp.After(latestTime) {
			latestTime = dist.Timestamp
		}
	}

	if matchCount == 0 {
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(ValidateTokenResponse{
			Success: false,
			Error:   "Validation token not found",
		})
		return
	}

	txs, err := cs.rpcClient.ListTransactions(cs.charityAddress, 10000)
	if err != nil {
		log.Printf("[API] HandleValidateToken: ERROR getting transactions: %v", err)
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(ValidateTokenResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	donorMap, totalDonations := aggregateDonationsFromTransactions(cs, txs)
	donatedAmount := 0.0
	if recipientAddr != "" {
		if donor, exists := donorMap[recipientAddr]; exists {
			donatedAmount = donor.TotalDonated
		}
	}

	flags, messages := rewardTiersForAmount(donatedAmount)

	json.NewEncoder(w).Encode(ValidateTokenResponse{
		Success:           true,
		Message:           "Token validated successfully",
		ValidationToken:   token,
		RecipientAddr:     recipientAddr,
		DonatedAmount:     donatedAmount,
		TotalAmount:       totalDonations,
		DistributionCount: matchCount,
		LastTimestamp:     latestTime.Format(time.RFC3339),
		Flags:             flags,
		Messages:          messages,
	})
}

func (cs *CharityServer) HandleValidatePassword(w http.ResponseWriter, r *http.Request) {
	log.Printf("[API] HandleValidatePassword: Request from %s", r.RemoteAddr)

	if r.Method != "POST" {
		w.WriteHeader(405)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST only"})
		return
	}

	var req ValidatePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(ValidateTokenResponse{
			Success: false,
			Error:   "Invalid request format",
		})
		return
	}

	if !cs.consumeCaptchaToken(req.CaptchaToken) {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(ValidateTokenResponse{
			Success: false,
			Error:   "Invalid captcha. Please try again.",
		})
		return
	}

	secretFlag := flagForPassword(strings.TrimSpace(req.Password))
	if secretFlag == "" {
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(ValidateTokenResponse{
			Success: false,
			Error:   "Password did not match",
		})
		return
	}

	json.NewEncoder(w).Encode(ValidateTokenResponse{
		Success: true,
		Message: "Password validated successfully",
		Flags:   []string{secretFlag},
	})
}

func (cs *CharityServer) HandleDistributions(w http.ResponseWriter, r *http.Request) {
	cs.distributionMu.Lock()
	list := append([]Distribution{}, cs.distributions...)
	cs.distributionMu.Unlock()

	total := 0.0
	for _, d := range list {
		total += d.Amount
	}

	json.NewEncoder(w).Encode(DistributionsResponse{
		Distributions: list,
		TotalGiven:    total,
		TotalRequests: len(list),
	})
}

func aggregateDonationsFromTransactions(cs *CharityServer, txs []interface{}) (map[string]*DonorEntry, float64) {
	donorMap := make(map[string]*DonorEntry)
	totalDonations := 0.0

	for _, tx := range txs {
		txMap, ok := tx.(map[string]interface{})
		if !ok {
			continue
		}

		category, _ := txMap["category"].(string)
		address, _ := txMap["address"].(string)
		amount, _ := txMap["amount"].(float64)
		txid, _ := txMap["txid"].(string)

		if (category == "receive" || category == "generate" || category == "immature") && address == cs.charityAddress && amount > 0 {
			senderAddr := "Unknown Donor"

			if category == "generate" || category == "immature" {
				senderAddr = "Mining Rewards (Coinbase)"
			} else if txid != "" {
				rawTx, err := cs.rpcClient.GetRawTransaction(txid, true)
				if err == nil {
					if rawTxMap, ok := rawTx.(map[string]interface{}); ok {
						if vin, ok := rawTxMap["vin"].([]interface{}); ok && len(vin) > 0 {
							if firstIn, ok := vin[0].(map[string]interface{}); ok {
								if prevTxid, ok := firstIn["txid"].(string); ok && prevTxid != "" {
									if vout, ok := firstIn["vout"].(float64); ok {
										prevTx, err := cs.rpcClient.GetRawTransaction(prevTxid, true)
										if err == nil {
											if prevTxMap, ok := prevTx.(map[string]interface{}); ok {
												if voutArray, ok := prevTxMap["vout"].([]interface{}); ok {
													voutIdx := int(vout)
													if voutIdx < len(voutArray) {
														if output, ok := voutArray[voutIdx].(map[string]interface{}); ok {
															if scriptPubKey, ok := output["scriptPubKey"].(map[string]interface{}); ok {
																if addresses, ok := scriptPubKey["addresses"].([]interface{}); ok && len(addresses) > 0 {
																	if addr, ok := addresses[0].(string); ok {
																		senderAddr = addr
																		log.Printf("[API] Donation trace: found sender address %s for txid %s", senderAddr, txid)
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}

			if donor, exists := donorMap[senderAddr]; exists {
				donor.TotalDonated += amount
				donor.TxCount++
			} else {
				donorMap[senderAddr] = &DonorEntry{
					Address:      senderAddr,
					TotalDonated: amount,
					TxCount:      1,
				}
			}
			totalDonations += amount
		}
	}

	return donorMap, totalDonations
}

func (cs *CharityServer) HandleLeaderboard(w http.ResponseWriter, r *http.Request) {
	log.Printf("[API] HandleLeaderboard: Request from %s", r.RemoteAddr)

	txs, err := cs.rpcClient.ListTransactions(cs.charityAddress, 10000)
	if err != nil {
		log.Printf("[API] HandleLeaderboard: ERROR getting transactions: %v", err)
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	log.Printf("[API] HandleLeaderboard: Processing %d transactions", len(txs))

	donorMap, totalDonations := aggregateDonationsFromTransactions(cs, txs)

	// Convert map to slice and sort by total donated
	donors := make([]DonorEntry, 0, len(donorMap))
	for _, donor := range donorMap {
		donors = append(donors, *donor)
	}

	// Sort by total donated (descending)
	for i := 0; i < len(donors); i++ {
		for j := i + 1; j < len(donors); j++ {
			if donors[j].TotalDonated > donors[i].TotalDonated {
				donors[i], donors[j] = donors[j], donors[i]
			}
		}
	}

	log.Printf("[API] HandleLeaderboard: Found %d unique donors, total donations: %.8f", len(donors), totalDonations)

	json.NewEncoder(w).Encode(LeaderboardResponse{
		Donors:         donors,
		TotalDonations: totalDonations,
		UniqueDonors:   len(donors),
	})
}

func (cs *CharityServer) HandleStatic(w http.ResponseWriter, r *http.Request) {
	http.FileServer(http.Dir("./static")).ServeHTTP(w, r)
}

// -------------------- main --------------------

func main() {
	charityAddress := os.Getenv("CHARITY_ADDRESS")
	charityWIF := os.Getenv("CHARITY_WIF")

	rpcURL := os.Getenv("KERNELCOIN_RPC_URL")
	rpcUser := os.Getenv("KERNELCOIN_RPC_USER")
	rpcPass := os.Getenv("KERNELCOIN_RPC_PASS")

	csvPath := os.Getenv("DISTRIBUTIONS_CSV")
	listen := os.Getenv("LISTEN_ADDR")

	if charityAddress == "" {
		charityAddress = "KCharityWalletAddressHere"
	}
	if charityWIF == "" {
		charityWIF = "CCharityWIFKeyHere"
	}
	if rpcURL == "" {
		rpcURL = "http://127.0.0.1:9332"
	}
	if csvPath == "" {
		csvPath = "distributions.csv"
	}
	if listen == "" {
		listen = "0.0.0.0:8080"
	}

	log.Printf("[INIT] Configuration:")
	log.Printf("[INIT]   Charity Address: %s", charityAddress)
	log.Printf("[INIT]   RPC URL: %s", rpcURL)
	log.Printf("[INIT]   RPC User: %s", rpcUser)
	log.Printf("[INIT]   CSV Path: %s", csvPath)
	log.Printf("[INIT]   Listen Address: %s", listen)

	os.MkdirAll(filepath.Dir(csvPath), 0755)

	server, err := NewCharityServer(charityAddress, charityWIF, rpcURL, rpcUser, rpcPass, csvPath)
	if err != nil {
		log.Fatalf("init failed: %v", err)
	}

	log.Println("Starting server on", listen)
	log.Fatal(http.ListenAndServe(listen, serverRoutes(server)))
}

// Mux setup
func serverRoutes(cs *CharityServer) *http.ServeMux {
	m := http.NewServeMux()

	m.HandleFunc("/api/balance", cs.HandleBalance)
	m.HandleFunc("/captcha/generate", cs.HandleCaptchaGenerate)
	m.HandleFunc("/captcha/verify", cs.HandleCaptchaVerify)
	m.HandleFunc("/api/request-coin", cs.HandleRequestCoin)
	m.HandleFunc("/api/validate-token", cs.HandleValidateToken)
	m.HandleFunc("/api/validate-password", cs.HandleValidatePassword)
	m.HandleFunc("/api/distributions", cs.HandleDistributions)
	m.HandleFunc("/api/leaderboard", cs.HandleLeaderboard)

	m.HandleFunc("/", cs.HandleStatic)

	return m
}
