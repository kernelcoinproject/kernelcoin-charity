package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type CharityServer struct {
	charityAddress string
	charityWIF     string
	rpcClient      *KernelcoinRPCClient
	distributionMu sync.Mutex
	distributions  []Distribution
	csvFile        string
}

type Distribution struct {
	Timestamp     time.Time `json:"timestamp"`
	RecipientAddr string    `json:"recipient_address"`
	Mnemonic      string    `json:"mnemonic,omitempty"`
	PrivateKeyWIF string    `json:"private_key_wif,omitempty"`
	TxHash        string    `json:"tx_hash,omitempty"`
	Amount        float64   `json:"amount"`
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
	Success        bool    `json:"success"`
	Message        string  `json:"message"`
	Mnemonic       string  `json:"mnemonic,omitempty"`
	PrivateKeyWIF  string  `json:"private_key_wif,omitempty"`
	RecipientAddr  string  `json:"recipient_address,omitempty"`
	TxHash         string  `json:"tx_hash,omitempty"`
	CharityBalance float64 `json:"charity_balance,omitempty"`
	Error          string  `json:"error,omitempty"`
}

type RecaptchaResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes,omitempty"`
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

func NewCharityServer(charityAddress, charityWIF, rpcURL, rpcUser, rpcPass, csvPath string) (*CharityServer, error) {

	rpcClient := NewKernelcoinRPCClient(rpcURL, rpcUser, rpcPass)

	server := &CharityServer{
		charityAddress: charityAddress,
		charityWIF:     charityWIF,
		rpcClient:      rpcClient,
		csvFile:        csvPath,
		distributions:  []Distribution{},
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

	return server, nil
}

func (cs *CharityServer) loadDistributions() error {
	cs.distributionMu.Lock()
	defer cs.distributionMu.Unlock()

	if _, err := os.Stat(cs.csvFile); os.IsNotExist(err) {
		f, _ := os.Create(cs.csvFile)
		w := csv.NewWriter(f)
		w.Write([]string{"timestamp", "recipient_address", "mnemonic", "private_key_wif", "tx_hash", "amount"})
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
		var amt float64
		fmt.Sscanf(row[5], "%f", &amt)

		t, _ := time.Parse(time.RFC3339, row[0])
		cs.distributions = append(cs.distributions, Distribution{
			Timestamp:     t,
			RecipientAddr: row[1],
			Mnemonic:      row[2],
			PrivateKeyWIF: row[3],
			TxHash:        row[4],
			Amount:        amt,
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

func verifyCaptcha(token string, secretKey string) (bool, error) {
	if secretKey == "" {
		// If no secret key is configured, skip verification (for testing)
		log.Printf("[CAPTCHA] No secret key configured, skipping verification")
		return true, nil
	}

	reqBody := map[string]string{
		"secret":   secretKey,
		"response": token,
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return false, err
	}

	resp, err := http.Post(
		"https://www.google.com/recaptcha/api/siteverify",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result RecaptchaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	log.Printf("[CAPTCHA] Verification result: success=%v, errors=%v", result.Success, result.ErrorCodes)
	return result.Success, nil
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

	// Verify captcha
	recaptchaSecret := os.Getenv("RECAPTCHA_SECRET_KEY")
	captchaValid, err := verifyCaptcha(req.CaptchaToken, recaptchaSecret)
	if err != nil {
		log.Printf("[API] HandleRequestCoin: ERROR verifying captcha: %v", err)
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(RequestCoinResponse{
			Success: false,
			Error:   "Captcha verification failed",
		})
		return
	}

	if !captchaValid {
		log.Printf("[API] HandleRequestCoin: ERROR - Invalid captcha")
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

	dist := Distribution{
		Timestamp:     time.Now(),
		RecipientAddr: wallet.LegacyAddress,
		Mnemonic:      wallet.Mnemonic,
		PrivateKeyWIF: wallet.PrivateKeyWIF,
		TxHash:        txid,
		Amount:        1.0,
	}
	_ = cs.saveDistribution(dist)

	newBal, _ := cs.rpcClient.GetBalance(cs.charityAddress)
	log.Printf("[API] HandleRequestCoin: New balance: %.8f", newBal)

	json.NewEncoder(w).Encode(RequestCoinResponse{
		Success:        true,
		Message:        "Sent 1 KCN",
		Mnemonic:       wallet.Mnemonic,
		PrivateKeyWIF:  wallet.PrivateKeyWIF,
		RecipientAddr:  wallet.LegacyAddress,
		TxHash:         txid,
		CharityBalance: newBal,
	})
	log.Printf("[API] HandleRequestCoin: SUCCESS")
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

func (cs *CharityServer) HandleLeaderboard(w http.ResponseWriter, r *http.Request) {
	log.Printf("[API] HandleLeaderboard: Request from %s", r.RemoteAddr)

	// Get all transactions
	txs, err := cs.rpcClient.ListTransactions(cs.charityAddress, 10000)
	if err != nil {
		log.Printf("[API] HandleLeaderboard: ERROR getting transactions: %v", err)
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	log.Printf("[API] HandleLeaderboard: Processing %d transactions", len(txs))

	// Aggregate donations by sender address
	donorMap := make(map[string]*DonorEntry)
	totalDonations := 0.0

	for _, tx := range txs {
		txMap, ok := tx.(map[string]interface{})
		if !ok {
			continue
		}

		// Count "receive" and "generate" (mining) transactions to the charity address
		category, _ := txMap["category"].(string)
		address, _ := txMap["address"].(string)
		amount, _ := txMap["amount"].(float64)
		txid, _ := txMap["txid"].(string)

		// Filter for incoming transactions to charity address (receive, generate, immature)
		if (category == "receive" || category == "generate" || category == "immature") && address == cs.charityAddress && amount > 0 {
			// Get the sender address from the raw transaction
			senderAddr := "Unknown Donor"

			// For mined/generated blocks, there's no sender - it's mining rewards
			if category == "generate" || category == "immature" {
				senderAddr = "Mining Rewards (Coinbase)"
			} else if txid != "" {
				// For regular transactions, trace back to find the sender
				rawTx, err := cs.rpcClient.GetRawTransaction(txid, true)
				if err == nil {
					if rawTxMap, ok := rawTx.(map[string]interface{}); ok {
						// Get the vin (inputs) array
						if vin, ok := rawTxMap["vin"].([]interface{}); ok && len(vin) > 0 {
							// Get the first input (sender)
							if firstIn, ok := vin[0].(map[string]interface{}); ok {
								// Try to get the address from the input
								if prevTxid, ok := firstIn["txid"].(string); ok && prevTxid != "" {
									// Get the previous transaction to find the sender address
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
																		log.Printf("[API] HandleLeaderboard: Found sender address: %s for txid: %s", senderAddr, txid)
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
	m.HandleFunc("/api/request-coin", cs.HandleRequestCoin)
	m.HandleFunc("/api/distributions", cs.HandleDistributions)
	m.HandleFunc("/api/leaderboard", cs.HandleLeaderboard)

	m.HandleFunc("/", cs.HandleStatic)

	return m
}
