package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

// KernelcoinRPCClient communicates with kernelcoind
type KernelcoinRPCClient struct {
	url      string
	user     string
	password string
}

// JSONRPCRequest represents a JSON-RPC 2.0 request
type JSONRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

// JSONRPCResponse represents JSON-RPC 2.0 response
type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result"`
	Error   interface{} `json:"error"`
	ID      int         `json:"id"`
}

// NewKernelcoinRPCClient creates an authenticated RPC client
func NewKernelcoinRPCClient(url, user, password string) *KernelcoinRPCClient {
	return &KernelcoinRPCClient{
		url:      url,
		user:     user,
		password: password,
	}
}

// call makes an authenticated RPC call
func (c *KernelcoinRPCClient) call(method string, params []interface{}) (interface{}, error) {
	log.Printf("[RPC] Calling method: %s with params: %v", method, params)
	log.Printf("[RPC] URL: %s, User: %s", c.url, c.user)

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		log.Printf("[RPC] ERROR: Failed to marshal request: %v", err)
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	log.Printf("[RPC] Request body: %s", string(requestBody))

	req, err := http.NewRequest("POST", c.url, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Printf("[RPC] ERROR: Failed to create HTTP request: %v", err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[RPC] ERROR: RPC POST failed: %v", err)
		return nil, fmt.Errorf("RPC POST failed: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("[RPC] Response status: %d %s", resp.StatusCode, resp.Status)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[RPC] ERROR: Failed to read response body: %v", err)
		return nil, fmt.Errorf("RPC read error: %w", err)
	}

	// For listtransactions and listunspent, avoid logging the massive response body
	if method == "listtransactions" || method == "listunspent" {
		log.Printf("[RPC] Response body: <truncated for %s, size: %d bytes>", method, len(body))
	} else {
		log.Printf("[RPC] Response body: %s", string(body))
	}

	var response JSONRPCResponse
	if err := json.Unmarshal(body, &response); err != nil {
		log.Printf("[RPC] ERROR: Failed to unmarshal response: %v", err)
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}

	if response.Error != nil {
		log.Printf("[RPC] ERROR: RPC returned error: %v", response.Error)
		return nil, fmt.Errorf("RPC error: %v", response.Error)
	}

	// For listtransactions and listunspent, just log the count, not the full result
	if method == "listtransactions" || method == "listunspent" {
		if array, ok := response.Result.([]interface{}); ok {
			log.Printf("[RPC] SUCCESS: Retrieved %d items", len(array))
		} else {
			log.Printf("[RPC] SUCCESS: Result type: %T", response.Result)
		}
	} else {
		log.Printf("[RPC] SUCCESS: Result type: %T, value: %v", response.Result, response.Result)
	}
	return response.Result, nil
}

// -----------------------------------------------------------
// API Helpers
// -----------------------------------------------------------

// BalanceInfo holds confirmed and unconfirmed balance information
type BalanceInfo struct {
	Confirmed   float64
	Unconfirmed float64
	Total       float64
}

func (c *KernelcoinRPCClient) GetBalance(address string) (float64, error) {
	balanceInfo, err := c.GetBalanceInfo(address)
	if err != nil {
		return 0, err
	}
	return balanceInfo.Total, nil
}

func (c *KernelcoinRPCClient) GetBalanceInfo(address string) (*BalanceInfo, error) {
	log.Printf("[RPC] GetBalanceInfo: Fetching balance for wallet (address: %s)", address)

	// Use getbalances - much faster than listunspent
	result, err := c.call("getbalances", []interface{}{})
	if err != nil {
		log.Printf("[RPC] GetBalanceInfo ERROR: %v", err)
		return nil, err
	}

	// Parse getbalances response
	balances, ok := result.(map[string]interface{})
	if !ok {
		log.Printf("[RPC] GetBalanceInfo ERROR: unexpected result type: %T", result)
		return nil, fmt.Errorf("unexpected getbalances response type: %T", result)
	}

	mine, ok := balances["mine"].(map[string]interface{})
	if !ok {
		log.Printf("[RPC] GetBalanceInfo ERROR: missing 'mine' field")
		return nil, fmt.Errorf("getbalances missing 'mine' field")
	}

	// Extract balances
	trusted, _ := mine["trusted"].(float64)                    // Confirmed balance (≥1 conf)
	untrustedPending, _ := mine["untrusted_pending"].(float64) // Unconfirmed (0 conf)
	immature, _ := mine["immature"].(float64)                  // Immature mining rewards

	confirmedBalance := trusted
	unconfirmedBalance := untrustedPending
	totalBalance := confirmedBalance + unconfirmedBalance + immature

	log.Printf("[RPC] GetBalanceInfo: Total %.8f (Confirmed: %.8f, Unconfirmed: %.8f, Immature: %.8f)",
		totalBalance, confirmedBalance, unconfirmedBalance, immature)

	return &BalanceInfo{
		Confirmed:   confirmedBalance,
		Unconfirmed: unconfirmedBalance,
		Total:       totalBalance,
	}, nil
}

func (c *KernelcoinRPCClient) ImportPrivateKey(wif string) (interface{}, error) {
	log.Printf("[RPC] ImportPrivateKey: importing private key")
	result, err := c.call("importprivkey", []interface{}{wif})
	if err != nil {
		log.Printf("[RPC] ImportPrivateKey ERROR: %v", err)
		return nil, err
	}
	log.Printf("[RPC] ImportPrivateKey SUCCESS")
	return result, nil
}

func (c *KernelcoinRPCClient) SendTransaction(fromWIF, toAddress string, amount float64) (string, error) {
	log.Printf("[RPC] SendTransaction: importing private key and sending %.8f to %s", amount, toAddress)
	_, _ = c.call("importprivkey", []interface{}{fromWIF})

	txID, err := c.call("sendtoaddress", []interface{}{toAddress, amount})
	if err != nil {
		log.Printf("[RPC] SendTransaction ERROR: %v", err)
		return "", err
	}

	if s, ok := txID.(string); ok {
		log.Printf("[RPC] SendTransaction SUCCESS: txid=%s", s)
		return s, nil
	}
	log.Printf("[RPC] SendTransaction ERROR: unexpected txid type: %T, value: %v", txID, txID)
	return "", fmt.Errorf("unexpected txid type: %T", txID)
}

func (c *KernelcoinRPCClient) ValidateAddress(addr string) (bool, error) {
	result, err := c.call("validateaddress", []interface{}{addr})
	if err != nil {
		return false, err
	}

	m, ok := result.(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("unexpected validateaddress type: %T", result)
	}

	if v, ok := m["isvalid"].(bool); ok {
		return v, nil
	}

	return false, fmt.Errorf("validateaddress missing isvalid")
}

func (c *KernelcoinRPCClient) ListTransactions(address string, count int) ([]interface{}, error) {
	log.Printf("[RPC] ListTransactions: Fetching up to %d transactions...", count)
	result, err := c.call("listtransactions", []interface{}{"*", count, 0, true})
	if err != nil {
		log.Printf("[RPC] ListTransactions ERROR: %v", err)
		return nil, err
	}

	txs, ok := result.([]interface{})
	if !ok {
		log.Printf("[RPC] ListTransactions ERROR: unexpected result type: %T", result)
		return nil, fmt.Errorf("unexpected listtransactions response type: %T", result)
	}

	log.Printf("[RPC] ListTransactions: Retrieved %d transactions", len(txs))
	return txs, nil
}

func (c *KernelcoinRPCClient) GetRawTransaction(txid string, verbose bool) (interface{}, error) {
	log.Printf("[RPC] GetRawTransaction called for txid: %s", txid)
	verboseInt := 0
	if verbose {
		verboseInt = 1
	}
	result, err := c.call("getrawtransaction", []interface{}{txid, verboseInt})
	if err != nil {
		log.Printf("[RPC] GetRawTransaction ERROR: %v", err)
		return nil, err
	}
	log.Printf("[RPC] GetRawTransaction SUCCESS")
	return result, nil
}
