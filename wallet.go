package main

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip39"
)

// Wallet represents a generated Kernelcoin wallet
type Wallet struct {
	Mnemonic       string
	PrivateKeyHex  string
	PrivateKeyWIF  string
	PublicKeyHex   string
	LegacyAddress  string
	SegWitAddress  string
	PublicKeyHash  string
	DerivationPath string
}

// KernelcoinParams defines the network parameters for Kernelcoin mainnet
var KernelcoinParams = chaincfg.Params{
	Name: "kernelcoin",
	Net:  0xf1c8d2fd, // Message start: 0xfd, 0xd2, 0xc8, 0xf1

	// Address encoding prefixes
	PubKeyHashAddrID:        45,  // K
	ScriptHashAddrID:        23,  // A
	PrivateKeyID:            28,  // C
	WitnessPubKeyHashAddrID: 0x06, // bc1 equivalent for kcn
	WitnessScriptHashAddrID: 0x0A, // bc1 equivalent for kcn

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x77, 0x88, 0xad, 0xe4}, // EXT_SECRET_KEY
	HDPublicKeyID:  [4]byte{0x77, 0x88, 0xb2, 0x1e}, // EXT_PUBLIC_KEY

	// Human-readable part for Bech32 encoded addresses
	Bech32HRPSegwit: "kcn",
}

// GenerateNewWallet creates a new Kernelcoin wallet
func GenerateNewWallet() (*Wallet, error) {
	// Generate a new 128-bit entropy (12 words)
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return nil, fmt.Errorf("failed to generate entropy: %w", err)
	}

	// Generate mnemonic from entropy
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	// Generate seed from mnemonic (with empty passphrase)
	seed := bip39.NewSeed(mnemonic, "")

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &KernelcoinParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive key using BIP44 path: m/44'/2'/0'/0/0
	// 2 is Litecoin's coin type (Kernelcoin is a Litecoin fork)
	derivationPath := "m/44'/2'/0'/0/0"

	purpose, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 44)
	if err != nil {
		return nil, fmt.Errorf("failed to derive purpose: %w", err)
	}

	coinType, err := purpose.Derive(hdkeychain.HardenedKeyStart + 2)
	if err != nil {
		return nil, fmt.Errorf("failed to derive coin type: %w", err)
	}

	account, err := coinType.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account: %w", err)
	}

	change, err := account.Derive(0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive change: %w", err)
	}

	addressKey, err := change.Derive(0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the private key
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}

	// Get WIF (Wallet Import Format) for private key
	wif, err := btcutil.NewWIF(privKey, &KernelcoinParams, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create WIF: %w", err)
	}

	// Get the public key
	pubKey := privKey.PubKey()

	// Generate legacy P2PKH address (starts with K)
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	legacyAddr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &KernelcoinParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create legacy address: %w", err)
	}

	// Generate bech32 SegWit address (kcn prefix)
	bech32Addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &KernelcoinParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create bech32 address: %w", err)
	}

	wallet := &Wallet{
		Mnemonic:       mnemonic,
		PrivateKeyHex:  hex.EncodeToString(privKey.Serialize()),
		PrivateKeyWIF:  wif.String(),
		PublicKeyHex:   hex.EncodeToString(pubKey.SerializeCompressed()),
		LegacyAddress:  legacyAddr.EncodeAddress(),
		SegWitAddress:  bech32Addr.EncodeAddress(),
		PublicKeyHash:  hex.EncodeToString(pubKeyHash),
		DerivationPath: derivationPath,
	}

	return wallet, nil
}

// GenerateWalletFromMnemonic creates a wallet from an existing mnemonic
func GenerateWalletFromMnemonic(mnemonic string) (*Wallet, error) {
	// Validate mnemonic
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic phrase")
	}

	// Generate seed from mnemonic (with empty passphrase)
	seed := bip39.NewSeed(mnemonic, "")

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &KernelcoinParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive key using BIP44 path: m/44'/2'/0'/0/0
	derivationPath := "m/44'/2'/0'/0/0"

	purpose, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 44)
	if err != nil {
		return nil, fmt.Errorf("failed to derive purpose: %w", err)
	}

	coinType, err := purpose.Derive(hdkeychain.HardenedKeyStart + 2)
	if err != nil {
		return nil, fmt.Errorf("failed to derive coin type: %w", err)
	}

	account, err := coinType.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account: %w", err)
	}

	change, err := account.Derive(0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive change: %w", err)
	}

	addressKey, err := change.Derive(0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the private key
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}

	// Get WIF (Wallet Import Format) for private key
	wif, err := btcutil.NewWIF(privKey, &KernelcoinParams, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create WIF: %w", err)
	}

	// Get the public key
	pubKey := privKey.PubKey()

	// Generate legacy P2PKH address (starts with K)
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	legacyAddr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &KernelcoinParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create legacy address: %w", err)
	}

	// Generate bech32 SegWit address (kcn prefix)
	bech32Addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &KernelcoinParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create bech32 address: %w", err)
	}

	wallet := &Wallet{
		Mnemonic:       mnemonic,
		PrivateKeyHex:  hex.EncodeToString(privKey.Serialize()),
		PrivateKeyWIF:  wif.String(),
		PublicKeyHex:   hex.EncodeToString(pubKey.SerializeCompressed()),
		LegacyAddress:  legacyAddr.EncodeAddress(),
		SegWitAddress:  bech32Addr.EncodeAddress(),
		PublicKeyHash:  hex.EncodeToString(pubKeyHash),
		DerivationPath: derivationPath,
	}

	return wallet, nil
}
