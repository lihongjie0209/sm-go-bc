package agreement

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/lihongjie0209/sm-go-bc/crypto"
	"github.com/lihongjie0209/sm-go-bc/crypto/sm2"
)

func TestSM2KeyExchange(t *testing.T) {
	// Get SM2 curve
	curve := sm2.GetCurve()

	// Test key exchange without confirmation
	t.Run("BasicKeyExchange", func(t *testing.T) {
		// Party A (initiator)
		dA, _ := new(big.Int).SetString("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE", 16)
		rA, _ := new(big.Int).SetString("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563", 16)

		privParamA, err := NewSM2KeyExchangePrivateParameters(true, dA, rA, curve)
		if err != nil {
			t.Fatalf("Failed to create private parameters for A: %v", err)
		}

		// Party B (responder)
		dB, _ := new(big.Int).SetString("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53", 16)
		rB, _ := new(big.Int).SetString("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80", 16)

		privParamB, err := NewSM2KeyExchangePrivateParameters(false, dB, rB, curve)
		if err != nil {
			t.Fatalf("Failed to create private parameters for B: %v", err)
		}

		// Create public parameters
		pubParamA, err := NewSM2KeyExchangePublicParameters(
			privParamA.GetStaticPublicPoint(),
			privParamA.GetEphemeralPublicPoint())
		if err != nil {
			t.Fatalf("Failed to create public parameters for A: %v", err)
		}

		pubParamB, err := NewSM2KeyExchangePublicParameters(
			privParamB.GetStaticPublicPoint(),
			privParamB.GetEphemeralPublicPoint())
		if err != nil {
			t.Fatalf("Failed to create public parameters for B: %v", err)
		}

		// Initialize key exchange for both parties
		keA := NewSM2KeyExchange(nil)
		if err := keA.Init(privParamA); err != nil {
			t.Fatalf("Failed to init key exchange for A: %v", err)
		}

		keB := NewSM2KeyExchange(nil)
		if err := keB.Init(privParamB); err != nil {
			t.Fatalf("Failed to init key exchange for B: %v", err)
		}

		// Calculate shared keys
		keyA, err := keA.CalculateKey(128, pubParamB)
		if err != nil {
			t.Fatalf("Failed to calculate key for A: %v", err)
		}

		keyB, err := keB.CalculateKey(128, pubParamA)
		if err != nil {
			t.Fatalf("Failed to calculate key for B: %v", err)
		}

		// Keys should match
		if hex.EncodeToString(keyA) != hex.EncodeToString(keyB) {
			t.Errorf("Keys do not match:\nA: %s\nB: %s",
				hex.EncodeToString(keyA),
				hex.EncodeToString(keyB))
		}

		t.Logf("Shared key: %s", hex.EncodeToString(keyA))
	})

	// Test key exchange with confirmation
	t.Run("KeyExchangeWithConfirmation", func(t *testing.T) {
		// Party A (initiator)
		dA, _ := new(big.Int).SetString("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE", 16)
		rA, _ := new(big.Int).SetString("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563", 16)

		privParamA, _ := NewSM2KeyExchangePrivateParameters(true, dA, rA, curve)

		// Party B (responder)
		dB, _ := new(big.Int).SetString("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53", 16)
		rB, _ := new(big.Int).SetString("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80", 16)

		privParamB, _ := NewSM2KeyExchangePrivateParameters(false, dB, rB, curve)

		// Create public parameters
		pubParamA, _ := NewSM2KeyExchangePublicParameters(
			privParamA.GetStaticPublicPoint(),
			privParamA.GetEphemeralPublicPoint())

		pubParamB, _ := NewSM2KeyExchangePublicParameters(
			privParamB.GetStaticPublicPoint(),
			privParamB.GetEphemeralPublicPoint())

		// Initialize key exchange for both parties
		keA := NewSM2KeyExchange(nil)
		keA.Init(privParamA)

		keB := NewSM2KeyExchange(nil)
		keB.Init(privParamB)

		// B calculates key with confirmation tags
		resultB, err := keB.CalculateKeyWithConfirmation(128, nil, pubParamA)
		if err != nil {
			t.Fatalf("Failed to calculate key with confirmation for B: %v", err)
		}
		keyB := resultB[0]
		s1 := resultB[1]
		s2 := resultB[2]

		// A verifies B's confirmation and generates own
		resultA, err := keA.CalculateKeyWithConfirmation(128, s1, pubParamB)
		if err != nil {
			t.Fatalf("Failed to calculate key with confirmation for A: %v", err)
		}
		keyA := resultA[0]
		s2A := resultA[1]

		// Keys should match
		if hex.EncodeToString(keyA) != hex.EncodeToString(keyB) {
			t.Errorf("Keys do not match:\nA: %s\nB: %s",
				hex.EncodeToString(keyA),
				hex.EncodeToString(keyB))
		}

		// Confirmation tags should match
		if hex.EncodeToString(s2) != hex.EncodeToString(s2A) {
			t.Errorf("S2 tags do not match:\nB: %s\nA: %s",
				hex.EncodeToString(s2),
				hex.EncodeToString(s2A))
		}

		t.Logf("Shared key: %s", hex.EncodeToString(keyA))
		t.Logf("S1: %s", hex.EncodeToString(s1))
		t.Logf("S2: %s", hex.EncodeToString(s2))
	})

	// Test with user IDs
	t.Run("KeyExchangeWithUserIDs", func(t *testing.T) {
		// Party A (initiator)
		dA, _ := new(big.Int).SetString("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE", 16)
		rA, _ := new(big.Int).SetString("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563", 16)

		privParamA, _ := NewSM2KeyExchangePrivateParameters(true, dA, rA, curve)
		privParamAWithID := crypto.NewParametersWithID(privParamA, []byte("ALICE123@YAHOO.COM"))

		// Party B (responder)
		dB, _ := new(big.Int).SetString("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53", 16)
		rB, _ := new(big.Int).SetString("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80", 16)

		privParamB, _ := NewSM2KeyExchangePrivateParameters(false, dB, rB, curve)
		privParamBWithID := crypto.NewParametersWithID(privParamB, []byte("BILL456@YAHOO.COM"))

		// Create public parameters
		pubParamA, _ := NewSM2KeyExchangePublicParameters(
			privParamA.GetStaticPublicPoint(),
			privParamA.GetEphemeralPublicPoint())
		pubParamAWithID := crypto.NewParametersWithID(pubParamA, []byte("ALICE123@YAHOO.COM"))

		pubParamB, _ := NewSM2KeyExchangePublicParameters(
			privParamB.GetStaticPublicPoint(),
			privParamB.GetEphemeralPublicPoint())
		pubParamBWithID := crypto.NewParametersWithID(pubParamB, []byte("BILL456@YAHOO.COM"))

		// Initialize key exchange for both parties
		keA := NewSM2KeyExchange(nil)
		keA.Init(privParamAWithID)

		keB := NewSM2KeyExchange(nil)
		keB.Init(privParamBWithID)

		// Calculate shared keys
		keyA, err := keA.CalculateKey(128, pubParamBWithID)
		if err != nil {
			t.Fatalf("Failed to calculate key for A: %v", err)
		}

		keyB, err := keB.CalculateKey(128, pubParamAWithID)
		if err != nil {
			t.Fatalf("Failed to calculate key for B: %v", err)
		}

		// Keys should match
		if hex.EncodeToString(keyA) != hex.EncodeToString(keyB) {
			t.Errorf("Keys do not match:\nA: %s\nB: %s",
				hex.EncodeToString(keyA),
				hex.EncodeToString(keyB))
		}

		t.Logf("Shared key with user IDs: %s", hex.EncodeToString(keyA))
	})
}
