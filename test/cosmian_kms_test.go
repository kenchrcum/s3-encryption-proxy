package test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"testing"
	"time"

	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/kmiptest"
	"github.com/ovh/kmip-go/payloads"
	"github.com/stretchr/testify/require"
)

func TestEncryptionEngineWithCosmianKMIP(t *testing.T) {
	exec := kmipserver.NewBatchExecutor()
	handler := &testKMIPWrapHandler{}
	exec.Route(kmip.OperationEncrypt, kmipserver.HandleFunc(handler.encrypt))
	exec.Route(kmip.OperationDecrypt, kmipserver.HandleFunc(handler.decrypt))

	addr, ca := kmiptest.NewServer(t, exec)
	tlsCfg := tlsConfigFromPEM(t, ca)

	manager, err := crypto.NewCosmianKMIPManager(crypto.CosmianKMIPOptions{
		Endpoint:       addr,
		Keys:           []crypto.KMIPKeyReference{{ID: "test-wrap-key", Version: 1}},
		TLSConfig:      tlsCfg,
		Timeout:        time.Second,
		Provider:       "test-kmip",
		DualReadWindow: 1,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = manager.Close(context.Background())
	})

	engine, err := crypto.NewEngine("fallback-password-123")
	require.NoError(t, err)
	crypto.SetKeyManager(engine, manager)

	plaintext := []byte("cosmian-encryption-test")
	encReader, encMetadata, err := engine.Encrypt(bytes.NewReader(plaintext), map[string]string{
		"Content-Type": "text/plain",
	})
	require.NoError(t, err)
	require.Equal(t, "true", encMetadata[crypto.MetaEncrypted])
	require.NotEmpty(t, encMetadata[crypto.MetaWrappedKeyCiphertext])
	require.Equal(t, "test-kmip", encMetadata[crypto.MetaKMSProvider])

	decReader, decMetadata, err := engine.Decrypt(encReader, encMetadata)
	require.NoError(t, err)
	require.Equal(t, "text/plain", decMetadata["Content-Type"])
	decrypted, err := io.ReadAll(decReader)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

type testKMIPWrapHandler struct{}

func (h *testKMIPWrapHandler) encrypt(_ context.Context, req *payloads.EncryptRequestPayload) (*payloads.EncryptResponsePayload, error) {
	return &payloads.EncryptResponsePayload{
		UniqueIdentifier: req.UniqueIdentifier,
		Data:             xorBytes(req.Data),
	}, nil
}

func (h *testKMIPWrapHandler) decrypt(_ context.Context, req *payloads.DecryptRequestPayload) (*payloads.DecryptResponsePayload, error) {
	return &payloads.DecryptResponsePayload{
		UniqueIdentifier: req.UniqueIdentifier,
		Data:             xorBytes(req.Data),
	}, nil
}

func xorBytes(in []byte) []byte {
	out := make([]byte, len(in))
	for i, b := range in {
		out[i] = b ^ 0xAA
	}
	return out
}

func tlsConfigFromPEM(t *testing.T, pem string) *tls.Config {
	t.Helper()
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM([]byte(pem)))
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}
}
