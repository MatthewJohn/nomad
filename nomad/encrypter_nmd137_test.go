package nomad

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/nomad/helper/testlog"
	"github.com/hashicorp/nomad/nomad/structs"
	"github.com/shoenig/test/must"
)

func TestEncrypter_nmd137(t *testing.T) {

	srv := &Server{
		logger: testlog.HCLogger(t),
		config: &Config{},
	}

	// Generate an encrypter, so we can get some wrapped keys.
	encrypter, err := NewEncrypter(srv, t.TempDir())
	must.NoError(t, err)

	// Fake life as a 1.6 server by writing only ed25519 keys and removing the
	// RSAKey. Add this to the encrypter as if we'd loaded it from the on-disk
	// keystore
	oldKey, err := structs.NewUnwrappedRootKey(structs.EncryptionAlgorithmAES256GCM)
	must.NoError(t, err)
	oldKey.RSAKey = nil

	// If we call addCipher as if we'd loaded the key from the on-disk keystore,
	// we can't hit the error anymore becasuse we exit AddWrappedKey early!?
	//
	//must.NoError(t, encrypter.addCipher(oldKey))

	// this is a (wrapped) RootKey but doesn't have any key material because it
	// comes from a legacy RootKeyMeta FSM snapshot
	wrappedOldKey := structs.NewRootKey(oldKey.Meta)

	// this is a RootKey with the exact same key ID, that has key material
	// because it comes from a RootKey FSM snapshot
	unwrappedNewKey := oldKey.Copy()
	wrappedNewKey, err := encrypter.wrapRootKey(unwrappedNewKey, true)
	must.NoError(t, err)

	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	t.Cleanup(shutdownCancel)

	err = encrypter.AddWrappedKey(shutdownCtx, wrappedNewKey)
	must.NoError(t, err)

	time.Sleep(2 * time.Second)

	err = encrypter.AddWrappedKey(shutdownCtx, wrappedOldKey)
	must.NoError(t, err)

	// Generate a context with a timeout and called the IsReady method. If the
	// IsReady method returns an error, then print out some potentially useful
	// information.
	timeoutContext, cancel := context.WithTimeout(shutdownCtx, 10*time.Second)
	defer cancel()

	if err := encrypter.IsReady(timeoutContext); err != nil {
		t.Logf("decrypt tasks: %v", encrypter.decryptTasks)
		t.Logf("keyring entries: %v", encrypter.keyring)
		t.Fail()
	}
}
