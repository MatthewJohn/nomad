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

	unwrappedKey1, err := structs.NewUnwrappedRootKey(structs.EncryptionAlgorithmAES256GCM)
	must.NoError(t, err)

	wrappedKey1, err := encrypter.AddUnwrappedKey(unwrappedKey1, true)
	must.NoError(t, err)
	must.NotNil(t, wrappedKey1)

	wrappedKey2 := wrappedKey1.Copy()
	wrappedKey2.WrappedKeys = []*structs.WrappedKey{}

	parentCtx := context.Background()

	// Generate a new encrypter, so we can test adding wrapped keys to it.
	freshEncrypter, err := NewEncrypter(srv, t.TempDir())
	must.NoError(t, err)
	must.NoError(t, freshEncrypter.AddWrappedKey(parentCtx, wrappedKey1))
	time.Sleep(2 * time.Second)
	must.NoError(t, freshEncrypter.AddWrappedKey(parentCtx, wrappedKey2))

	// Generate a context with a timeout and called the IsReady method. If the
	// IsReady method returns an error, then print out some potentially useful
	// information.
	timeoutContext, cancel := context.WithTimeout(parentCtx, 10*time.Second)
	defer cancel()

	if err := freshEncrypter.IsReady(timeoutContext); err != nil {
		t.Logf("decrypt tasks: %v", freshEncrypter.decryptTasks)
		t.Logf("keyring entries: %v", freshEncrypter.keyring)
		t.Fail()
	}
}
