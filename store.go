package chain

import (
	"time"

	"github.com/veilkey/veilkey-go-package/refs"
)

// Store is the interface the executor uses to persist state.
// Both vaultcenter and localvault DB layers implement this,
// enabling the chain package to be shared between services.
type Store interface {
	// TokenRef operations
	SaveRefWithExpiryAndHash(parts RefParts, ciphertext string, version int, status refs.RefStatus, expiresAt time.Time, secretName, plaintextHash string) error
	UpdateRefWithName(canonical, ciphertext string, version int, status refs.RefStatus, name string) error
	DeleteRef(canonical string) error

	// Agent operations
	UpsertAgent(nodeID, label, vaultHash, vaultName, ip string, port, secretsCount, configsCount, version, keyVersion int) error
	RegisterChild(child *ChildRecord) error

	// Config operations
	SaveConfig(key, value string) error

	// Audit operations
	SaveAuditEvent(event *AuditRecord) error
}

// ChainMeta provides read/write access to chain metadata (height, hash).
// Used by the ABCI Application for state recovery and commit persistence.
type ChainMeta interface {
	GetConfigValue(key string) (string, error)
	SaveConfig(key, value string) error
}

// RefParts holds the parsed components of a canonical ref.
type RefParts struct {
	Family string
	Scope  refs.RefScope
	ID     string
}

// ChildRecord holds child node registration data.
type ChildRecord struct {
	NodeID       string
	Label        string
	URL          string
	EncryptedDEK []byte
	Nonce        []byte
	Version      int
}

// AuditRecord holds audit event data.
type AuditRecord struct {
	EventID             string
	EntityType          string
	EntityID            string
	Action              string
	ActorType           string
	ActorID             string
	Reason              string
	Source              string
	ApprovalChallengeID string
	BeforeJSON          string
	AfterJSON           string
}
