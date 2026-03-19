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
	DeleteAgent(nodeID string) error
	UpdateAgentState(nodeID string, updates *AgentStateUpdate) error
	RegisterChild(child *ChildRecord) error
	DeleteChild(nodeID string) error
	UpdateChildURL(nodeID, url string) error

	// Binding operations
	SaveBinding(binding *BindingRecord) error
	DeleteBinding(bindingID string) error
	DeleteBindingsByTarget(bindingType, targetName string) error

	// Global function operations
	SaveGlobalFunction(fn *GlobalFunctionRecord) error
	DeleteGlobalFunction(name string) error

	// Config operations
	SaveConfig(key, value string) error
	DeleteConfig(key string) error

	// Node topology
	SetParentURL(parentURL string) error

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

// ChildRecord holds child node registration data for chain TX.
// SECURITY: DEK fields excluded — key material never goes on chain.
type ChildRecord struct {
	NodeID  string
	Label   string
	URL     string
	Version int
}

// BindingRecord holds binding data for chain TX.
type BindingRecord struct {
	BindingID    string
	BindingType  string
	TargetName   string
	VaultHash    string
	SecretName   string
	FieldKey     string
	RefCanonical string
	Required     bool
}

// AgentStateUpdate carries partial agent state updates.
// Pointer fields: nil = no change, non-nil = set to value.
type AgentStateUpdate struct {
	RotationRequired *bool
	RotationReason   *string
	RebindRequired   *bool
	RebindReason     *string
	RetryStage       *int
	NextRetryAt      *time.Time // nil = clear
	SetNextRetryAt   bool       // true = apply NextRetryAt (even if nil = clear)
	BlockedAt        *time.Time // nil = clear
	SetBlockedAt     bool       // true = apply BlockedAt (even if nil = clear)
	BlockReason      *string
	KeyVersion       *int
}

// GlobalFunctionRecord holds global function data for chain TX.
type GlobalFunctionRecord struct {
	Name         string
	FunctionHash string
	Category     string
	Command      string
	VarsJSON     string
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
