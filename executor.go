package chain

import (
	"fmt"
	"log"
	"time"

	"github.com/veilkey/veilkey-go-package/crypto"
	"github.com/veilkey/veilkey-go-package/refs"
)

// Execute applies a decoded TxEnvelope to the database.
// Returns (resultCode uint32, resultLog string).
// Code 0 = success, 1 = unknown type, 2 = decode error, 3 = db error, 4 = validation error.
//
// IMPORTANT: This function must be deterministic for chain replay.
// Never use time.Now() — all time references must come from env.Timestamp.
func Execute(d Store, env *TxEnvelope) (uint32, string) {
	code, resultLog, entityType, entityID := executeTx(d, env)

	// Auto-generate audit row on successful TX execution
	if code == 0 && env.ActorType != "" {
		auditErr := d.SaveAuditEvent(&AuditRecord{
			EventID:    crypto.GenerateUUID(),
			EntityType: entityType,
			EntityID:   entityID,
			Action:     string(env.Type),
			ActorType:  env.ActorType,
			ActorID:    env.ActorID,
			Source:     env.Source,
		})
		if auditErr != nil {
			log.Printf("chain: auto-audit failed for %s: %v", env.Type, auditErr)
		}
	}

	return code, resultLog
}

// executeTx dispatches the TX to the appropriate db method.
// Returns (code, log, entityType, entityID) for audit generation.
func executeTx(d Store, env *TxEnvelope) (uint32, string, string, string) {
	switch env.Type {

	// ── TokenRef operations ─────────────────────────────────────────────

	case TxSaveTokenRef:
		p, err := DecodePayload[SaveTokenRefPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode SaveTokenRef: %v", err), "", ""
		}

		normScope, normStatus, normErr := refs.NormalizeScopeStatus(
			p.RefFamily, p.RefScope, p.Status, refs.RefScopeTemp,
		)
		if normErr != nil {
			return 4, fmt.Sprintf("validate SaveTokenRef: %v", normErr), "", ""
		}

		parts := RefParts{Family: p.RefFamily, Scope: normScope, ID: p.RefID}
		expiresAt := env.Timestamp.Add(4 * time.Hour) // deterministic — based on TX timestamp
		if p.ExpiresAt != nil {
			expiresAt = *p.ExpiresAt
		}
		if err := d.SaveRefWithExpiryAndHash(
			parts, p.Ciphertext, p.Version,
			normStatus, expiresAt,
			p.SecretName, p.PlaintextHash,
		); err != nil {
			return 3, fmt.Sprintf("db SaveTokenRef: %v", err), "", ""
		}
		canonical := refs.MakeRef(p.RefFamily, normScope, p.RefID)
		return 0, canonical, "tracked_ref", canonical

	case TxUpdateTokenRef:
		p, err := DecodePayload[UpdateTokenRefPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode UpdateTokenRef: %v", err), "", ""
		}
		if _, _, _, parseErr := refs.ParseRef(p.RefCanonical); parseErr != nil {
			return 4, fmt.Sprintf("validate UpdateTokenRef: %v", parseErr), "", ""
		}
		if err := d.UpdateRefWithName(
			p.RefCanonical, p.Ciphertext, p.Version,
			p.Status, "",
		); err != nil {
			return 3, fmt.Sprintf("db UpdateTokenRef: %v", err), "", ""
		}
		return 0, p.RefCanonical, "tracked_ref", p.RefCanonical

	case TxDeleteTokenRef:
		p, err := DecodePayload[DeleteTokenRefPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode DeleteTokenRef: %v", err), "", ""
		}
		if _, _, _, parseErr := refs.ParseRef(p.RefCanonical); parseErr != nil {
			return 4, fmt.Sprintf("validate DeleteTokenRef: %v", parseErr), "", ""
		}
		if err := d.DeleteRef(p.RefCanonical); err != nil {
			return 3, fmt.Sprintf("db DeleteTokenRef: %v", err), "", ""
		}
		return 0, p.RefCanonical, "tracked_ref", p.RefCanonical

	case TxIncrementRefVersion:
		p, err := DecodePayload[IncrementRefVersionPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode IncrementRefVersion: %v", err), "", ""
		}
		if _, _, _, parseErr := refs.ParseRef(p.RefCanonical); parseErr != nil {
			return 4, fmt.Sprintf("validate IncrementRefVersion: %v", parseErr), "", ""
		}
		if err := d.UpdateRefWithName(p.RefCanonical, "", p.NewVersion, "", ""); err != nil {
			return 3, fmt.Sprintf("db IncrementRefVersion: %v", err), "", ""
		}
		return 0, fmt.Sprintf("%s@v%d", p.RefCanonical, p.NewVersion), "tracked_ref", p.RefCanonical

	// ── Agent operations ────────────────────────────────────────────────

	case TxUpsertAgent:
		p, err := DecodePayload[UpsertAgentPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode UpsertAgent: %v", err), "", ""
		}
		if err := d.UpsertAgent(
			p.NodeID, p.Label, p.VaultHash, p.VaultName,
			p.IP, p.Port, p.SecretsCount, p.ConfigsCount,
			p.Version, p.KeyVersion,
		); err != nil {
			return 3, fmt.Sprintf("db UpsertAgent: %v", err), "", ""
		}
		return 0, p.NodeID, "agent", p.NodeID

	case TxUpdateAgentState:
		p, err := DecodePayload[UpdateAgentStatePayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode UpdateAgentState: %v", err), "", ""
		}
		update := &AgentStateUpdate{}
		update.RotationRequired = p.RotationRequired
		update.RotationReason = p.RotationReason
		update.RebindRequired = p.RebindRequired
		update.RebindReason = p.RebindReason
		update.RetryStage = p.RetryStage
		update.BlockReason = p.BlockReason
		update.KeyVersion = p.KeyVersion
		if p.NextRetryAt != nil {
			update.SetNextRetryAt = true
			if *p.NextRetryAt != "" {
				t, err := time.Parse(time.RFC3339, *p.NextRetryAt)
				if err != nil {
					return 4, fmt.Sprintf("validate UpdateAgentState next_retry_at: %v", err), "", ""
				}
				update.NextRetryAt = &t
			}
		}
		if p.BlockedAt != nil {
			update.SetBlockedAt = true
			if *p.BlockedAt != "" {
				t, err := time.Parse(time.RFC3339, *p.BlockedAt)
				if err != nil {
					return 4, fmt.Sprintf("validate UpdateAgentState blocked_at: %v", err), "", ""
				}
				update.BlockedAt = &t
			}
		}
		if err := d.UpdateAgentState(p.NodeID, update); err != nil {
			return 3, fmt.Sprintf("db UpdateAgentState: %v", err), "", ""
		}
		return 0, p.NodeID, "agent", p.NodeID

	case TxDeleteAgent:
		p, err := DecodePayload[DeleteAgentPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode DeleteAgent: %v", err), "", ""
		}
		if err := d.DeleteAgent(p.NodeID); err != nil {
			return 3, fmt.Sprintf("db DeleteAgent: %v", err), "", ""
		}
		return 0, p.NodeID, "agent", p.NodeID

	case TxRegisterChild:
		p, err := DecodePayload[RegisterChildPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode RegisterChild: %v", err), "", ""
		}
		child := &ChildRecord{
			NodeID:  p.NodeID,
			Label:   p.Label,
			URL:     p.URL,
			Version: p.Version,
		}
		if err := d.RegisterChild(child); err != nil {
			return 3, fmt.Sprintf("db RegisterChild: %v", err), "", ""
		}
		return 0, p.NodeID, "child", p.NodeID

	case TxDeleteChild:
		p, err := DecodePayload[DeleteChildPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode DeleteChild: %v", err), "", ""
		}
		if err := d.DeleteChild(p.NodeID); err != nil {
			return 3, fmt.Sprintf("db DeleteChild: %v", err), "", ""
		}
		return 0, p.NodeID, "child", p.NodeID

	case TxUpdateChildURL:
		p, err := DecodePayload[UpdateChildURLPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode UpdateChildURL: %v", err), "", ""
		}
		if err := d.UpdateChildURL(p.NodeID, p.URL); err != nil {
			return 3, fmt.Sprintf("db UpdateChildURL: %v", err), "", ""
		}
		return 0, p.NodeID, "child", p.NodeID

	// ── Config operations ───────────────────────────────────────────────

	case TxSetConfig:
		p, err := DecodePayload[SetConfigPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode SetConfig: %v", err), "", ""
		}
		if err := d.SaveConfig(p.Key, p.Value); err != nil {
			return 3, fmt.Sprintf("db SetConfig: %v", err), "", ""
		}
		return 0, p.Key, "config", p.Key

	case TxDeleteConfig:
		p, err := DecodePayload[DeleteConfigPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode DeleteConfig: %v", err), "", ""
		}
		if err := d.DeleteConfig(p.Key); err != nil {
			return 3, fmt.Sprintf("db DeleteConfig: %v", err), "", ""
		}
		return 0, p.Key, "config", p.Key

	case TxSetParentURL:
		p, err := DecodePayload[SetParentURLPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode SetParentURL: %v", err), "", ""
		}
		if err := d.SetParentURL(p.ParentURL); err != nil {
			return 3, fmt.Sprintf("db SetParentURL: %v", err), "", ""
		}
		return 0, p.ParentURL, "node_info", "parent_url"

	// ── Binding operations ──────────────────────────────────────────────

	case TxSaveBinding:
		p, err := DecodePayload[SaveBindingPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode SaveBinding: %v", err), "", ""
		}
		if p.RefCanonical != "" {
			if _, _, _, parseErr := refs.ParseRef(p.RefCanonical); parseErr != nil {
				return 4, fmt.Sprintf("validate SaveBinding ref: %v", parseErr), "", ""
			}
		}
		if err := d.SaveBinding(&BindingRecord{
			BindingID:    p.BindingID,
			BindingType:  p.BindingType,
			TargetName:   p.TargetName,
			VaultHash:    p.VaultHash,
			SecretName:   p.SecretName,
			FieldKey:     p.FieldKey,
			RefCanonical: p.RefCanonical,
			Required:     p.Required,
		}); err != nil {
			return 3, fmt.Sprintf("db SaveBinding: %v", err), "", ""
		}
		return 0, p.BindingID, "binding", p.BindingID

	case TxDeleteBinding:
		p, err := DecodePayload[DeleteBindingPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode DeleteBinding: %v", err), "", ""
		}
		if err := d.DeleteBinding(p.BindingID); err != nil {
			return 3, fmt.Sprintf("db DeleteBinding: %v", err), "", ""
		}
		return 0, p.BindingID, "binding", p.BindingID

	case TxDeleteBindingsByTarget:
		p, err := DecodePayload[DeleteBindingsByTargetPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode DeleteBindingsByTarget: %v", err), "", ""
		}
		if err := d.DeleteBindingsByTarget(p.BindingType, p.TargetName); err != nil {
			return 3, fmt.Sprintf("db DeleteBindingsByTarget: %v", err), "", ""
		}
		entityID := p.BindingType + ":" + p.TargetName
		return 0, entityID, "binding", entityID

	// ── Global function operations ──────────────────────────────────────

	case TxSaveGlobalFunction:
		p, err := DecodePayload[SaveGlobalFunctionPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode SaveGlobalFunction: %v", err), "", ""
		}
		if err := d.SaveGlobalFunction(&GlobalFunctionRecord{
			Name:         p.Name,
			FunctionHash: p.FunctionHash,
			Category:     p.Category,
			Command:      p.Command,
			VarsJSON:     p.VarsJSON,
		}); err != nil {
			return 3, fmt.Sprintf("db SaveGlobalFunction: %v", err), "", ""
		}
		return 0, p.Name, "global_function", p.Name

	case TxDeleteGlobalFunction:
		p, err := DecodePayload[DeleteGlobalFunctionPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode DeleteGlobalFunction: %v", err), "", ""
		}
		if err := d.DeleteGlobalFunction(p.Name); err != nil {
			return 3, fmt.Sprintf("db DeleteGlobalFunction: %v", err), "", ""
		}
		return 0, p.Name, "global_function", p.Name

	// ── Audit operations (explicit metadata) ────────────────────────────

	case TxRecordAuditEvent:
		p, err := DecodePayload[RecordAuditEventPayload](env)
		if err != nil {
			return 2, fmt.Sprintf("decode RecordAuditEvent: %v", err), "", ""
		}
		auditErr := d.SaveAuditEvent(&AuditRecord{
			EventID:             p.EventID,
			EntityType:          p.EntityType,
			EntityID:            p.EntityID,
			Action:              p.Action,
			ActorType:           p.ActorType,
			ActorID:             p.ActorID,
			Reason:              p.Reason,
			Source:              p.Source,
			ApprovalChallengeID: p.ApprovalChallengeID,
			BeforeJSON:          p.BeforeJSON,
			AfterJSON:           p.AfterJSON,
		})
		if auditErr != nil {
			return 3, fmt.Sprintf("db RecordAuditEvent: %v", auditErr), "", ""
		}
		// Skip auto-audit for explicit audit TX (avoid double-write)
		return 0, p.EventID, "", ""

	default:
		return 1, fmt.Sprintf("unknown tx type: %s", env.Type), "", ""
	}
}
