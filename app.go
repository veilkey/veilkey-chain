package chain

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"

	abcitypes "github.com/cometbft/cometbft/abci/types"
)

// Application implements the CometBFT ABCI v0.38 interface.
// It uses Store for TX execution and ChainMeta for chain state recovery.
type Application struct {
	store     Store
	config    ChainMeta
	appHeight int64
	appHash   []byte
}

var _ abcitypes.Application = (*Application)(nil)

// NewApplication creates an ABCI application backed by the given store.
func NewApplication(store Store, config ChainMeta) *Application {
	app := &Application{store: store, config: config}
	app.recoverState()
	return app
}

func (app *Application) recoverState() {
	if val, err := app.config.GetConfigValue(ConfigKeyChainHeight); err == nil {
		if h, err := strconv.ParseInt(val, 10, 64); err == nil {
			app.appHeight = h
		}
	}
	if val, err := app.config.GetConfigValue(ConfigKeyChainHash); err == nil {
		if decoded, err := hex.DecodeString(val); err == nil {
			app.appHash = decoded
		}
	}
}

func (app *Application) Info(_ context.Context, req *abcitypes.RequestInfo) (*abcitypes.ResponseInfo, error) {
	return &abcitypes.ResponseInfo{
		Data:             AppName,
		Version:          AppVersion,
		LastBlockHeight:  app.appHeight,
		LastBlockAppHash: app.appHash,
	}, nil
}

func (app *Application) InitChain(_ context.Context, _ *abcitypes.RequestInitChain) (*abcitypes.ResponseInitChain, error) {
	return &abcitypes.ResponseInitChain{}, nil
}

func (app *Application) CheckTx(_ context.Context, req *abcitypes.RequestCheckTx) (*abcitypes.ResponseCheckTx, error) {
	_, err := DecodeTx(req.Tx)
	if err != nil {
		return &abcitypes.ResponseCheckTx{Code: 1, Log: err.Error()}, nil
	}
	return &abcitypes.ResponseCheckTx{Code: 0}, nil
}

func (app *Application) FinalizeBlock(_ context.Context, req *abcitypes.RequestFinalizeBlock) (*abcitypes.ResponseFinalizeBlock, error) {
	txResults := make([]*abcitypes.ExecTxResult, len(req.Txs))

	for i, txBytes := range req.Txs {
		env, err := DecodeTx(txBytes)
		if err != nil {
			txResults[i] = &abcitypes.ExecTxResult{Code: 2, Log: err.Error()}
			continue
		}
		code, log := Execute(app.store, env)
		txResults[i] = &abcitypes.ExecTxResult{Code: code, Log: log}
	}

	app.appHeight = req.Height
	app.appHash = computeAppHash(req.Height)

	return &abcitypes.ResponseFinalizeBlock{
		TxResults: txResults,
		AppHash:   app.appHash,
	}, nil
}

func (app *Application) Commit(_ context.Context, _ *abcitypes.RequestCommit) (*abcitypes.ResponseCommit, error) {
	_ = app.config.SaveConfig(ConfigKeyChainHeight, fmt.Sprintf("%d", app.appHeight))
	_ = app.config.SaveConfig(ConfigKeyChainHash, hex.EncodeToString(app.appHash))
	return &abcitypes.ResponseCommit{}, nil
}

func (app *Application) Query(_ context.Context, req *abcitypes.RequestQuery) (*abcitypes.ResponseQuery, error) {
	return &abcitypes.ResponseQuery{
		Code: 0,
		Log:  fmt.Sprintf("height=%d", app.appHeight),
		Key:  req.Data,
	}, nil
}

func (app *Application) PrepareProposal(_ context.Context, req *abcitypes.RequestPrepareProposal) (*abcitypes.ResponsePrepareProposal, error) {
	return &abcitypes.ResponsePrepareProposal{Txs: req.Txs}, nil
}

func (app *Application) ProcessProposal(_ context.Context, _ *abcitypes.RequestProcessProposal) (*abcitypes.ResponseProcessProposal, error) {
	return &abcitypes.ResponseProcessProposal{
		Status: abcitypes.ResponseProcessProposal_ACCEPT,
	}, nil
}

func (app *Application) ListSnapshots(_ context.Context, _ *abcitypes.RequestListSnapshots) (*abcitypes.ResponseListSnapshots, error) {
	return &abcitypes.ResponseListSnapshots{}, nil
}

func (app *Application) OfferSnapshot(_ context.Context, _ *abcitypes.RequestOfferSnapshot) (*abcitypes.ResponseOfferSnapshot, error) {
	return &abcitypes.ResponseOfferSnapshot{}, nil
}

func (app *Application) LoadSnapshotChunk(_ context.Context, _ *abcitypes.RequestLoadSnapshotChunk) (*abcitypes.ResponseLoadSnapshotChunk, error) {
	return &abcitypes.ResponseLoadSnapshotChunk{}, nil
}

func (app *Application) ApplySnapshotChunk(_ context.Context, _ *abcitypes.RequestApplySnapshotChunk) (*abcitypes.ResponseApplySnapshotChunk, error) {
	return &abcitypes.ResponseApplySnapshotChunk{Result: abcitypes.ResponseApplySnapshotChunk_ACCEPT}, nil
}

func (app *Application) ExtendVote(_ context.Context, _ *abcitypes.RequestExtendVote) (*abcitypes.ResponseExtendVote, error) {
	return &abcitypes.ResponseExtendVote{}, nil
}

func (app *Application) VerifyVoteExtension(_ context.Context, _ *abcitypes.RequestVerifyVoteExtension) (*abcitypes.ResponseVerifyVoteExtension, error) {
	return &abcitypes.ResponseVerifyVoteExtension{}, nil
}

func computeAppHash(height int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(height))
	h := sha256.Sum256(b)
	return h[:]
}
