package chain

// Config keys persisted to DB for chain state recovery.
const (
	ConfigKeyChainHeight = "_chain_height"
	ConfigKeyChainHash   = "_chain_hash"
)

// Application metadata returned in ABCI Info.
const (
	AppName    = "veilkey-vaultcenter"
	AppVersion = "0.1.0"
)

// Chain defaults.
const (
	DefaultChainID       = "veilkey-chain-1"
	DefaultValidatorName = "vaultcenter"
	DefaultRPCListen     = "tcp://127.0.0.1:26657"
	DefaultP2PListen     = "tcp://0.0.0.0:26656"
	DefaultLogLevel      = "error"
)
