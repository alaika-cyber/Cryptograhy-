const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const STEGO_MAGIC = "STG2";
const STEGO_VERSION = 1;

const algorithmSelect = document.getElementById("algorithm");
const actionSelect = document.getElementById("cryptoAction");
const controlsHost = document.getElementById("algoControls");
const cryptoInput = document.getElementById("cryptoInput");
const cryptoOutput = document.getElementById("cryptoOutput");
const runCryptoBtn = document.getElementById("runCrypto");
const clearCryptoBtn = document.getElementById("clearCrypto");
const copyCryptoBtn = document.getElementById("copyCrypto");
const downloadCryptoBtn = document.getElementById("downloadCrypto");

const textCarrierInput = document.getElementById("textCarrier");
const textDecodeInput = document.getElementById("textDecodeImage");
const secretMessageInput = document.getElementById("secretMessage");
const textProtectInput = document.getElementById("textProtect");
const textPassphraseInput = document.getElementById("textPassphrase");
const hideTextBtn = document.getElementById("hideTextBtn");
const extractTextBtn = document.getElementById("extractTextBtn");
const encryptThenHideBtn = document.getElementById("encryptThenHide");
const extractThenLoadBtn = document.getElementById("extractThenLoad");
const textStatus = document.getElementById("textStatus");
const textStegoDownload = document.getElementById("downloadTextStego");
const textCapacity = document.getElementById("textCapacity");
const textCarrierPreview = document.getElementById("textCarrierPreview");
const textDecodePreview = document.getElementById("textDecodePreview");
const textProgress = document.getElementById("textProgress");

const imageCarrierInput = document.getElementById("imageCarrier");
const secretImageInput = document.getElementById("secretImage");
const imageDecodeContainerInput = document.getElementById("imageDecodeContainer");
const imageProtectInput = document.getElementById("imageProtect");
const imagePassphraseInput = document.getElementById("imagePassphrase");
const hideImageBtn = document.getElementById("hideImageBtn");
const extractImageBtn = document.getElementById("extractImageBtn");
const imageStatus = document.getElementById("imageStatus");
const imageStegoDownload = document.getElementById("downloadImageStego");
const extractedImageDownload = document.getElementById("downloadExtractedImage");
const imageCapacity = document.getElementById("imageCapacity");
const imageCarrierPreview = document.getElementById("imageCarrierPreview");
const secretImagePreview = document.getElementById("secretImagePreview");
const imageProgress = document.getElementById("imageProgress");

const state = {
  textStegoObjectUrl: null,
  imageStegoObjectUrl: null,
  extractedImageObjectUrl: null,
  cryptoDownloadUrl: null,
  previewUrls: {},
};

const crc32Table = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let j = 0; j < 8; j += 1) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  return `${mb.toFixed(2)} MB`;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToBytes(base64) {
  if (typeof base64 !== "string" || !/^[A-Za-z0-9+/=]+$/.test(base64)) {
    throw new Error("Invalid base64 input.");
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function strToBytes(str) {
  return textEncoder.encode(str);
}

function bytesToStr(bytes) {
  return textDecoder.decode(bytes);
}

function concatBytes(arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    output.set(arr, offset);
    offset += arr.length;
  }
  return output;
}

function u16ToBytes(num) {
  return new Uint8Array([(num >>> 8) & 0xff, num & 0xff]);
}

function bytesToU16(bytes, offset = 0) {
  return (bytes[offset] << 8) + bytes[offset + 1];
}

function u32ToBytes(num) {
  return new Uint8Array([
    (num >>> 24) & 0xff,
    (num >>> 16) & 0xff,
    (num >>> 8) & 0xff,
    num & 0xff,
  ]);
}

function bytesToU32(bytes, offset = 0) {
  return ((bytes[offset] << 24) >>> 0)
    + ((bytes[offset + 1] << 16) >>> 0)
    + ((bytes[offset + 2] << 8) >>> 0)
    + (bytes[offset + 3] >>> 0);
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) {
    crc = crc32Table[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function randomBytes(length) {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

function assertPayloadFields(payload, required, context) {
  for (const key of required) {
    if (!(key in payload)) throw new Error(`Invalid ${context} payload. Missing ${key}.`);
  }
}

function safeJsonParse(raw, context) {
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`${context} is not valid JSON.`);
  }
}

async function deriveAesKey(passphrase, salt, iterations = 250000) {
  const baseKey = await crypto.subtle.importKey("raw", strToBytes(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptAesText(plainText, passphrase) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const iterations = 250000;
  const key = await deriveAesKey(passphrase, salt, iterations);
  const cipherBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, strToBytes(plainText));

  return JSON.stringify({
    ver: 1,
    alg: "AES-GCM",
    kdf: "PBKDF2-SHA256",
    iterations,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ct: bytesToBase64(new Uint8Array(cipherBuffer)),
  });
}

async function decryptAesText(cipherJson, passphrase) {
  const payload = safeJsonParse(cipherJson, "AES ciphertext");
  assertPayloadFields(payload, ["salt", "iv", "ct", "iterations"], "AES");

  const iterations = Number(payload.iterations);
  if (!Number.isInteger(iterations) || iterations < 50000 || iterations > 2000000) {
    throw new Error("Invalid AES PBKDF2 iterations.");
  }

  const salt = base64ToBytes(payload.salt);
  const iv = base64ToBytes(payload.iv);
  const ct = base64ToBytes(payload.ct);
  const key = await deriveAesKey(passphrase, salt, iterations);
  const plainBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return bytesToStr(new Uint8Array(plainBuffer));
}

function arrayBufferToPem(buffer, typeLabel) {
  const base64 = bytesToBase64(new Uint8Array(buffer));
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${typeLabel}-----\n${lines.join("\n")}\n-----END ${typeLabel}-----`;
}

function pemToArrayBuffer(pem) {
  const base64 = pem.replace(/-----BEGIN[^-]+-----/g, "").replace(/-----END[^-]+-----/g, "").replace(/\s+/g, "");
  if (!base64) throw new Error("Invalid PEM format.");
  return base64ToBytes(base64).buffer;
}

async function generateRsaKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"],
  );
  const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  return {
    publicPem: arrayBufferToPem(spki, "PUBLIC KEY"),
    privatePem: arrayBufferToPem(pkcs8, "PRIVATE KEY"),
  };
}

async function importRsaPublicKey(publicPem) {
  return crypto.subtle.importKey("spki", pemToArrayBuffer(publicPem), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
}

async function importRsaPrivateKey(privatePem) {
  return crypto.subtle.importKey("pkcs8", pemToArrayBuffer(privatePem), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
}

async function encryptRsaHybrid(plainText, publicPem) {
  const publicKey = await importRsaPublicKey(publicPem);
  const aesRaw = randomBytes(32);
  const aesKey = await crypto.subtle.importKey("raw", aesRaw, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = randomBytes(12);
  const ctBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, strToBytes(plainText));
  const wrappedKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, aesRaw);

  return JSON.stringify({
    ver: 1,
    alg: "RSA-HYBRID",
    ek: bytesToBase64(new Uint8Array(wrappedKey)),
    iv: bytesToBase64(iv),
    ct: bytesToBase64(new Uint8Array(ctBuffer)),
  });
}

async function decryptRsaHybrid(cipherJson, privatePem) {
  const payload = safeJsonParse(cipherJson, "RSA-Hybrid ciphertext");
  assertPayloadFields(payload, ["ek", "iv", "ct"], "RSA-Hybrid");

  const privateKey = await importRsaPrivateKey(privatePem);
  const aesRaw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, base64ToBytes(payload.ek));
  const aesKey = await crypto.subtle.importKey("raw", aesRaw, { name: "AES-GCM" }, false, ["decrypt"]);
  const plainBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(payload.iv) },
    aesKey,
    base64ToBytes(payload.ct),
  );
  return bytesToStr(new Uint8Array(plainBuffer));
}

async function generateEcdhKeyPair() {
  const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const rawPublic = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  const privatePkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  return {
    publicPem: arrayBufferToPem(rawPublic, "EC PUBLIC KEY"),
    privatePem: arrayBufferToPem(privatePkcs8, "EC PRIVATE KEY"),
  };
}

async function importEcdhPublicKey(publicPem) {
  return crypto.subtle.importKey("raw", pemToArrayBuffer(publicPem), { name: "ECDH", namedCurve: "P-256" }, false, []);
}

async function importEcdhPrivateKey(privatePem) {
  return crypto.subtle.importKey("pkcs8", pemToArrayBuffer(privatePem), { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
}

async function encryptEcdhHybrid(plainText, recipientPublicPem) {
  const recipientPublic = await importEcdhPublicKey(recipientPublicPem);
  const ephPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const sharedBits = await crypto.subtle.deriveBits({ name: "ECDH", public: recipientPublic }, ephPair.privateKey, 256);
  const aesKey = await crypto.subtle.importKey("raw", sharedBits, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, strToBytes(plainText));
  const ephRaw = await crypto.subtle.exportKey("raw", ephPair.publicKey);

  return JSON.stringify({
    ver: 1,
    alg: "ECDH-HYBRID",
    epk: bytesToBase64(new Uint8Array(ephRaw)),
    iv: bytesToBase64(iv),
    ct: bytesToBase64(new Uint8Array(ct)),
  });
}

async function decryptEcdhHybrid(cipherJson, privatePem) {
  const payload = safeJsonParse(cipherJson, "ECDH-Hybrid ciphertext");
  assertPayloadFields(payload, ["epk", "iv", "ct"], "ECDH-Hybrid");

  const recipientPrivate = await importEcdhPrivateKey(privatePem);
  const ephPublic = await crypto.subtle.importKey(
    "raw",
    base64ToBytes(payload.epk),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );

  const sharedBits = await crypto.subtle.deriveBits({ name: "ECDH", public: ephPublic }, recipientPrivate, 256);
  const aesKey = await crypto.subtle.importKey("raw", sharedBits, { name: "AES-GCM" }, false, ["decrypt"]);
  const plainBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(payload.iv) },
    aesKey,
    base64ToBytes(payload.ct),
  );

  return bytesToStr(new Uint8Array(plainBuffer));
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", strToBytes(text));
  return [...new Uint8Array(digest)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function rotateChar(char, amount) {
  const code = char.charCodeAt(0);
  if (code >= 65 && code <= 90) return String.fromCharCode(((code - 65 + amount + 26) % 26) + 65);
  if (code >= 97 && code <= 122) return String.fromCharCode(((code - 97 + amount + 26) % 26) + 97);
  return char;
}

function caesarEncrypt(text, shift) {
  const fixedShift = Number(shift) || 0;
  return [...text].map((char) => rotateChar(char, fixedShift)).join("");
}

function caesarDecrypt(text, shift) {
  const fixedShift = Number(shift) || 0;
  return [...text].map((char) => rotateChar(char, -fixedShift)).join("");
}

function vigenereTransform(text, key, isDecrypt) {
  const normalizedKey = (key || "").replace(/[^A-Za-z]/g, "").toLowerCase();
  if (!normalizedKey.length) throw new Error("Vigenere key must include letters.");

  let keyIndex = 0;
  const output = [];
  for (const char of text) {
    const code = char.charCodeAt(0);
    const isUpper = code >= 65 && code <= 90;
    const isLower = code >= 97 && code <= 122;
    if (!isUpper && !isLower) {
      output.push(char);
      continue;
    }
    const keyShift = normalizedKey.charCodeAt(keyIndex % normalizedKey.length) - 97;
    output.push(rotateChar(char, isDecrypt ? -keyShift : keyShift));
    keyIndex += 1;
  }
  return output.join("");
}

function vigenereEncrypt(text, key) {
  return vigenereTransform(text, key, false);
}

function vigenereDecrypt(text, key) {
  return vigenereTransform(text, key, true);
}

function createEl(tag, attrs = {}, text = "") {
  const el = document.createElement(tag);
  Object.entries(attrs).forEach(([key, value]) => {
    if (key === "class") el.className = value;
    else el.setAttribute(key, value);
  });
  if (text) el.textContent = text;
  return el;
}

function buildRsaControls() {
  const row = createEl("div", { class: "action-row" });
  const keyBtn = createEl("button", { id: "rsaGenerate", type: "button", class: "ghost" }, "Generate RSA Keys");
  const saveBtn = createEl("button", { id: "rsaSave", type: "button", class: "ghost" }, "Save Keys Local");
  const loadBtn = createEl("button", { id: "rsaLoad", type: "button", class: "ghost" }, "Load Keys Local");
  const fpBtn = createEl("button", { id: "rsaFinger", type: "button", class: "ghost" }, "Show Fingerprint");
  row.append(keyBtn, saveBtn, loadBtn, fpBtn);

  const fp = createEl("p", { id: "rsaFingerprint", class: "meta" }, "Fingerprint: not calculated");

  const pubWrap = createEl("label");
  pubWrap.append("Public Key (PEM)");
  pubWrap.append(createEl("textarea", { id: "rsaPublicKey", placeholder: "Paste RSA public key" }));
  const privWrap = createEl("label");
  privWrap.append("Private Key (PEM)");
  privWrap.append(createEl("textarea", { id: "rsaPrivateKey", placeholder: "Paste RSA private key" }));

  controlsHost.append(row, fp, pubWrap, privWrap);

  keyBtn.addEventListener("click", async () => {
    try {
      const generated = await generateRsaKeyPair();
      document.getElementById("rsaPublicKey").value = generated.publicPem;
      document.getElementById("rsaPrivateKey").value = generated.privatePem;
      cryptoOutput.value = "Generated RSA key pair.";
    } catch (err) {
      cryptoOutput.value = `Key generation failed: ${err.message}`;
    }
  });

  saveBtn.addEventListener("click", () => {
    localStorage.setItem("ciphercanvas-rsa-public", document.getElementById("rsaPublicKey").value.trim());
    localStorage.setItem("ciphercanvas-rsa-private", document.getElementById("rsaPrivateKey").value.trim());
    cryptoOutput.value = "RSA keys saved in browser local storage.";
  });

  loadBtn.addEventListener("click", () => {
    document.getElementById("rsaPublicKey").value = localStorage.getItem("ciphercanvas-rsa-public") || "";
    document.getElementById("rsaPrivateKey").value = localStorage.getItem("ciphercanvas-rsa-private") || "";
    cryptoOutput.value = "Loaded RSA keys from browser local storage.";
  });

  fpBtn.addEventListener("click", async () => {
    const value = document.getElementById("rsaPublicKey").value.trim();
    if (!value) {
      cryptoOutput.value = "Provide public key first for fingerprint.";
      return;
    }
    const hash = await sha256Hex(value);
    fp.textContent = `Fingerprint: ${hash.slice(0, 16)}...${hash.slice(-16)}`;
  });
}

function buildEcdhControls() {
  const row = createEl("div", { class: "action-row" });
  const keyBtn = createEl("button", { id: "ecdhGenerate", type: "button", class: "ghost" }, "Generate ECDH Keys");
  const saveBtn = createEl("button", { id: "ecdhSave", type: "button", class: "ghost" }, "Save Keys Local");
  const loadBtn = createEl("button", { id: "ecdhLoad", type: "button", class: "ghost" }, "Load Keys Local");
  row.append(keyBtn, saveBtn, loadBtn);

  const pubWrap = createEl("label");
  pubWrap.append("Public Key (PEM)");
  pubWrap.append(createEl("textarea", { id: "ecdhPublicKey", placeholder: "Paste ECDH public key" }));
  const privWrap = createEl("label");
  privWrap.append("Private Key (PEM)");
  privWrap.append(createEl("textarea", { id: "ecdhPrivateKey", placeholder: "Paste ECDH private key" }));

  controlsHost.append(row, pubWrap, privWrap);

  keyBtn.addEventListener("click", async () => {
    try {
      const generated = await generateEcdhKeyPair();
      document.getElementById("ecdhPublicKey").value = generated.publicPem;
      document.getElementById("ecdhPrivateKey").value = generated.privatePem;
      cryptoOutput.value = "Generated ECDH key pair.";
    } catch (err) {
      cryptoOutput.value = `ECDH key generation failed: ${err.message}`;
    }
  });

  saveBtn.addEventListener("click", () => {
    localStorage.setItem("ciphercanvas-ecdh-public", document.getElementById("ecdhPublicKey").value.trim());
    localStorage.setItem("ciphercanvas-ecdh-private", document.getElementById("ecdhPrivateKey").value.trim());
    cryptoOutput.value = "ECDH keys saved in browser local storage.";
  });

  loadBtn.addEventListener("click", () => {
    document.getElementById("ecdhPublicKey").value = localStorage.getItem("ciphercanvas-ecdh-public") || "";
    document.getElementById("ecdhPrivateKey").value = localStorage.getItem("ciphercanvas-ecdh-private") || "";
    cryptoOutput.value = "Loaded ECDH keys from browser local storage.";
  });
}

function renderAlgoControls() {
  const algorithm = algorithmSelect.value;
  controlsHost.innerHTML = "";

  if (algorithm === "aes") {
    const wrapper = createEl("label");
    wrapper.append("Passphrase");
    wrapper.append(createEl("input", { id: "aesPassphrase", type: "password", placeholder: "Enter passphrase" }));
    controlsHost.append(wrapper);
    return;
  }

  if (algorithm === "rsa-hybrid") {
    buildRsaControls();
    return;
  }

  if (algorithm === "ecdh-hybrid") {
    buildEcdhControls();
    return;
  }

  if (algorithm === "caesar") {
    const wrapper = createEl("label");
    wrapper.append("Shift");
    wrapper.append(createEl("input", { id: "caesarShift", type: "number", value: "3" }));
    controlsHost.append(wrapper);
    return;
  }

  if (algorithm === "vigenere") {
    const wrapper = createEl("label");
    wrapper.append("Vigenere Key");
    wrapper.append(createEl("input", { id: "vigenereKey", type: "text", placeholder: "Example: ORANGE" }));
    controlsHost.append(wrapper);
  }
}

function setProgress(el, value) {
  el.value = Math.max(0, Math.min(100, value));
}

function setDownloadLink(linkEl, objectUrl, filename) {
  if (!objectUrl) {
    linkEl.classList.remove("ready");
    linkEl.removeAttribute("href");
    return;
  }
  linkEl.href = objectUrl;
  linkEl.download = filename;
  linkEl.classList.add("ready");
}

function cleanupObjectUrl(key) {
  if (state[key]) {
    URL.revokeObjectURL(state[key]);
    state[key] = null;
  }
}

function setPreview(imgEl, file, key) {
  if (state.previewUrls[key]) {
    URL.revokeObjectURL(state.previewUrls[key]);
    state.previewUrls[key] = null;
  }

  if (!file || !file.type.startsWith("image/")) {
    imgEl.classList.remove("ready");
    imgEl.removeAttribute("src");
    return;
  }

  const url = URL.createObjectURL(file);
  state.previewUrls[key] = url;
  imgEl.src = url;
  imgEl.classList.add("ready");
}

async function readFileAsArrayBuffer(file) {
  return file.arrayBuffer();
}

async function loadImageFromFile(file) {
  return new Promise((resolve, reject) => {
    const image = new Image();
    const objectUrl = URL.createObjectURL(file);
    image.onload = () => {
      URL.revokeObjectURL(objectUrl);
      resolve(image);
    };
    image.onerror = () => {
      URL.revokeObjectURL(objectUrl);
      reject(new Error("Could not load image."));
    };
    image.src = objectUrl;
  });
}

async function fileToImageData(file) {
  const image = await loadImageFromFile(file);
  const canvas = document.createElement("canvas");
  canvas.width = image.width;
  canvas.height = image.height;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(image, 0, 0);
  return {
    imageData: ctx.getImageData(0, 0, canvas.width, canvas.height),
    width: canvas.width,
    height: canvas.height,
  };
}

async function imageDataToPngBlob(imageData, width, height) {
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d");
  ctx.putImageData(imageData, 0, 0);
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (!blob) {
        reject(new Error("Could not create PNG blob."));
        return;
      }
      resolve(blob);
    }, "image/png");
  });
}

function estimateCarrierCapacityBytes(width, height) {
  const usableChannels = width * height * 3;
  return Math.floor(usableChannels / 8);
}

async function updateCapacityLabel(fileInput, labelEl) {
  const file = fileInput.files[0];
  if (!file) {
    labelEl.textContent = "Capacity: unknown";
    return;
  }

  const image = await loadImageFromFile(file);
  const cap = estimateCarrierCapacityBytes(image.width, image.height);
  labelEl.textContent = `Capacity: ${formatBytes(cap)} (${cap} bytes)`;
}

function packForEmbedding(payload) {
  const checksum = crc32(payload);
  return concatBytes([
    strToBytes(STEGO_MAGIC),
    new Uint8Array([STEGO_VERSION]),
    u32ToBytes(payload.length),
    u32ToBytes(checksum),
    payload,
  ]);
}

function embedBytesInImageData(imageData, packed) {
  const data = new Uint8ClampedArray(imageData.data);
  const maxBytes = estimateCarrierCapacityBytes(imageData.width, imageData.height);
  if (packed.length > maxBytes) {
    throw new Error(`Payload too large. Capacity ${maxBytes} bytes, got ${packed.length}.`);
  }

  let bitIndex = 0;
  for (let i = 0; i < data.length && bitIndex < packed.length * 8; i += 1) {
    if ((i + 1) % 4 === 0) continue;
    const byte = packed[Math.floor(bitIndex / 8)];
    const bit = (byte >> (7 - (bitIndex % 8))) & 1;
    data[i] = (data[i] & 0xfe) | bit;
    bitIndex += 1;
  }

  return new ImageData(data, imageData.width, imageData.height);
}

function extractBytesFromImageData(imageData) {
  const data = imageData.data;
  let pointer = 0;

  function readBit() {
    while (pointer < data.length && (pointer + 1) % 4 === 0) pointer += 1;
    if (pointer >= data.length) throw new Error("Unexpected end of image data while extracting.");
    const bit = data[pointer] & 1;
    pointer += 1;
    return bit;
  }

  function readByte() {
    let byte = 0;
    for (let i = 0; i < 8; i += 1) byte = (byte << 1) | readBit();
    return byte;
  }

  const magic = new Uint8Array([readByte(), readByte(), readByte(), readByte()]);
  if (bytesToStr(magic) !== STEGO_MAGIC) {
    throw new Error("No supported stego payload found. Decode from generated PNG output.");
  }

  const version = readByte();
  if (version !== STEGO_VERSION) {
    throw new Error(`Unsupported stego payload version: ${version}`);
  }

  const payloadLength = bytesToU32(new Uint8Array([readByte(), readByte(), readByte(), readByte()]));
  const checksum = bytesToU32(new Uint8Array([readByte(), readByte(), readByte(), readByte()]));
  if (payloadLength > estimateCarrierCapacityBytes(imageData.width, imageData.height)) {
    throw new Error("Corrupted payload length.");
  }

  const payload = new Uint8Array(payloadLength);
  for (let i = 0; i < payloadLength; i += 1) payload[i] = readByte();

  if (crc32(payload) !== checksum) {
    throw new Error("Payload checksum mismatch. Image may be modified or pass-through compressed.");
  }

  return payload;
}

function buildTextPayload(rawMessage, encrypted) {
  const data = strToBytes(rawMessage);
  const flags = new Uint8Array([encrypted ? 1 : 0]);
  return concatBytes([strToBytes("TXT2"), flags, u32ToBytes(data.length), data]);
}

function parseTextPayload(payload) {
  if (bytesToStr(payload.slice(0, 4)) !== "TXT2") throw new Error("Payload is not text-stego data.");
  const flags = payload[4];
  const dataLength = bytesToU32(payload, 5);
  const dataStart = 9;
  const dataEnd = dataStart + dataLength;
  if (dataEnd > payload.length) throw new Error("Corrupted text payload.");
  return { encrypted: Boolean(flags & 1), data: payload.slice(dataStart, dataEnd) };
}

function buildImagePayload(mime, dataBytes, encrypted) {
  const mimeBytes = strToBytes(mime);
  const flags = new Uint8Array([encrypted ? 1 : 0]);
  return concatBytes([
    strToBytes("IMG2"),
    flags,
    u16ToBytes(mimeBytes.length),
    u32ToBytes(dataBytes.length),
    mimeBytes,
    dataBytes,
  ]);
}

function parseImagePayload(payload) {
  if (bytesToStr(payload.slice(0, 4)) !== "IMG2") throw new Error("Payload is not image-stego data.");
  const flags = payload[4];
  const mimeLength = bytesToU16(payload, 5);
  const dataLength = bytesToU32(payload, 7);
  const mimeStart = 11;
  const mimeEnd = mimeStart + mimeLength;
  const dataStart = mimeEnd;
  const dataEnd = dataStart + dataLength;
  if (mimeLength < 1 || mimeLength > 128 || dataEnd > payload.length) throw new Error("Corrupted image payload.");
  return {
    encrypted: Boolean(flags & 1),
    mime: bytesToStr(payload.slice(mimeStart, mimeEnd)),
    data: payload.slice(dataStart, dataEnd),
  };
}

function downloadCryptoOutput() {
  cleanupObjectUrl("cryptoDownloadUrl");
  if (!cryptoOutput.value.trim()) {
    cryptoOutput.value = "Output empty. Run crypto first.";
    return;
  }
  const blob = new Blob([cryptoOutput.value], { type: "text/plain" });
  state.cryptoDownloadUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = state.cryptoDownloadUrl;
  anchor.download = "crypto-output.txt";
  anchor.click();
}

function setupDropForInput(inputEl, previewEl, previewKey, onFileSelected) {
  const label = inputEl.closest("label");
  if (!label) return;
  ["dragenter", "dragover"].forEach((event) => {
    label.addEventListener(event, (e) => {
      e.preventDefault();
      label.style.outline = "2px solid #0f766e";
    });
  });
  ["dragleave", "drop"].forEach((event) => {
    label.addEventListener(event, (e) => {
      e.preventDefault();
      label.style.outline = "none";
    });
  });
  label.addEventListener("drop", (e) => {
    const dt = e.dataTransfer;
    if (!dt || !dt.files || !dt.files.length) return;
    inputEl.files = dt.files;
    const file = dt.files[0];
    if (previewEl) setPreview(previewEl, file, previewKey);
    if (onFileSelected) onFileSelected();
  });
}

algorithmSelect.addEventListener("change", renderAlgoControls);
renderAlgoControls();

runCryptoBtn.addEventListener("click", async () => {
  const action = actionSelect.value;
  const algorithm = algorithmSelect.value;
  const input = cryptoInput.value;

  if (!input.trim()) {
    cryptoOutput.value = "Input is empty.";
    return;
  }

  try {
    if (algorithm === "aes") {
      const passphrase = document.getElementById("aesPassphrase").value;
      if (!passphrase) throw new Error("Passphrase is required for AES.");
      cryptoOutput.value = action === "encrypt"
        ? await encryptAesText(input, passphrase)
        : await decryptAesText(input, passphrase);
      return;
    }

    if (algorithm === "rsa-hybrid") {
      const publicKey = document.getElementById("rsaPublicKey").value.trim();
      const privateKey = document.getElementById("rsaPrivateKey").value.trim();
      if (action === "encrypt") {
        if (!publicKey) throw new Error("Public key is required for encryption.");
        cryptoOutput.value = await encryptRsaHybrid(input, publicKey);
      } else {
        if (!privateKey) throw new Error("Private key is required for decryption.");
        cryptoOutput.value = await decryptRsaHybrid(input, privateKey);
      }
      return;
    }

    if (algorithm === "ecdh-hybrid") {
      const publicKey = document.getElementById("ecdhPublicKey").value.trim();
      const privateKey = document.getElementById("ecdhPrivateKey").value.trim();
      if (action === "encrypt") {
        if (!publicKey) throw new Error("ECDH public key is required for encryption.");
        cryptoOutput.value = await encryptEcdhHybrid(input, publicKey);
      } else {
        if (!privateKey) throw new Error("ECDH private key is required for decryption.");
        cryptoOutput.value = await decryptEcdhHybrid(input, privateKey);
      }
      return;
    }

    if (algorithm === "caesar") {
      const shift = document.getElementById("caesarShift").value;
      cryptoOutput.value = action === "encrypt" ? caesarEncrypt(input, shift) : caesarDecrypt(input, shift);
      return;
    }

    if (algorithm === "vigenere") {
      const key = document.getElementById("vigenereKey").value;
      cryptoOutput.value = action === "encrypt" ? vigenereEncrypt(input, key) : vigenereDecrypt(input, key);
      return;
    }

    cryptoOutput.value = "Unsupported algorithm.";
  } catch (err) {
    cryptoOutput.value = `Error: ${err.message}`;
  }
});

clearCryptoBtn.addEventListener("click", () => {
  cryptoInput.value = "";
  cryptoOutput.value = "";
});

copyCryptoBtn.addEventListener("click", async () => {
  if (!cryptoOutput.value.trim()) return;
  await navigator.clipboard.writeText(cryptoOutput.value);
  cryptoOutput.value += "\n\n[Copied to clipboard]";
});

downloadCryptoBtn.addEventListener("click", downloadCryptoOutput);

encryptThenHideBtn.addEventListener("click", () => {
  if (!cryptoOutput.value.trim()) {
    textStatus.textContent = "Status: run encryption first in Crypto Lab.";
    return;
  }
  secretMessageInput.value = cryptoOutput.value;
  textStatus.textContent = "Status: encrypted output copied to Secret Message.";
});

extractThenLoadBtn.addEventListener("click", () => {
  if (!secretMessageInput.value.trim()) {
    textStatus.textContent = "Status: extract text first.";
    return;
  }
  cryptoInput.value = secretMessageInput.value;
  textStatus.textContent = "Status: extracted text loaded into Crypto Input.";
});

textCarrierInput.addEventListener("change", async () => {
  setPreview(textCarrierPreview, textCarrierInput.files[0], "textCarrier");
  await updateCapacityLabel(textCarrierInput, textCapacity);
});

textDecodeInput.addEventListener("change", () => {
  setPreview(textDecodePreview, textDecodeInput.files[0], "textDecode");
});

imageCarrierInput.addEventListener("change", async () => {
  setPreview(imageCarrierPreview, imageCarrierInput.files[0], "imageCarrier");
  await updateCapacityLabel(imageCarrierInput, imageCapacity);
});

secretImageInput.addEventListener("change", () => {
  setPreview(secretImagePreview, secretImageInput.files[0], "secretImage");
});

setupDropForInput(textCarrierInput, textCarrierPreview, "textCarrier", async () => {
  await updateCapacityLabel(textCarrierInput, textCapacity);
});
setupDropForInput(textDecodeInput, textDecodePreview, "textDecode");
setupDropForInput(imageCarrierInput, imageCarrierPreview, "imageCarrier", async () => {
  await updateCapacityLabel(imageCarrierInput, imageCapacity);
});
setupDropForInput(secretImageInput, secretImagePreview, "secretImage");
setupDropForInput(imageDecodeContainerInput, null, null);

hideTextBtn.addEventListener("click", async () => {
  cleanupObjectUrl("textStegoObjectUrl");
  setDownloadLink(textStegoDownload, null);
  setProgress(textProgress, 0);

  try {
    const carrier = textCarrierInput.files[0];
    if (!carrier) throw new Error("Choose a carrier image first.");
    if (carrier.type === "image/jpeg") {
      textStatus.textContent = "Status: warning - JPEG can damage hidden bits; output is forced to PNG.";
    }

    let message = secretMessageInput.value;
    if (!message.trim()) throw new Error("Secret message is empty.");

    const protect = textProtectInput.checked;
    const passphrase = textPassphraseInput.value;
    setProgress(textProgress, 20);

    if (protect) {
      if (!passphrase) throw new Error("Passphrase required when text protection is enabled.");
      message = await encryptAesText(message, passphrase);
    }

    const payload = buildTextPayload(message, protect);
    const packed = packForEmbedding(payload);
    setProgress(textProgress, 45);

    const { imageData, width, height } = await fileToImageData(carrier);
    const encoded = embedBytesInImageData(imageData, packed);
    setProgress(textProgress, 75);

    const blob = await imageDataToPngBlob(encoded, width, height);
    state.textStegoObjectUrl = URL.createObjectURL(blob);
    setDownloadLink(textStegoDownload, state.textStegoObjectUrl, "stego-text.png");
    setProgress(textProgress, 100);
    textStatus.textContent = `Status: text hidden successfully (${packed.length} bytes packed).`;
  } catch (err) {
    textStatus.textContent = `Status: error - ${err.message}`;
    setProgress(textProgress, 0);
  }
});

extractTextBtn.addEventListener("click", async () => {
  setProgress(textProgress, 0);
  try {
    const encodedImage = textDecodeInput.files[0];
    if (!encodedImage) throw new Error("Choose the encoded image for decoding.");

    const { imageData } = await fileToImageData(encodedImage);
    setProgress(textProgress, 25);
    const payload = extractBytesFromImageData(imageData);
    const parsed = parseTextPayload(payload);
    let message = bytesToStr(parsed.data);
    setProgress(textProgress, 65);

    if (parsed.encrypted) {
      const passphrase = textPassphraseInput.value;
      if (!passphrase) throw new Error("Passphrase is required to decrypt hidden text.");
      message = await decryptAesText(message, passphrase);
    }

    secretMessageInput.value = message;
    setProgress(textProgress, 100);
    textStatus.textContent = "Status: text extracted successfully.";
  } catch (err) {
    textStatus.textContent = `Status: error - ${err.message}`;
    setProgress(textProgress, 0);
  }
});

hideImageBtn.addEventListener("click", async () => {
  cleanupObjectUrl("imageStegoObjectUrl");
  setDownloadLink(imageStegoDownload, null);
  setProgress(imageProgress, 0);

  try {
    const carrier = imageCarrierInput.files[0];
    const secret = secretImageInput.files[0];
    if (!carrier || !secret) throw new Error("Choose both a carrier image and a secret image.");
    if (carrier.type === "image/jpeg") {
      imageStatus.textContent = "Status: warning - JPEG carrier may not preserve hidden bits; output is PNG.";
    }

    const protect = imageProtectInput.checked;
    const passphrase = imagePassphraseInput.value;

    let payloadMime = secret.type || "application/octet-stream";
    let payloadData = new Uint8Array(await readFileAsArrayBuffer(secret));
    setProgress(imageProgress, 20);

    if (protect) {
      if (!passphrase) throw new Error("Passphrase required when image protection is enabled.");
      const wrapped = JSON.stringify({ mime: payloadMime, data: bytesToBase64(payloadData) });
      const encryptedText = await encryptAesText(wrapped, passphrase);
      payloadMime = "application/aes-json";
      payloadData = strToBytes(encryptedText);
    }

    const payload = buildImagePayload(payloadMime, payloadData, protect);
    const packed = packForEmbedding(payload);
    setProgress(imageProgress, 50);

    const { imageData, width, height } = await fileToImageData(carrier);
    const encoded = embedBytesInImageData(imageData, packed);
    const blob = await imageDataToPngBlob(encoded, width, height);

    state.imageStegoObjectUrl = URL.createObjectURL(blob);
    setDownloadLink(imageStegoDownload, state.imageStegoObjectUrl, "stego-image.png");
    setProgress(imageProgress, 100);
    imageStatus.textContent = `Status: image hidden successfully (${packed.length} bytes packed).`;
  } catch (err) {
    imageStatus.textContent = `Status: error - ${err.message}`;
    setProgress(imageProgress, 0);
  }
});

extractImageBtn.addEventListener("click", async () => {
  cleanupObjectUrl("extractedImageObjectUrl");
  setDownloadLink(extractedImageDownload, null);
  setProgress(imageProgress, 0);

  try {
    const container = imageDecodeContainerInput.files[0];
    if (!container) throw new Error("Choose the encoded carrier image for extraction.");

    const { imageData } = await fileToImageData(container);
    setProgress(imageProgress, 30);

    const payload = extractBytesFromImageData(imageData);
    const parsed = parseImagePayload(payload);

    let mime = parsed.mime;
    let dataBytes = parsed.data;
    setProgress(imageProgress, 60);

    if (parsed.encrypted) {
      const passphrase = imagePassphraseInput.value;
      if (!passphrase) throw new Error("Passphrase is required to decrypt hidden image.");

      const decryptedJson = await decryptAesText(bytesToStr(parsed.data), passphrase);
      const wrapped = safeJsonParse(decryptedJson, "Decrypted image metadata");
      assertPayloadFields(wrapped, ["mime", "data"], "decrypted image metadata");
      mime = wrapped.mime;
      dataBytes = base64ToBytes(wrapped.data);
    }

    const blob = new Blob([dataBytes], { type: mime || "application/octet-stream" });
    state.extractedImageObjectUrl = URL.createObjectURL(blob);
    const extension = (mime && mime.includes("/")) ? mime.split("/")[1] : "bin";
    setDownloadLink(extractedImageDownload, state.extractedImageObjectUrl, `extracted-secret.${extension}`);

    setProgress(imageProgress, 100);
    imageStatus.textContent = "Status: secret image extracted successfully.";
  } catch (err) {
    imageStatus.textContent = `Status: error - ${err.message}`;
    setProgress(imageProgress, 0);
  }
});
