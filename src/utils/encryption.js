const crypto = require("crypto");

const algorithm = "aes-128-cbc";
const BLOCK_SIZE = 16; // AES-128 block size

// Fungsi untuk menambahkan PKCS7 padding
function addPadding(text) {
  const pad = BLOCK_SIZE - (text.length % BLOCK_SIZE);
  const padBuffer = Buffer.alloc(pad, pad);
  return Buffer.concat([Buffer.from(text), padBuffer]);
}

// Fungsi untuk menghapus PKCS7 padding
function removePadding(buffer) {
  const padLength = buffer[buffer.length - 1];
  return buffer.slice(0, buffer.length - padLength);
}

exports.encrypt = (text, key) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);

  // Tambahkan padding ke text
  const paddedText = addPadding(text);

  // Encrypt dengan padding
  let encrypted = cipher.update(paddedText);
  encrypted = Buffer.concat([encrypted, cipher.final()]);

  return iv.toString("hex") + ":" + encrypted.toString("hex");
};

exports.decrypt = (text, key) => {
  const [ivHex, encryptedHex] = text.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const encrypted = Buffer.from(encryptedHex, "hex");

  const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), iv);
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  // Hapus padding dari hasil dekripsi
  const unpadded = removePadding(decrypted);

  return unpadded.toString();
};
