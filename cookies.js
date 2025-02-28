const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();
app.use(cookieParser());

const algorithm = 'aes-256-cbc';
const key = crypto.randomBytes(32); // Store this securely!
const iv = crypto.randomBytes(16);

function encrypt(text) {
  let cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
}

function decrypt(text) {
  let iv = Buffer.from(text.iv, 'hex');
  let encryptedText = Buffer.from(text.encryptedData, 'hex');
  let decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

app.get('/set-cookie', (req, res) => {
  const data = JSON.stringify({ user_id: 12345 });
  const encrypted = encrypt(data);
  res.cookie('user_data', encrypted, { httpOnly: true, secure: true, sameSite: 'strict' });
  res.send('Cookie set!');
});

app.get('/get-cookie', (req, res) => {
  const encrypted = req.cookies.user_data;
  const decrypted = decrypt(encrypted);
  res.send(`Decrypted data: ${decrypted}`);
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));