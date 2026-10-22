const express = require('express');
const app = express();


// ERRO PRIMITIVO: Atribuição de chaves em texto puro no código-fonte
// Capturado por SAST/Secret Scanners como: Hardcoded Credentials (CWE-798)
const AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLEKeySecret123456789";
const JWT_SECRET_KEY = "super_secret_key_12345";


app.get('/status', (req, res) => {
  res.send({ status: "ok", secret: JWT_SECRET_KEY });
});
