// Amostra vulneravel: API Express. Gabarito em comentario na linha do sink.
const express = require("express");
const fs = require("fs");
const path = require("path");
const mysql = require("mysql");

const app = express();
const db = mysql.createConnection({ host: "db", user: "app", password: "s3nh4-fixa" }); // achado: CWE-798
const JWT_SECRET = "segredo-do-jwt-123"; // achado: CWE-798
const DATABASE_URL = "postgres://app:s3nh4@db:5432/app"; // achado: CWE-798

app.get("/usuario", (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM usuarios WHERE id = " + id, (err, linhas) => { // achado: CWE-89
    res.json(linhas);
  });
});

app.post("/busca", async (req, res) => {
  const { termo, ordem } = req.body;
  const sql = `SELECT * FROM produtos WHERE nome LIKE '%${termo}%' ORDER BY ${ordem}`;
  const linhas = await db.query(sql); // achado: CWE-89
  res.send(`<h1>Resultados para ${termo}</h1>`); // achado: CWE-79
});

app.get("/arquivo", (req, res) => {
  const nome = req.params.nome;
  const caminho = path.join(__dirname, "uploads", nome);
  fs.readFile(caminho, (err, dados) => res.send(dados)); // achado: CWE-22
  res.sendFile(req.query.anexo); // achado: CWE-22
});

app.get("/sair", (req, res) => {
  res.redirect(req.query.next); // achado: CWE-601
});

app.get("/perfil", (req, res) => {
  const partes = [];
  partes.push("<p>");
  partes.push(req.query.bio);
  res.write(partes.join("")); // achado: CWE-79
});

app.get("/continuar", (req, res) => {
  const destino = req.query.destino;
  if (destino.length > 0) {
    res.redirect(destino); // achado: CWE-601
  }
});

// Fluxo interprocedural: o motor nao segue o dado para dentro de funcao do projeto.
function buscarPorNome(nome) {
  return db.query("SELECT * FROM usuarios WHERE nome = '" + nome + "'"); // limitacao: CWE-89 fluxo interprocedural
}

app.get("/nome", (req, res) => buscarPorNome(req.query.nome));
