// Amostra segura: mesmos fluxos da vulneravel, com a defesa correta.
const express = require("express");
const fs = require("fs");
const path = require("path");
const escapeHtml = require("escape-html");

const app = express();
const db = mysql.createConnection({ host: "db", user: "app", password: process.env.DB_PASSWORD });
const JWT_SECRET = process.env.JWT_SECRET;
const API_KEY = "<sua-chave-aqui>";

app.get("/usuario", (req, res) => {
  db.query("SELECT * FROM usuarios WHERE id = ?", [req.query.id], (err, linhas) => {
    res.json(linhas);
  });
});

app.get("/pagina", (req, res) => {
  const pagina = parseInt(req.query.pagina, 10);
  db.query(`SELECT * FROM produtos LIMIT 10 OFFSET ${pagina * 10}`);
  res.send("<h1>" + escapeHtml(req.query.titulo) + "</h1>");
});

app.get("/arquivo", (req, res) => {
  const nome = path.basename(req.params.nome);
  fs.readFile(path.join(__dirname, "uploads", nome), (err, dados) => res.send(dados));
});

app.get("/sair", (req, res) => {
  res.redirect("/login");
});

function render(dados) {
  document.getElementById("saida").textContent = location.hash;
  document.getElementById("lista").innerHTML = DOMPurify.sanitize(dados);
}
