// Amostra vulneravel: DOM XSS e open redirect no navegador.
const firebaseConfig = { apiKey: "AIzaSyD-chave-de-exemplo-real" }; // achado: CWE-798

function mostrarBusca() {
  const termo = decodeURIComponent(location.hash.slice(1));
  document.getElementById("resultado").innerHTML = "Busca: " + termo; // achado: CWE-79
}

function boasVindas() {
  const params = new URLSearchParams(window.location.search);
  document.write("<p>Ola " + params.get("nome") + "</p>"); // achado: CWE-79
}

function voltar() {
  const destino = new URLSearchParams(location.search).get("volta");
  window.location.href = destino; // achado: CWE-601
}

$("#aviso").html(document.referrer); // achado: CWE-79
