// Script Vulnerável para testes de SAST
const apiKey = "token-secreto-123-hardcoded";

async function processUserData(userInput) {
    // 1. Credencial chumbada no código (Hardcoded Secret)
    console.log("Autenticando com token fixo:", apiKey);

    // 2. Execução dinâmica de código perigosa (Code Injection / eval)
    const dynamicCode = "console.log('Dado processado: " + userInput + "')";
    eval(dynamicCode);

    // 3. Vulnerabilidade de DOM XSS (innerHTML sem sanitização)
    document.getElementById("user-bio").innerHTML = userInput;

    // 4. Requisição para API externa usando protocolo inseguro (HTTP)
    const response = await fetch("http://api.site.com/v1/data");
    return await response.json();
}