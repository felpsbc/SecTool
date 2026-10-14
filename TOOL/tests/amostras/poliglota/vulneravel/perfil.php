<?php
// Amostra vulneravel: PHP puro com mysqli/PDO.
$DB_PASSWORD = "s3nh4-do-banco"; // achado: CWE-798
define('API_SECRET', 'chave-secreta-123'); // achado: CWE-798
$config = ['host' => 'db', 'password' => 'outra-senha']; // achado: CWE-798

$conn = mysqli_connect("db", "app", getenv("DB_PASS"));
$id = $_GET['id'];
$resultado = mysqli_query($conn, "SELECT * FROM usuarios WHERE id = " . $id); // achado: CWE-89

$pdo = new PDO($dsn, 'app', getenv('DB_PASS'));
$nome = $_POST['nome'];
$pdo->query("SELECT * FROM usuarios WHERE nome = '$nome'"); // achado: CWE-89

echo "<h1>Ola, " . $nome . "</h1>"; // achado: CWE-79

$pagina = $_GET['pagina'];
include $pagina . ".php"; // achado: CWE-22
$conteudo = file_get_contents("/srv/arquivos/" . $_GET['arquivo']); // achado: CWE-22

header("Location: " . $_GET['volta']); // achado: CWE-601

setcookie("sessao", $token); // achado: CWE-614, CWE-1004

$doc = simplexml_load_string($_POST['xml'], 'SimpleXMLElement', LIBXML_NOENT); // achado: CWE-611

function listar($filtro) {
    global $pdo;
    return $pdo->query("SELECT * FROM itens WHERE tipo = '$filtro'"); // limitacao: CWE-89 fluxo interprocedural
}
listar($_GET['tipo']);
?>
<p>Busca: <?= $_GET['q'] ?></p> <!-- achado: CWE-79 -->
