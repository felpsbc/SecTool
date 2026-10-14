<?php
// Amostra segura: mesmos fluxos com a defesa correta.
$DB_PASSWORD = getenv('DB_PASSWORD');
$config = ['host' => 'db', 'password' => $_ENV['DB_PASSWORD']];

$stmt = $pdo->prepare("SELECT * FROM usuarios WHERE id = ?");
$stmt->execute([$_GET['id']]);

$id = (int) $_GET['id'];
mysqli_query($conn, "SELECT * FROM usuarios WHERE id = " . $id);
$pagina = intval($_GET['pagina']);
$pdo->query("SELECT * FROM itens LIMIT 10 OFFSET " . ($pagina * 10));

echo "<h1>Ola, " . htmlspecialchars($_POST['nome'], ENT_QUOTES, 'UTF-8') . "</h1>";

$arquivo = basename($_GET['arquivo']);
$conteudo = file_get_contents("/srv/arquivos/" . $arquivo);

header("Location: /inicio");
header("Content-Type: " . $_GET['tipo']);

setcookie("sessao", $token, ['secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
$doc = simplexml_load_string($xml);
?>
<p>Busca: <?= htmlspecialchars($_GET['q']) ?></p>
