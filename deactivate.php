<?php
// eo/roll-in/deactivate.php
require_once __DIR__.'/config.php';

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type, X-API-Key');
header('Access-Control-Allow-Methods: POST, OPTIONS');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

// API key
$hdrKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
if ($hdrKey !== API_KEY) {
  http_response_code(401);
  echo json_encode(['ok'=>false,'error'=>'unauthorized']); exit;
}

$pdo = pdo();  // Obtener conexión (config.php define pdo())

// JSON
$body = file_get_contents('php://input');
$data = json_decode($body, true);
if (!is_array($data)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'invalid_json']); exit; }

$codeHex = strtoupper(trim($data['code_hex'] ?? ''));   // “A1B2C3D4E5”
if (!preg_match('/^[0-9A-F]{10}$/', $codeHex)) {
  http_response_code(422); echo json_encode(['ok'=>false,'error'=>'invalid_code_hex']); exit;
}

// opcional: si envías {"active":true} también sirve para reactivar
$active = isset($data['active']) ? (int)!!$data['active'] : 0;

try {
  $sql = "UPDATE whitelist_controls SET active=:active WHERE code=UNHEX(:code_hex) LIMIT 1";
  $st  = $pdo->prepare($sql);
  $st->execute([':active'=>$active, ':code_hex'=>$codeHex]);

  if ($st->rowCount() === 0) {
    echo json_encode(['ok'=>false,'error'=>'not_found']); exit;
  }
  echo json_encode(['ok'=>true,'active'=>$active]);
} catch (Throwable $e) {
  http_response_code(500);
  echo json_encode(['ok'=>false,'error'=>$e->getMessage()]);
}
