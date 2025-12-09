<?php
// eo/roll-in/enroll.php
require_once __DIR__.'/config.php';   // define $pdo (PDO) y API_KEY

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type, X-API-Key');
header('Access-Control-Allow-Methods: POST, OPTIONS');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

// --- API key ---
$hdrKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
if ($hdrKey !== API_KEY) {
  http_response_code(401);
  echo json_encode(['ok'=>false,'error'=>'unauthorized']); exit;
}

$pdo = pdo();  // Obtener conexión (config.php define pdo())

// --- JSON body ---
$body = file_get_contents('php://input');
$data = json_decode($body, true);
if (!is_array($data)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'invalid_json']); exit; }

$label    = trim($data['label']    ?? '');
$codeHex  = strtoupper(trim($data['code_hex'] ?? ''));  // 10 hex chars
$active   = isset($data['active']) ? !!$data['active'] : true;

if ($label === '' || strlen($label) > 255) {
  http_response_code(422); echo json_encode(['ok'=>false,'error'=>'invalid_label']); exit;
}
if (!preg_match('/^[0-9A-F]{10}$/', $codeHex)) {
  http_response_code(422); echo json_encode(['ok'=>false,'error'=>'invalid_code_hex']); exit;
}

try {
  // Insertar siempre un registro nuevo (no se actualizan duplicados)
  $sql = "INSERT INTO whitelist_controls (label, code, active, last_used_at)
          VALUES (:label, UNHEX(:code_hex), :active, NULL)";
  $st  = $pdo->prepare($sql);
  $st->execute([
    ':label'    => $label,
    ':code_hex' => $codeHex,
    ':active'   => $active ? 1 : 0,
  ]);

  echo json_encode(['ok'=>true,'id'=>(int)$pdo->lastInsertId()]);
} catch (Throwable $e) {
  $msg = $e->getMessage();
  // Si hay constraint UNIQUE en code, retornamos error explícito
  if (strpos($msg, '1062') !== false) {
    http_response_code(409);
    echo json_encode(['ok'=>false,'error'=>'duplicate_code']);
  } else {
    http_response_code(500);
    echo json_encode(['ok'=>false,'error'=>$msg]);
  }
}
