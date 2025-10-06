<?php
require __DIR__.'/config.php';
require_api_key();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  respond(['ok'=>false,'error'=>'method_not_allowed'], 405, ['Allow'=>'POST']);
}

$raw  = file_get_contents('php://input');
$data = json_decode($raw, true);
if (!is_array($data)) respond(['ok'=>false,'error'=>'invalid_json'], 400);

$door      = trim((string)($data['door'] ?? 'unknown'));
$timestamp = trim((string)($data['timestamp'] ?? '')); // opcional
$deviceId  = trim((string)($data['device_id'] ?? ''));

$controlId = isset($data['control_id']) ? (int)$data['control_id'] : 0;
$codeHex   = isset($data['code']) ? strtoupper(preg_replace('/[^0-9A-F]/','',$data['code'])) : '';
$label     = isset($data['label']) ? trim((string)$data['label']) : '';

$pdo = pdo();

// Resolver control_id
if ($controlId > 0) {
  $st = $pdo->prepare('SELECT id FROM whitelist_controls WHERE id=? AND active=1');
  $st->execute([$controlId]);
  if (!$st->fetch()) respond(['ok'=>false,'error'=>'unknown_control'],404);
} elseif ($codeHex !== '') {
  if (strlen($codeHex) !== 10) respond(['ok'=>false,'error'=>'code_hex_length'],422);
  $bin = hex2bin($codeHex);
  $st = $pdo->prepare('SELECT id FROM whitelist_controls WHERE code=? AND active=1');
  $st->execute([$bin]);
  $row = $st->fetch();
  if (!$row) respond(['ok'=>false,'error'=>'code_not_found_or_inactive'],404);
  $controlId = (int)$row['id'];
} elseif ($label !== '') {
  $st = $pdo->prepare('SELECT id FROM whitelist_controls WHERE label=? AND active=1');
  $st->execute([$label]);
  $row = $st->fetch();
  if (!$row) respond(['ok'=>false,'error'=>'label_not_found'],404);
  $controlId = (int)$row['id'];
} else {
  respond(['ok'=>false,'error'=>'missing_control_identifier'],422);
}

$pdo->beginTransaction();
try {
  // Insertar actividad
  $st = $pdo->prepare(
    'INSERT INTO control_activity (control_id, door, used_at) VALUES (?, ?, COALESCE(?, CURRENT_TIMESTAMP))'
  );
  $usedAt = $timestamp ?: null;
  $st->execute([$controlId, $door, $usedAt]);
  $activityId = (int)$pdo->lastInsertId();

  // Actualizar last_used_at
  $st = $pdo->prepare('UPDATE whitelist_controls SET last_used_at = COALESCE(?, CURRENT_TIMESTAMP) WHERE id=?');
  $st->execute([$usedAt, $controlId]);

  $pdo->commit();
  respond(['ok'=>true, 'activity_id'=>$activityId, 'control_id'=>$controlId]);
} catch (Throwable $e) {
  $pdo->rollBack();
  respond(['ok'=>false, 'error'=>'db_error', 'detail'=>$e->getMessage()], 500);
}
