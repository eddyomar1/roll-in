<?php

// codes.php
 
require __DIR__.'/config.php';
require_api_key();

$onlyActive = !isset($_GET['only_active']) || $_GET['only_active'] !== '0';

$sql = 'SELECT id,label,code,active,last_used_at,updated_at
        FROM whitelist_controls';
if ($onlyActive) $sql .= ' WHERE active = 1';
$sql .= ' ORDER BY id';

$rows = pdo()->query($sql)->fetchAll();

$codes = [];
$ctx = hash_init('sha256');
foreach ($rows as $r) {
  $hex = strtoupper(bin2hex($r['code'])); // 10 hex chars
  $codes[] = [
    'id'           => (int)$r['id'],
    'label'        => $r['label'],
    'code'         => $hex,
    'active'       => (bool)$r['active'],
    'last_used_at' => $r['last_used_at'],
  ];
  hash_update($ctx, $r['code']);          // dataset hash
}
$hash = hash_final($ctx);
$etag = '"'.substr($hash,0,32).'"';

if (isset($_SERVER['HTTP_IF_NONE_MATCH']) && $_SERVER['HTTP_IF_NONE_MATCH'] === $etag) {
  respond(null, 304, ['ETag'=>$etag, 'Cache-Control'=>'no-cache']);
}

respond([
  'ok'    => true,
  'count' => count($codes),
  'hash'  => $hash,
  'codes' => $codes,
], 200, ['ETag'=>$etag, 'Cache-Control'=>'no-cache']);
