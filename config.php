<?php declare(strict_types=1);

// config.php



// ---------- AJUSTA ESTO ----------
const DB_HOST = 'localhost';
const DB_NAME = 'u138076177_pw';
const DB_USER = 'u138076177_chacharito';
const DB_PASS = '3spWifiPruev@';


const API_KEY = 'ColocaUnSecretoLargo';     // Header: X-API-Key
// ----------------------------------

// JSON + CORS básico
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type, X-API-Key');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

function pdo(): PDO {
  static $pdo = null;
  if ($pdo) return $pdo;
  $dsn = 'mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4';
  $pdo = new PDO($dsn, DB_USER, DB_PASS, [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
  ]);
  return $pdo;
}

function require_api_key(): void {
  $key = $_SERVER['HTTP_X_API_KEY'] ?? '';
  if ($key !== API_KEY) {
    http_response_code(401);
    echo json_encode(['ok'=>false,'error'=>'unauthorized']);
    exit;
  }
}

function respond($data, int $status=200, array $headers=[]): void {
  http_response_code($status);
  foreach ($headers as $k=>$v) header("$k: $v");
  echo json_encode($data, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
  exit;
}
