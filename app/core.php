<?php

if(file_exists(__DIR__ . '/debug_mode')) {
    error_reporting(E_ALL);
    ini_set('display_errors', 'On');
    ini_set('display_startup_errors', 'On');
}

use \Slim\Http\Request as Request;
use \Slim\Http\Response as Response;

require 'vendor/autoload.php';

session_cache_limiter(false);
session_start();

// Create and configure slim app
$config = ['settings' => [
    'addContentLengthHeader' => false,
    'displayErrorDetails' => true,
    'debug' => true,
    'log' => [
        'name' => 'api.insecurity.com',
        'level' => Monolog\Logger::DEBUG,
        'path' => __DIR__ . '/logs/app.log',
    ],
    'db' => [
        'host' => 'localhost',
        'dbname' => 'InSecurity',
        'user' => 'api',
        'pass' => 'password'
    ],
]];

$app = new \Slim\App($config);

$container = $app->getContainer();

// Setup Monolog
$container['log'] = function($c) {
    $log = new \Monolog\Logger($c['settings']['log']['name']);
    $fileHandler = new \Monolog\Handler\StreamHandler($c['settings']['log']['path'], $c['settings']['log']['level']);
    $log->pushHandler($fileHandler);
    return $log;
};

// Setup Database Connection
$container['db'] = function ($c) {
    $settings = $c->get('settings')['db'];
    $pdo = new PDO('mysql:host=' . $settings['host'] . ';dbname=' . $settings['dbname'],
        $settings['user'], $settings['pass']);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    return $pdo;
};

# Middleware to easily capture request ip address
$app->add(new RKA\Middleware\IpAddress(false));


$app->get('/', function(Request $request, Response $response) {
    return $response->withRedirect('http://docs.insecurityapi.apiary.io/');
})->setName('index');


$app->group('/Scanner', function () use ($app) {

    $app->post('/Scan', function(Request $request, Response $response) {

        $data = $request->getParsedBody();

        // Validate request
        if( isset($data['scanType'])
            &&
            (
                $data['scanType'] == 'Complete'
                ||
                $data['scanType'] == 'Discovery'
                ||
                $data['scanType'] == 'Vulnerability'
                ||
                ($data['scanType'] == 'Targeted' && isset($data['devices']) && is_array($data['devices']))
            )
        ) {
            // Create new scan entry in db
            $stmt = $this->db->prepare('INSERT INTO `Scan` (`scanType`, `creator`) VALUES (:scanType, :creator);');
            $stmt->execute([
                ':scanType' => $data['scanType'],
                ':creator' => $request->getAttribute('ip_address')
            ]);

            $scan_id = $this->db->lastInsertId();

            // TODO: Insert into devices table for targeted scans (if supported at a later date)

            // Fire and forget scanner
            $cmd = 'python3 ' . __DIR__ . '/../scanner/scanner.py ' . $scan_id;
            system("$cmd 2>&1 | while IFS= read -r line; do echo \"\$(date -u) \$line\"; done >> " . __DIR__ . '/logs/scanner.log');

            // Inform user the request has been successfully created
            return $response->withJson(['id' => $scan_id], 201);
        }
        else {
            // If type is Targeted, error caused by missing devices, otherwise it must be an invalid scan type
            if($data['scanType'] == 'Targeted')
                $err_msg = 'Targeted Scans require a list of device ips';
            else
                $err_msg = 'Invalid Scan Type';

            return $response->withJson($err_msg, 400);
        }

    })->setName('scan');


    $app->get('/History', function(Request $request, Response $response) {

    })->setName('history');

});


$app->group('/Scan', function () use ($app) {

    $app->get('/{id}/Status', function (Request $request, Response $response, $args) {
        // $request->getAttribute('id');
        // $args['since']
    })->setName('status');


    $app->get('/{id}/Report', function (Request $request, Response $response) {
        // $request->getAttribute('id');
    })->setName('report');

});


// Github webhook proxy (for deployment hooks)
$app->post('/update/{project}', function (Request $request, Response $response, $args) {

    $data = $request->getParsedBody();

    $cmd = escapeshellcmd(__DIR__ . '/get_updates.sh ' . $request->getAttribute('project'));

    // Run the command and log output with timestamps
    system("$cmd 2>&1 | while IFS= read -r line; do echo \"\$(date -u) \$line\"; done >> " . __DIR__ . '/logs/update.log');

})->setName('update');


$app->run();
