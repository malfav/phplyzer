<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malicious PHP Analyzer Lab</title>
    <style>
        body {
            background-color: #2e2e2e;
            color: #e0e0e0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .container {
            width: 80%;
            margin: 0 auto;
            padding: 20px;
            background-color: #1c1c1c;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.5);
        }
        h1, h2, h3 {
            color: #ff9800;
        }
        input[type="file"] {
            margin: 20px 0;
            background-color: #333;
            border: 1px solid #555;
            color: #e0e0e0;
            padding: 10px;
            border-radius: 4px;
        }
        button {
            background-color: #444;
            border: none;
            color: #e0e0e0;
            padding: 10px 20px;
            cursor: pointer;
            border-radius: 4px;
            font-size: 16px;
        }
        button:hover {
            background-color: #555;
        }
        .result {
            margin-top: 20px;
            padding: 10px;
            background-color: #333;
            border-radius: 8px;
        }
        pre {
            background-color: #1c1c1c;
            padding: 10px;
            border-radius: 8px;
            color: #e0e0e0;
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        table, th, td {
            border: 1px solid #555;
        }
        th, td {
            padding: 10px;
            text-align: left;
        }
        th {
            background-color: #444;
        }
        .malicious {
            background-color: #ff4c4c;
            color: #fff;
        }
        .clean {
            background-color: #4caf50;
            color: #fff;
        }
        .suspicious {
            background-color: #ffeb3b;
            color: #000;
        }
        .decoded-content {
            display: none;
        }
        .decoded-content.visible {
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>PHP Analyzer LAB</h1>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file" accept=".php" required>
            <button type="submit">Scan File</button>
        </form>

        <?php
        function scanMaliciousCode($code) {
            $maliciousPatterns = [
                '/system\s*\(/i' => 'system() - Executes an external program',
                '/exec\s*\(/i' => 'exec() - Executes an external program',
                '/shell_exec\s*\(/i' => 'shell_exec() - Executes commands via shell',
                '/passthru\s*\(/i' => 'passthru() - Executes commands and outputs the raw result',
                '/eval\s*\(/i' => 'eval() - Executes a string as PHP code',
                '/assert\s*\(/i' => 'assert() - Evaluates a string as PHP code',
                '/base64_decode\s*\(/i' => 'base64_decode() - Decodes a base64 encoded string',
                '/gzinflate\s*\(/i' => 'gzinflate() - Inflates a deflated string',
                '/gzuncompress\s*\(/i' => 'gzuncompress() - Uncompresses a gzipped string',
                '/str_rot13\s*\(/i' => 'str_rot13() - Performs ROT13 encoding',
                '/file_get_contents\s*\(/i' => 'file_get_contents() - Reads file into a string',
                '/fopen\s*\(/i' => 'fopen() - Opens a file or URL',
                '/fwrite\s*\(/i' => 'fwrite() - Writes to a file',
                '/include\s*\(/i' => 'include() - Includes and evaluates a specified file',
                '/require\s*\(/i' => 'require() - Includes and evaluates a specified file',
                '/curl_exec\s*\(/i' => 'curl_exec() - Executes a cURL session',
                '/mysql_query\s*\(/i' => 'mysql_query() - Executes a MySQL query',
                '/mysqli_query\s*\(/i' => 'mysqli_query() - Executes a MySQLi query',
                '/highlight_file\s*\(/i' => 'highlight_file() - Syntax highlights a file',
                '/ob_start\s*\(/i' => 'ob_start() - Turns on output buffering',
                '/ob_get_clean\s*\(/i' => 'ob_get_clean() - Gets the contents of the output buffer and deletes the buffer',
                '/proc_open\s*\(/i' => 'proc_open() - Executes a command and opens file pointers for input/output',
                '/popen\s*\(/i' => 'popen() - Opens a pipe to a process',
                '/socket_create\s*\(/i' => 'socket_create() - Creates a socket',
                '/stream_socket_client\s*\(/i' => 'stream_socket_client() - Opens a client-side socket connection',
                '/mail\s*\(/i' => 'mail() - Sends an email',
                '/chmod\s*\(/i' => 'chmod() - Changes file mode',
                '/chown\s*\(/i' => 'chown() - Changes file owner',
                '/unlink\s*\(/i' => 'unlink() - Deletes a file',
                '/touch\s*\(/i' => 'touch() - Sets file access time and modification time',
                '/system_exec\s*\(/i' => 'system_exec() - Executes a system command',
                '/exec_cmd\s*\(/i' => 'exec_cmd() - Executes a command',
                '/shell\s*\(/i' => 'shell() - Executes shell commands',
                '/passthru_command\s*\(/i' => 'passthru_command() - Executes a command and outputs raw result',
                '/eval_string\s*\(/i' => 'eval_string() - Executes a string as PHP code',
                '/assert_code\s*\(/i' => 'assert_code() - Evaluates code as PHP',
                '/decode_base64\s*\(/i' => 'decode_base64() - Decodes base64 encoded string',
                '/decompress_gzinflate\s*\(/i' => 'decompress_gzinflate() - Decompresses gzinflate data',
                '/decompress_gzuncompress\s*\(/i' => 'decompress_gzuncompress() - Decompresses gzuncompress data',
                '/rot13_string\s*\(/i' => 'rot13_string() - Applies ROT13 encoding',
                '/read_file\s*\(/i' => 'read_file() - Reads a file',
                '/open_file\s*\(/i' => 'open_file() - Opens a file',
                '/write_file\s*\(/i' => 'write_file() - Writes to a file',
                '/include_file\s*\(/i' => 'include_file() - Includes a file',
                '/require_file\s*\(/i' => 'require_file() - Requires a file',
                '/execute_curl\s*\(/i' => 'execute_curl() - Executes a cURL session',
                '/query_mysql\s*\(/i' => 'query_mysql() - Executes a MySQL query',
                '/query_mysqli\s*\(/i' => 'query_mysqli() - Executes a MySQLi query',
                '/highlight_php\s*\(/i' => 'highlight_php() - Highlights PHP code',
                '/start_output_buffering\s*\(/i' => 'start_output_buffering() - Starts output buffering',
                '/clean_output_buffer\s*\(/i' => 'clean_output_buffer() - Clears output buffer',
                '/open_process\s*\(/i' => 'open_process() - Opens a process',
                '/popen_cmd\s*\(/i' => 'popen_cmd() - Opens a pipe to a process',
                '/create_socket\s*\(/i' => 'create_socket() - Creates a socket',
                '/connect_socket\s*\(/i' => 'connect_socket() - Connects to a socket',
                '/send_email\s*\(/i' => 'send_email() - Sends an email',
                '/change_file_mode\s*\(/i' => 'change_file_mode() - Changes file mode',
                '/change_file_owner\s*\(/i' => 'change_file_owner() - Changes file owner',
                '/delete_file\s*\(/i' => 'delete_file() - Deletes a file',
                '/set_file_time\s*\(/i' => 'set_file_time() - Sets file time',
            ];

            $result = [];
            foreach ($maliciousPatterns as $pattern => $description) {
                if (preg_match_all($pattern, $code, $matches, PREG_OFFSET_CAPTURE)) {
                    foreach ($matches[0] as $match) {
                        $line = substr_count(substr($code, 0, $match[1]), "\n") + 1;
                        $result[] = ['keyword' => $match[0], 'description' => $description, 'line' => $line];
                    }
                }
            }
            return $result;
        }

        function getVirusTotalReport($filePath) {
            $apiKey = 'Your_API_KEY';
            $apiKey = 'Your_API_KEY';
            $fileContent = file_get_contents($filePath);
            $fileHash = hash('sha256', $fileContent);
            
            $url = "https://www.virustotal.com/api/v3/files/{$fileHash}";
            $headers = [
                "x-apikey: $apiKey"
            ];
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            $response = curl_exec($ch);
            curl_close($ch);

            if (!$response) {
                return ['error' => 'Unable to fetch VirusTotal report.'];
            }

            return json_decode($response, true);
        }

        function displayVirusTotalResult($report) {
            if (isset($report['error'])) {
                echo '<div class="result"><p>Error: ' . htmlspecialchars($report['error']) . '</p></div>';
                return;
            }

            $attributes = [
                'malicious' => 0,
                'suspicious' => 0,
                'clean' => 0
            ];

            if (isset($report['data']['attributes']['last_analysis_stats'])) {
                $stats = $report['data']['attributes']['last_analysis_stats'];
                $attributes['malicious'] = $stats['malicious'];
                $attributes['suspicious'] = $stats['suspicious'];
                $attributes['clean'] = $stats['undetected'];
            }

            echo '<div class="result">';
            echo '<h2>VirusTotal Scan Results</h2>';
            echo '<table>';
            echo '<thead><tr><th>Status</th><th>Count</th></tr></thead>';
            echo '<tbody>';
            foreach ($attributes as $status => $count) {
                $class = $status == 'malicious' ? 'malicious' : ($status == 'suspicious' ? 'suspicious' : 'clean');
                echo "<tr class=\"$class\"><td>" . ucfirst($status) . "</td><td>$count</td></tr>";
            }
            echo '</tbody></table>';
            echo '</div>';
        }

        function decodeContent($content) {
            $decoded = [];
            // Base64
            if (preg_match_all('/base64_decode\s*\(\s*["\'](.*?)["\']\s*\)/i', $content, $matches)) {
                foreach ($matches[1] as $encoded) {
                    $decoded['Base64'][] = base64_decode($encoded);
                }
            }
            // ROT13
            if (preg_match_all('/str_rot13\s*\(\s*["\'](.*?)["\']\s*\)/i', $content, $matches)) {
                foreach ($matches[1] as $encoded) {
                    $decoded['ROT13'][] = str_rot13($encoded);
                }
            }
            return $decoded;
        }

        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
            $file = $_FILES['file'];
            if ($file['error'] === UPLOAD_ERR_OK) {
                $filePath = $file['tmp_name'];
                $fileContent = file_get_contents($filePath);
                $maliciousCode = scanMaliciousCode($fileContent);
                $decodedContent = decodeContent($fileContent);

                echo '<div class="result">';
                echo '<h2>Malicious Keywords Detected</h2>';
                if (!empty($maliciousCode)) {
                    echo '<table>';
                    echo '<thead><tr><th>Keyword</th><th>Description</th><th>Line</th></tr></thead>';
                    echo '<tbody>';
                    foreach ($maliciousCode as $code) {
                        echo '<tr class="malicious"><td>' . htmlspecialchars($code['keyword']) . '</td><td>' . htmlspecialchars($code['description']) . '</td><td>' . htmlspecialchars($code['line']) . '</td></tr>';
                    }
                    echo '</tbody></table>';
                } else {
                    echo '<p>No malicious code detected.</p>';
                }
                echo '</div>';

                $report = getVirusTotalReport($filePath);
                displayVirusTotalResult($report);

                if (!empty($decodedContent)) {
                    echo '<div class="result decoded-content visible">';
                    echo '<h2>Decoded Content</h2>';
                    foreach ($decodedContent as $type => $contents) {
                        echo '<h3>' . htmlspecialchars($type) . '</h3>';
                        echo '<ul>';
                        foreach ($contents as $content) {
                            echo '<li><pre>' . htmlspecialchars($content) . '</pre></li>';
                        }
                        echo '</ul>';
                    }
                    echo '</div>';
                }
            } else {
                echo '<div class="result"><p>Error uploading file. Please try again.</p></div>';
            }
        }
        ?>
    </div>
</body>
</html>
