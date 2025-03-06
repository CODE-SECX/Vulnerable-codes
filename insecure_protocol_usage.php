<?php
// Fetching data from an insecure HTTP URL
$url = "http://example.com/api/data";
$response = file_get_contents($url);
echo $response;

// cURL request using an insecure HTTP URL
$ch = curl_init("http://example.com/api/data");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$data = curl_exec($ch);
curl_close($ch);
echo $data;

// Redirecting users to an insecure HTTP URL
header("Location: http://example.com/login");

// Hardcoded HTTP links in HTML output
echo '<a href="http://example.com">Click Here</a>';

// Using HTTP for API endpoints
$api_url = "http://api.example.com/v1/users";
$result = file_get_contents($api_url);
?>
