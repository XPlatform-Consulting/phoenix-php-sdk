<?php

namespace mediasilo\http;

use mediasilo\config\Meta as META;
use mediasilo\http\HttpResponseHandler;

class WebClient {

    private $username;

    private $password;

    private $host;

    private $useSession;

    private $sessionKey;

    private $httpResponseHandler;

    private $baseUrl;

    public static function init($baseUrl) {
        $instance = new self();
        $instance->baseUrl = $baseUrl;
        $instance->httpResponseHandler = new HttpResponseHandler();

        return $instance;
    }

    public static function createFromHostCredentials($username, $password, $host, $baseUrl) {
        $instance = WebClient::init($baseUrl);
        $instance->username = $username;
        $instance->password = $password;
        $instance->host = $host;
        $instance->useSession = false;

        return $instance;
    }

    public static function createFromSession($session, $host, $baseUrl) {
        $instance = WebClient::init($baseUrl);
        $instance->host = $host;
        $instance->sessionKey = $session;
        $instance->useSession = true;

        return $instance;
    }

    public function get($path) {
        $curl = curl_init();

        curl_setopt_array($curl, array(
            CURLOPT_TIMEOUT => 20,
            CURLOPT_HTTPHEADER => $this->getRequestHeaders(),
            CURLOPT_RETURNTRANSFER => 1,
            CURLOPT_HEADER => 1,
            CURLOPT_URL => (rtrim($this->baseUrl, "/")."/".rtrim(ltrim($path, "/"))),
            CURLOPT_USERAGENT => $this->host.":".$this->username." PHP SDK Version ".META::MEDIASILO_SDK_VERSION
        ));

        $result = curl_exec($curl);

        $this->httpResponseHandler->handle($result, curl_getinfo($curl, CURLINFO_HTTP_CODE));

        $header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
        $http_status_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);

        $headers_raw = substr($result, 0, $header_size);
        $headers = $this->parseResponseHeaders($headers_raw);
        $body = substr($result, $header_size);

        return new WebClientResponse($body, $headers, $http_status_code);
    }

    public function post($path, $payload) {
        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_TIMEOUT => 20,
            CURLOPT_HTTPHEADER => $this->getRequestHeaders(),
            CURLOPT_POST => 1,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_RETURNTRANSFER => 1,
            CURLOPT_URL => (rtrim($this->baseUrl, "/")."/".rtrim(ltrim($path, "/"))),
            CURLOPT_USERAGENT => $this->host.":".$this->username." PHP SDK Version ".META::MEDIASILO_SDK_VERSION
        ));

        $result = curl_exec($curl);

        $this->httpResponseHandler->handle($result, curl_getinfo($curl, CURLINFO_HTTP_CODE));

        curl_close($curl);

        return $result;
    }

    public function put($path, $payload) {
        $fp = fopen('php://temp/maxmemory:256000', 'w');
        if (!$fp) {
            die('could not open temp memory data');
        }
        fwrite($fp, $payload);
        fseek($fp, 0);

        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_HTTPHEADER => $this->getRequestHeaders(),
            CURLOPT_PUT => 1,
            CURLOPT_BINARYTRANSFER => true,
            CURLOPT_INFILE => $fp,
            CURLOPT_INFILESIZE, strlen($payload),
            CURLOPT_RETURNTRANSFER => 1,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_URL => (rtrim($this->baseUrl, "/")."/".rtrim(ltrim($path, "/"))),
            CURLOPT_USERAGENT => $this->host.":".$this->username." PHP SDK Version ".META::MEDIASILO_SDK_VERSION
        ));

        $result = curl_exec($curl);

        $this->httpResponseHandler->handle($result, curl_getinfo($curl, CURLINFO_HTTP_CODE));

        curl_close($curl);
    }

    public function delete($path) {
        $curl = curl_init();

        curl_setopt_array($curl, array(
            CURLOPT_TIMEOUT => 20,
            CURLOPT_HTTPHEADER => $this->getRequestHeaders($isDelete = true),
            CURLOPT_CUSTOMREQUEST => "DELETE",
            CURLOPT_RETURNTRANSFER => 1,
            CURLOPT_URL => (rtrim($this->baseUrl, "/")."/".rtrim(ltrim($path, "/"))),
            CURLOPT_USERAGENT => $this->host.":".$this->username." PHP SDK Version ".META::MEDIASILO_SDK_VERSION
        ));

        $result = curl_exec($curl);

        $this->httpResponseHandler->handle($result, curl_getinfo($curl, CURLINFO_HTTP_CODE));

        curl_close($curl);

        return $result;
    }

    private function getRequestHeaders($isDelete = false) {
        
        if($isDelete){
            // Bug with mediasilo - not deleting asset because of that header! 
            $headers = array(/*"Content-Type: application/json; charset=utf-8",*/"Accept: application/json, text/plain");
        } else {
            $headers = array("Content-Type: application/json; charset=utf-8","Accept: application/json, text/plain");
        }
        $hostHeader = "MediaSiloHostContext:".$this->host;
        array_push($headers, $hostHeader);
        if ($this->useSession) {
            $sessionHeader = "MediaSiloSessionKey:".$this->sessionKey;
            array_push($headers, $sessionHeader);
        } else {
            $authHeader = "Authorization: Basic ".base64_encode($this->username.":".$this->password);
            array_push($headers, $authHeader);
        }

        // pass through cookies
        $cookieHeader = "Cookie: ";
        $delim = "";
        foreach ($_COOKIE as $key => $val) {
            $cookieHeader = $cookieHeader . $delim . $key . "=" . $val;
            $delim = "; ";
        }
        array_push($headers, $cookieHeader);

        // pass through our nonce header if it's sent
        if(function_exists('apache_request_headers')){
            $sentHeaders = \apache_request_headers();
            $n1 = isset($sentHeaders["n1"]) ? $sentHeaders["n1"] : false ;
            if (isset($n1) && strlen($n1) > 0) {
                array_push($headers, "n1: " . $n1);
            }
        }
        return $headers;
    }

    private function parseResponseHeaders($headers_raw) {
        $headers = explode("\r\n", $headers_raw);
        $returnedHeaders = Array();
        for ($i=0;$i<count($headers); $i++) {
            if (strlen($headers[$i]) > 0) {
                array_push($returnedHeaders, $headers[$i]);
            }
        }
        return $returnedHeaders;
    }
}
