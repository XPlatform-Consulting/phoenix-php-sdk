<?php

namespace mediasilo;

use mediasilo\MediaSiloAPI;
use mediasilo\http\WebClient;
use mediasilo\config\Meta;
use mediasilo\http\MediaSiloResourcePaths;
use mediasilo\user\PasswordResetRequest;
use mediasilo\user\PasswordReset;


class SystemAPI extends MediaSiloAPI
{
    public function __construct() {}

    public static function createFromHostCredentials($username, $password, $hostname, $baseUrl = Meta::API_ROOT_URL) {
        $instance = new self();
        $instance->webClient = WebClient::createFromHostCredentials($username, $password, $hostname, $baseUrl);
        $instance->init();
        return $instance;
    }

    public static function createFromSession($session, $host, $baseUrl = Meta::API_ROOT_URL) {
        $instance = new self();
        $instance->webClient = WebClient::createFromSession($session, $host, $baseUrl);
        $instance->init();
        return $instance;
    }

    /**
     * Get all preferences defined for ANY account. !!!Internal Use Only!!!.
     * @param $accountId
     * @return mixed
     */
    public function getAccountPreferencesForAccount($accountId) {
        return $this->accountPreferencesProxy->getPreferences($accountId);
    }

    /**
     * Get a list of tracked events specified by the events list and filtered by a query
     * @param Array $events
     * @param String $query
     * @return Array[Object]
     */
    public function getAnalytics($events, $query)
    {
        $resourcePath = sprintf(MediaSiloResourcePaths::ANALYTICS_SPECIFIC, join(",", $events));
        $clientResponse = json_decode($this->webClient->post($resourcePath, $query));
        return $clientResponse;
    }
    /**
     * Get a list of tracked events specified by the events list and filtered by a quicklink id
     * @param String $quicklinkid
     * @param Array $events
     * @return Array[Object]
     */
    public function getQuickLinkAnalytics($quicklinkId, $events, $query)
    {
        $resourcePath = sprintf(MediaSiloResourcePaths::QUICKLINK_ANALYTICS, $quicklinkId, join(",", $events));
        $resourcePath = sprintf("%s?%s", $resourcePath, $query);
        $clientResponse = json_decode($this->webClient->GET($resourcePath)->getBody());
        return $clientResponse;
    }
    
    /**
     * Get a list of tracked events specified by the events list and filtered by a quicklink id
     * @param String $quicklinkid
     * @param Array $events
     * @return Array[Object]
     */
    public function getUserQuickLinkAnalytics($quicklinkId, $userId, $events, $query)
    {
        $resourcePath = sprintf(MediaSiloResourcePaths::QUICKLINK_ANALYTICS, $quicklinkId, join(",", $events));
        $resourcePath = sprintf("%s?data.mediasiloUserId=%s", $resourcePath, $userId);
        $resourcePath = sprintf("%s&%s", $resourcePath, $query);
        $clientResponse = json_decode($this->webClient->GET($resourcePath));
        return $clientResponse;
    }

    /**
     * Performs a Password Reset Request (sends password reset link with token to user's email)
     *
     * @requires System Permission
     * @param $hostname
     * @param $username
     * @param string $type (optional)
     * @param null $redirectUri (optional)
     * @returns Object - ID property contains request token id
     */
    public function initiatePasswordReset($hostname, $username, $type = "reset", $redirectUri = null) {
        $request = new PasswordResetRequest($hostname, $username, $type, $redirectUri);
        return json_decode($this->webClient->post(MediaSiloResourcePaths::PASSWORD_RESET, $request->toJson()));
    }

    /**
     * Validates a Password Reset Request token is still valid
     * @requires System Permission
     * @param String $token
     * @return Object - Reset Token Representation
     */
    public function validateResetToken($token) {
        $resourcePath = sprintf("%s/%s", MediaSiloResourcePaths::PASSWORD_RESET, $token);
        $clientResponse = $this->webClient->get($resourcePath);
        return json_decode($clientResponse->getBody());
    }

    /**
     * Performs a password update for a user associated with a valid token
     * * @requires System Permission
     * @param String $token
     * @param String $password
     * @return Object - redirectUrl property contains location to redirect to upon success
     */
    public function processPasswordReset($token, $password) {
        $request = new PasswordReset($token, $password);
        return json_decode($this->webClient->put(MediaSiloResourcePaths::PASSWORD_RESET, $request->toJson()));
    }

    /**
     * Validates a project invite request is valid, and returns the details
     * @requires System Permissions
     * @param String $token
     * @return Object - Invite Token Representation
     */
    public function validateInviteToken($token) {
        $resourcePath = sprintf("%s/%s", MediaSiloResourcePaths::PROJECT_INVITE, $token);
        $clientResponse = $this->webClient->get($resourcePath);
        return json_decode($clientResponse->getBody());
    }

    /**
     * Gets a User Key/Value Pair By UUID
     * @param String $id
     * @return Object
     */
    public function getUserKeyPair($id)
    {
        $clientResponse = $this->webClient->get($this->webClient->get(MediaSiloResourcePaths::USER_LOOKUPS . "/" . $id));
        return json_decode($clientResponse->getBody());
    }

    /**
     * Gets a list of User Key/Value Pairs
     * @return Array[Object]
     */
    public function getUserKeyPairs()
    {
        $clientResponse = $this->webClient->get(MediaSiloResourcePaths::USER_LOOKUPS);
        return json_decode($clientResponse->getBody());
    }

}
