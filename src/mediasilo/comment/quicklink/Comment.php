<?php

namespace mediasilo\comment\quicklink;

use mediasilo\model\Serializable;

class Comment implements Serializable{

    public $id;
    public $at;
    public $inResponseTo;
    public $context;
    public $startTimeCode;
    public $endTimeCode;
    public $dateCreated;
    public $body;
    public $user;
    public $responses;

    function __construct($at, $inResponseTo, $context, $body)
    {
        $this->at = $at;
        $this->inResponseTo = $inResponseTo;
        $this->context = $context;
        $this->body = $body;
    }

    function toJson() {
        return json_encode($this);
    }

    public static function fromJson($json) {
        $mixed = json_decode($json);
        $comment = new Comment($mixed->at, $mixed->inResponseTo, $mixed->context, $mixed->body);
        $comment->id = $mixed->id;
        $comment->startTimeCode = $mixed->startTimeCode;
        $comment->endTimeCode = $mixed->endTimeCode;
        $comment->dateCreated = $mixed->dateCreated;
        $comment->user = $mixed->user;
        $comment->responses = $mixed->responses;
    }
}