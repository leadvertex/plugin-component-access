<?php
/**
 * Created for plugin-component-access
 * Date: 22.09.2020
 * @author Timur Kasumov (XAKEPEHOK)
 */

namespace Leadvertex\Plugin\Components\Access\Token;


use Lcobucci\JWT\Token;

interface InputTokenInterface
{

    public function __construct(string $token);

    public function getId(): string;

    public function getBackendUri(): string;

    public function getInputToken(): Token;

    public function getOutputToken(): Token;

    public static function getInstance(): ?InputTokenInterface;

}