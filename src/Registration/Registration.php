<?php
/**
 * Created for plugin-component-access
 * Date: 20.11.2020
 * @author Timur Kasumov (XAKEPEHOK)
 */

namespace Leadvertex\Plugin\Components\Access\Registration;


use Lcobucci\JWT\Token;
use Leadvertex\Plugin\Components\Access\PublicKey\Exceptions\TokenVerificationException;
use Leadvertex\Plugin\Components\Access\PublicKey\PublicKey;
use Leadvertex\Plugin\Components\Db\ModelTrait;
use Leadvertex\Plugin\Components\Db\SinglePluginModelInterface;
use Leadvertex\Plugin\Components\Db\SinglePluginModelTrait;

class Registration implements SinglePluginModelInterface
{

    use ModelTrait, SinglePluginModelTrait;

    protected int $registeredAt;
    protected string $LVPT;

    /**
     * Registration constructor.
     * @param Token $token
     * @throws TokenVerificationException
     */
    public function __construct(Token $token)
    {
        $this->registeredAt = time();
        PublicKey::verify($token);
        $this->LVPT = $token->getClaim('LVPT');
    }

    public function getRegisteredAt(): int
    {
        return $this->registeredAt;
    }

    public function getLVPT(): string
    {
        return $this->LVPT;
    }

    public static function schema(): array
    {
        return [
            'registeredAt' => ['INT', 'NOT NULL'],
            'LVPT' => ['CHAR(512)', 'NOT NULL'],
        ];
    }
}