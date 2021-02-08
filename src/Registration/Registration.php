<?php
/**
 * Created for plugin-component-access
 * Date: 20.11.2020
 * @author Timur Kasumov (XAKEPEHOK)
 */

namespace Leadvertex\Plugin\Components\Access\Registration;


use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Leadvertex\Plugin\Components\Access\PublicKey\Exceptions\TokenVerificationException;
use Leadvertex\Plugin\Components\Access\PublicKey\PublicKey;
use Leadvertex\Plugin\Components\Db\Components\Connector;
use Leadvertex\Plugin\Components\Db\Model;
use Leadvertex\Plugin\Components\Db\SinglePluginModelInterface;

class Registration extends Model implements SinglePluginModelInterface
{

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

    /**
     * @return Registration|Model|null
     */
    public static function find(): ?Model
    {
        return parent::find();
    }

    public function getRegisteredAt(): int
    {
        return $this->registeredAt;
    }

    public function getLVPT(): string
    {
        return $this->LVPT;
    }

    public function getOutputToken(callable $handler): Token
    {
        $reference = Connector::getReference();

        $builder = new Builder();
        $builder->issuedBy($_ENV['LV_PLUGIN_SELF_URI']);
        $builder->withClaim('cid', $reference->getCompanyId());
        $builder->withClaim('plugin', [
            'alias' => $reference->getAlias(),
            'id' => $reference->getId(),
        ]);
        $handler($builder);

        return $builder->getToken(new Sha512(), new Key($this->getLVPT()));
    }

    public static function schema(): array
    {
        return [
            'registeredAt' => ['INT', 'NOT NULL'],
            'LVPT' => ['CHAR(512)', 'NOT NULL'],
        ];
    }
}