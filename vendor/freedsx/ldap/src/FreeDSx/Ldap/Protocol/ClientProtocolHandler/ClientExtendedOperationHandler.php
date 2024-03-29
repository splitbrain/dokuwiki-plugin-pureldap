<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Protocol\Factory\ExtendedResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Socket\Exception\ConnectionException;
use ReflectionClass;
use ReflectionException;

/**
 * Logic for handling extended operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientExtendedOperationHandler extends ClientBasicHandler
{
    /**
     * @var ExtendedResponseFactory
     */
    protected $extendedResponseFactory;

    public function __construct(ExtendedResponseFactory $extendedResponseFactory = null)
    {
        $this->extendedResponseFactory = $extendedResponseFactory ?? new ExtendedResponseFactory();
    }

    /**
     * @param ClientProtocolContext $context
     * @return LdapMessageResponse|null
     * @throws OperationException
     * @throws EncoderException
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     * @throws ConnectionException
     * @throws ReflectionException
     * @throws RuntimeException
     */
    public function handleRequest(ClientProtocolContext $context): ?LdapMessageResponse
    {
        $messageFrom = parent::handleRequest($context);

        /** @var ExtendedRequest $request */
        $request = $context->getRequest();
        if (!$this->extendedResponseFactory->has($request->getName())) {
            return $messageFrom;
        }
        if ($messageFrom === null) {
            throw new OperationException('Expected an LDAP message response, but none was received.');
        }

        $response = $this->extendedResponseFactory->get(
            $messageFrom->getResponse()->toAsn1(),
            $request->getName()
        );
        $prop = (new ReflectionClass(LdapMessageResponse::class))->getProperty('response');
        $prop->setAccessible(true);
        $prop->setValue($messageFrom, $response);

        return $messageFrom;
    }
}
