[composer]: https://getcomposer.org/
[league_oauth2_client]: https://oauth2-client.thephpleague.com/
[govuk_account]: https://www.sign-in.service.gov.uk/

GOV.UK One Login (OAuth2 Provider)
===================================
A provider (based on [PHP League OAuth2-Client][league_oauth2_client]) to interact with [GOV.UK Account][govuk_account].

Supports autoconfiguration for most settings using the discovery endpoint.

>For identity assurance (when verifying the JWT in , you will need to define the `identity_assurance_public_key` and `expected_core_identity_issuer` for the short interim until the key and issuer is published on the discovery endpoint.

Installing
----------
The recommended way to install is through [Composer][composer].
```
composer require dvsa/php-govuk-account
```

Configuring
-----------
You may want to refer to the documentation provided at [PHP League OAuth2-Client][league_oauth2_client] as this package is a provider for that abstract package.

When instantiating the provider, the constructor accepts **additional** attributes defined in `array $options = []` which are specific for this provider; in addition to the default options provided by the AbstractProvider ([PHP League OAuth2-Client][league_oauth2_client]).

```php
'base_uri' => 'https://oidc.integration.account.gov.uk', // Base URI for the GOV.UK One Login API 
'discovery_endpoint' => 'https://oidc.integration.account.gov.uk/.well-known/openid-configuration', // Endpoint for OIDC discovery
'core_identity_did_document_url' => 'https://identity.integration.account.gov.uk/.well-known/did.json', // The DID document URL used to verify the JWTCoreIdentity token from UserDetails endpoint
'client_id' => '', // Client ID issued by GOV.UK One Login
'keys' => [
    'algorithm' => 'RS256', // Algorithm for private_key
    'private_key' => '', // Private key used to encode assertion when obtaining access token (public key must be shared with GOV.UK One Login)
    'public_key' => '', // Public key used to decode assertion when obtaining access token
],
'redirect_uri' => [
    'logged_in' => '', // The url used for redirection back to the service
    'logged_out' => '', // The url used for redirection back to the service
],
'expected_core_identity_issuer' => 'https://identity.integration.account.gov.uk/', // Issuer for JWTCoreIdentity token
```

Contributing
------------
Please refer to our [Contribution Guide](/CONTRIBUTING.md) and [Contributor Code of Conduct](/CODE_OF_CONDUCT.md).
