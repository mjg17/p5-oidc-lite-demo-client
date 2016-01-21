use strict;
use warnings;
use utf8;
use Test::More;
use OIDC::Lite::Demo::Client::Web::C::ORCID;

_URI_TO_ORCID_AUTHZ_ENDPOINT: {
    my $orcid_config = {
        'client_id' => q{aaa},
        'client_secret' => q{bbb},
        'redirect_uri' => q{http://localhost:5000/orcid/callback},
        'scope' => q{openid email profile},
    };
    my $uri = 
        OIDC::Lite::Demo::Client::Web::C::ORCID->_uri_to_orcid_authorization_endpoint( $orcid_config, q{state_string} );
    ok( $uri, q{uri is returned} );
    like( $uri, qr/\Ahttps:\/\/(sandbox\.)?orcid\.org\/oauth\/authorize/);
    like( $uri, qr/client_id=aaa/);
    like( $uri, qr/response_type=code/);
    like( $uri, qr/redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Forcid%2Fcallback/);
    like( $uri, qr/access_type=offline/);
    like( $uri, qr/scope=openid\+email\+profile/);
    like( $uri, qr/state=state_string/);
};

done_testing;
