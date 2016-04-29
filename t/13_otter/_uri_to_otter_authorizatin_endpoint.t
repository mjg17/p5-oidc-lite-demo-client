use strict;
use warnings;
use utf8;
use Test::More;
use OIDC::Lite::Demo::Client::Web::C::Otter;

_URI_TO_OTTER_AUTHZ_ENDPOINT: {
    my $otter_config = {
        'client_id' => q{aaa},
        'client_secret' => q{bbb},
        'redirect_uri' => q{http://localhost:5000/otter/callback},
        'scope' => q{openid email profile},
    };
    my $uri = 
        OIDC::Lite::Demo::Client::Web::C::Otter->_uri_to_otter_authorizatin_endpoint( $otter_config, q{state_string} );
    ok( $uri, q{uri is returned} );
    like( $uri, qr/\Ahttps:\/\/accounts\.otter\.com\/o\/oauth2\/auth/);
    like( $uri, qr/client_id=aaa/);
    like( $uri, qr/response_type=code/);
    like( $uri, qr/redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fotter%2Fcallback/);
    like( $uri, qr/access_type=offline/);
    like( $uri, qr/scope=openid\+email\+profile/);
    like( $uri, qr/state=state_string/);
};

done_testing;
