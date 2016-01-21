use strict;
use warnings;
use utf8;
use Test::More;
use OIDC::Lite::Demo::Client::Web::C::ORCID;

_CLIENT: {
    my $orcid_config = {
        'client_id' => q{aaa},
        'client_secret' => q{bbb},
        'redirect_uri' => q{http://localhost:5000/orcid/callback},
        'scope' => q{openid email profile},
    };
    my $client =
        OIDC::Lite::Demo::Client::Web::C::ORCID->_client( $orcid_config );
    ok( $client, q{object is returned} );
    isa_ok( $client, q{OIDC::Lite::Client::WebServer}, q{OIDC::Lite::Client::WebServer} );
};

done_testing;
