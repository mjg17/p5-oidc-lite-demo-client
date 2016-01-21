use strict;
use warnings;
use utf8;
use Test::More;
use Test::MockObject;
use Plack::Session;
use OIDC::Lite::Demo::Client::Web::C::ORCID;

_AUTHORIZE: {
    Test::MockObject->fake_module(
        'OIDC::Lite::Demo::Client',
        'new' => sub{bless {}, shift},
        'session' => sub {
            return Plack::Session->new({
                'psgix.session' => +{},
                'psgix.session.options' => +{},
            });
        },
        'config' => sub {
            return {
                'Credentials' => {
                    'ORCID' => {
                        'client_id' => q{aaa},
                        'client_secret' => q{bbb},
                        'redirect_uri' => q{http://localhost:5000/orcid/callback},
                        'scope' => q{openid email profile},
                    },
                },
            };
        },
        'redirect' => sub{
            my ($class, $url) = @_;
            return "redirect : ".$url;
        },
    );
    Test::MockObject->fake_module(
        'OIDC::Lite::Demo::Client::Session',
        'generate_state' => sub {
            return q{state_string};
        },
        'set_state' => sub {
            return;
        },
    );

    my $c = OIDC::Lite::Demo::Client->new();
    my $res = OIDC::Lite::Demo::Client::Web::C::ORCID->authorize($c);
    like ($res, qr/\Aredirect : https:\/\/(sandbox\.)?orcid\.org\/oauth\/authorize/);
    like ($res, qr/client_id=aaa/);
    like ($res, qr/response_type=code/);
    like ($res, qr/redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Forcid%2Fcallback/);
    like ($res, qr/access_type=offline/);
    like ($res, qr/scope=openid\+email\+profile/);
    like ($res, qr/state=state_string/);
};

done_testing;
