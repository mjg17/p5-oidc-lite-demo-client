package OIDC::Lite::Demo::Client::Web::C::Otter;

use strict;
use warnings;
use utf8;

use OIDC::Lite::Demo::Client::Session;
use OIDC::Lite::Client::WebServer;
use OIDC::Lite::Model::IDToken;
use JSON qw/encode_json decode_json/;

sub default {
    my ($self, $c) = @_;
    return $c->render('providers/otter/top.tt');
}

sub authorize {
    my ($self, $c) = @_;

    # generate and save state parameter to session
    my $state = OIDC::Lite::Demo::Client::Session->generate_state($c->session, q{Otter});
    OIDC::Lite::Demo::Client::Session->set_state($c->session, q{Otter}, $state);

    # build authorize request URL
    my $otter_config = $c->config->{'Credentials'}->{'Otter'};
    my $uri = $self->_uri_to_otter_authorizatin_endpoint( $otter_config, $state );

    return $c->redirect($uri);
}

sub _uri_to_otter_authorizatin_endpoint {
    my ($self, $otter_config, $state) = @_;

    return $self->_client( $otter_config )->uri_to_redirect(
        redirect_uri => $otter_config->{'redirect_uri'},
        scope        => $otter_config->{'scope'},
        state        => $state,
    );
}

sub _client {
    my ($self, $otter_config) = @_;

    return OIDC::Lite::Client::WebServer->new(
        id               => $otter_config->{'client_id'},
        secret           => $otter_config->{'client_secret'},
        authorize_uri    => $otter_config->{'authorization_endpoint'},
        access_token_uri => $otter_config->{'token_endpoint'},
    );
}

sub callback {
    my ($self, $c) = @_;

    my $req = $c->req;

    # state valdation
    my $state = $req->param('state');
    my $session_state = 
        OIDC::Lite::Demo::Client::Session->get_state($c->session, q{Otter});

    unless ($state && $session_state && $state eq $session_state) {
        # invalid state
        return $c->render('providers/otter/error.tt' => {
            message => q{The state parameter is missing or not matched with session.},
        });
    }

    # code
    my $code = $req->param('code');
    unless ($code) {
        # invalid state
        return $c->render('providers/otter/error.tt' => {
            message => q{The code parameter is missing.},
        });
    }

    # prepare access token request
    my $otter_config = $c->config->{'Credentials'}->{'Otter'};
    my $client = $self->_client( $otter_config );

    # get_access_token
    my $token = $client->get_access_token(
        code         => $code,
        redirect_uri => $otter_config->{'redirect_uri'},
    );
    my $res = $client->last_response;
    my $request_body = $res->request->content;
    $request_body =~ s/client_secret=[^\&]+/client_secret=(hidden)/;

    unless ($token) {
        return $c->render('providers/otter/error.tt' => {
            message => q{Failed to get access token response},
            code => $res->code,
            content => $res->content,
            request => $request_body,
        });
    }
    my $info = {
        token_request => $request_body,
        token_response => $res->content,
    };

    # ID Token validation
    my $id_token = OIDC::Lite::Model::IDToken->load($token->id_token);
    $info->{'id_token'} = {
        header => encode_json( $id_token->header ),
        payload => encode_json( $id_token->payload ),
        string => $id_token->token_string,
    };

    # # get_user_info
    # my $userinfo_res = $self->_get_userinfo( $token->access_token, $otter_config );
    # unless ($userinfo_res->is_success) {
    #     return $c->render('providers/otter/error.tt' => {
    #         message => q{Failed to get userinfo response},
    #         code => $userinfo_res->code,
    #         content => $userinfo_res->content,
    #     });
    # }
    # $info->{'userinfo_endpoint'} = $otter_config->{'userinfo_endpoint'};
    # $info->{'userinfo_request_header'} = $userinfo_res->request->header('Authorization');
    # $info->{'userinfo_response'} = $userinfo_res->content;

    # display result
    return $c->render('providers/otter/authorized.tt' => {
        info => $info,
    });
}

sub _get_userinfo {
    my ($self, $access_token, $otter_config) = @_;

    my $req = HTTP::Request->new( GET => $otter_config->{'userinfo_endpoint'} );
    $req->header( Authorization => sprintf(q{Bearer %s}, $access_token) );
    return LWP::UserAgent->new->request($req);
}

sub id_token {
    my ($self, $c) = @_;

    my $result;
    my $id_token;
    my $req = $c->req;

    if( $req->method eq q{POST} ) {
        $id_token = $req->param('id_token');
        $result = $self->_validate_otter_id_token( $id_token );
    }

    # validate payload
    if ( $result->{payload} ) {
        $result->{payload_detail} = $self->_validate_otter_id_token_payload( 
                                        $result->{payload}, 
                                        $c->config->{'Credentials'}->{'Otter'}
                                    );
    }

    return $c->render('providers/otter/id_token.tt' => {
        id_token => $id_token,
        result => $result,
    });
}

sub _validate_otter_id_token {
    my ($self, $id_token_string) = @_;

    my $result = {
        id_token_string => $id_token_string,
        signature_status => 0,
    };

    # load IDToken Object
    my $id_token = OIDC::Lite::Model::IDToken->load( $result->{id_token_string} );
    if ( $id_token ) {

        my $encoded = [split(/\./, $result->{id_token_string})];
        ($result->{encoded_header}, $result->{encoded_payload}, $result->{encoded_signature}) = @$encoded;
        $result->{signing_input} = $result->{encoded_header}.'.'.$result->{encoded_payload};

        # Otter's ID Token has kid param in header.
        return $result 
            unless (    $id_token->header->{alg} && 
                        $id_token->header->{alg} eq q{RS256} &&
                        $id_token->header->{kid} );
        $result->{header_content} = encode_json( $id_token->header );

        # fetch pubkey and verify signature
        my $key = $self->_get_otter_pub_key( $id_token->header->{kid} );
        return $result unless $key;
        $result->{pubkey} = $key;
        $id_token->key($key);
        return $result unless $id_token->verify;

        $result->{signature_status} = 1;
        $result->{payload_content} = encode_json( $id_token->payload );
        # for payload validation
        $result->{payload} = $id_token->payload;
    }

    return $result;
}

sub _get_otter_pub_key {
    my ( $self, $kid ) = @_;

    # FIXME: get from config
    my $pub_key = <<'__EO_KEY__';
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChfw/PEXvL4+Btsex0a4EWnUUC
l8/4Cnc3FmPBuG7QnHo+tdl+MGDHNRJzfzgSrLBNxrBZM6cIcTkVaOTM4dh2CKNV
HiL+/ZdZSPwQGpg4xsvwocm+NUa8P+imy7GHcAQ+YqdesKTehv8zMBZ1ilGxYxvG
OrmKHWW05uk6LQTAhwIDAQAB
-----END PUBLIC KEY-----
__EO_KEY__

    # eval {
    #     $pub_key = Crypt::OpenSSL::CA::X509->parse($certs->{"$kid"})->get_public_key->to_PEM;
    # };
    # return if $@;

    return $pub_key;
}

sub _validate_otter_id_token_payload {
    my ( $self, $payload, $config ) = @_;
    my $detail = {
        status => 0,
    };

    # iss
    $detail->{iss} = $payload->{iss};
    unless ( $payload->{iss} ) {
        $detail->{message} = q{iss does not exist};
        return $detail;
    }
    unless ( $payload->{iss} =~ qr{otter.+\.sanger\.ac\.uk} ) {
        $detail->{message} = q{iss is not Otter};
        return $detail;
    }

    # iat
    $detail->{current} = time();
    $detail->{iat} = $payload->{iat};
    unless ( $payload->{iat} ) {
        $detail->{message} = q{iat does not exist};
        return $detail;
    }
    my $now = time();
    unless ( $payload->{iat} <= $now ) {
        $detail->{message} = q{iat is greater than current timestamp};
        return $detail;
    }

    # exp
    $detail->{exp} = $payload->{exp};
    unless ( $payload->{exp} ) {
        $detail->{message} = q{exp does not exist};
        return $detail;
    }
    unless ( $payload->{exp} >= $now ) {
        $detail->{message} = q{exp is not greater than current timestamp};
        return $detail;
    }

    # aud anz azp
    $detail->{aud} = $payload->{aud};
    $detail->{client_id} = $config->{client_id};
    unless ( $payload->{aud} || $payload->{azp} ) {
        $detail->{message} = q{aud does not exist};
        return $detail;
    }
    unless ( $payload->{aud} eq $config->{client_id} ) {
        $detail->{message} = q{aud does not match with this app's client_id};
        return $detail;
    }

    # userinfo
    unless ( $payload->{sub} ) {
        $detail->{message} = q{sub does not exist};
        return $detail;
    }

    $detail->{status} = 1;
    $detail->{userinfo} = encode_json({
        sub => $payload->{sub},
    });

    return $detail;
}

1;
