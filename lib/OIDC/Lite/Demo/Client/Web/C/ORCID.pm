package OIDC::Lite::Demo::Client::Web::C::ORCID;

use strict;
use warnings;
use utf8;

use OIDC::Lite::Demo::Client::Session;
use OAuth::Lite2::Client::WebServer;
use OIDC::Lite::Model::IDToken;
use JSON qw/encode_json decode_json/;
use Crypt::OpenSSL::CA;
#use HTTP::Tiny;

my $GOOGLE_CERTS_URL = q{https://www.googleapis.com/oauth2/v1/certs};

my $config = {
    'authorization_endpoint' => 'https://sandbox.orcid.org/oauth/authorize',
    'token_endpoint'         => 'https://api.sandbox.orcid.org/oauth/token',
    'userinfo_endpoint'      => 'https://api.sandbox.orcid.org/v1.2/%s/orcid-profile',
};

sub default {
    my ($self, $c) = @_;
    return $c->render('providers/orcid/top.tt');
}

sub authorize {
    my ($self, $c) = @_;

    # generate and save state parameter to session
    my $state = OIDC::Lite::Demo::Client::Session->generate_state($c->session, q{ORCID});
    OIDC::Lite::Demo::Client::Session->set_state($c->session, q{ORCID}, $state);

    # build authorize request URL
    my $orcid_config = $c->config->{'Credentials'}->{'ORCID'};
    my $uri = $self->_uri_to_orcid_authorization_endpoint( $orcid_config, $state );

    return $c->redirect($uri);
}

sub _uri_to_orcid_authorization_endpoint {
    my ($self, $orcid_config, $state) = @_;

    return $self->_client( $orcid_config )->uri_to_redirect(
        redirect_uri => $orcid_config->{'redirect_uri'},
        scope        => $orcid_config->{'scope'},
        state        => $state,
    );
}

sub _client {
    my ($self, $orcid_config) = @_;

    return OAuth::Lite2::Client::WebServer->new(
        id               => $orcid_config->{'client_id'},
        secret           => $orcid_config->{'client_secret'},
        authorize_uri    => $config->{'authorization_endpoint'},
        access_token_uri => $config->{'token_endpoint'},
#        agent            => HTTP::Tiny->new,
    );
}

sub callback {
    my ($self, $c) = @_;

    my $req = $c->req;

    # state valdation
    my $state = $req->param('state');
    my $session_state = 
        OIDC::Lite::Demo::Client::Session->get_state($c->session, q{ORCID});

    unless ($state && $session_state && $state eq $session_state) {
        # invalid state
        return $c->render('providers/orcid/error.tt' => {
            message => q{The state parameter is missing or not matched with session.},
        });
    }

    # code
    my $code = $req->param('code');
    unless ($code) {
        # invalid state
        return $c->render('providers/orcid/error.tt' => {
            message => q{The code parameter is missing.},
        });
    }

    # prepare access token request
    my $orcid_config = $c->config->{'Credentials'}->{'ORCID'};
    my $client = $self->_client( $orcid_config );

    # get_access_token
    my $token = $client->get_access_token(
        code         => $code,
        redirect_uri => $orcid_config->{'redirect_uri'},
    );
    my $res = $client->last_response;
    my $request_body = $res->request->content;
    $request_body =~ s/client_secret=[^\&]+/client_secret=(hidden)/;

    unless ($token) {
        return $c->render('providers/orcid/error.tt' => {
            message => q{Failed to get access token response},
            code => $res->code,
            content => $res->content,
            request => $request_body,
            req_uri => $res->request->uri->as_string,
        });
    }
    my $info = {
        token_request => $request_body,
        token_response => $res->content,
    };

    # # ID Token validation
    # my $id_token = OIDC::Lite::Model::IDToken->load($token->id_token);
    # $info->{'id_token'} = {
    #     header => encode_json( $id_token->header ),
    #     payload => encode_json( $id_token->payload ),
    #     string => $id_token->token_string,
    # };

    # get_user_info
    my $userinfo_res = $self->_get_userinfo( $token->access_token, $token->{orcid} );
    unless ($userinfo_res->is_success) {
        return $c->render('providers/orcid/error.tt' => {
            message => q{Failed to get userinfo response},
            code => $userinfo_res->code,
            content => $userinfo_res->content,
            request => $userinfo_res->request->content,
            req_uri => $userinfo_res->request->uri->as_string,
        });
    }
    $info->{'userinfo_endpoint'} = $userinfo_res->request->uri->as_string;
    $info->{'userinfo_request_header'} = $userinfo_res->request->header('Authorization');
    $info->{'userinfo_response'} = $userinfo_res->content;

    # display result
    return $c->render('providers/orcid/authorized.tt' => {
        info => $info,
    });
}

sub _get_userinfo {
    my ($self, $access_token, $orcid) = @_;

    my $uri = sprintf($config->{'userinfo_endpoint'}, $orcid);
    my $req = HTTP::Request->new( GET => $uri );
    $req->header( Authorization => sprintf(q{Bearer %s}, $access_token) );
    $req->header( Accept => 'application/json' );
    return LWP::UserAgent->new->request($req);
}

sub id_token {
    my ($self, $c) = @_;

    my $result;
    my $id_token;
    my $req = $c->req;

    if( $req->method eq q{POST} ) {
        $id_token = $req->param('id_token');
        $result = $self->_validate_orcid_id_token( $id_token );
    }

    # validate payload
    if ( $result->{payload} ) {
        $result->{payload_detail} = $self->_validate_orcid_id_token_payload( 
                                        $result->{payload}, 
                                        $c->config->{'Credentials'}->{'ORCID'}
                                    );
    }

    return $c->render('providers/orcid/id_token.tt' => {
        id_token => $id_token,
        result => $result,
    });
}

sub _validate_orcid_id_token {
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

        # Google's ID Token has kid param in header.
        return $result 
            unless (    $id_token->header->{alg} && 
                        $id_token->header->{alg} eq q{RS256} &&
                        $id_token->header->{kid} );
        $result->{header_content} = encode_json( $id_token->header );

        # fetch pubkey and verify signature
        my $key = $self->_get_orcid_pub_key( $id_token->header->{kid} );
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

sub _get_orcid_pub_key {
    my ( $self, $kid ) = @_;
    
    my $pub_key;

    my $res = LWP::UserAgent->new->request(HTTP::Request->new( GET => $GOOGLE_CERTS_URL ));
    return unless $res->is_success;

    my $certs;
    eval {
        $certs = decode_json( $res->content );
    };
    return unless ( $certs && $certs->{"$kid"} );

    eval {
        $pub_key = Crypt::OpenSSL::CA::X509->parse($certs->{"$kid"})->get_public_key->to_PEM;
    };
    return if $@;

    return $pub_key;
}

sub _validate_orcid_id_token_payload {
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
    unless ( $payload->{iss} eq q{accounts.google.com} ) {
        $detail->{message} = q{iss is not Google};
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
    unless ( $payload->{sub} && $payload->{email} && $payload->{email_verified} ) {
        $detail->{message} = q{sub, email and email_verified do not exist};
        return $detail;
    }

    $detail->{status} = 1;
    $detail->{userinfo} = encode_json({
        sub => $payload->{sub},
        email => $payload->{email},
        email_verified => $payload->{email_verified},
    });

    return $detail;
}

1;
