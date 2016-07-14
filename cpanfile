requires 'Amon2'                          , '3.87';
requires 'Amon2::Plugin::Web::CSRFDefender', '0';
requires 'Router::Simple::Sinatraish'     , '0.03';
requires 'Text::Xslate'                   , '1.6001';
requires 'Amon2::DBI'                     , '0.30';
requires 'DBD::SQLite'                    , '1.33';
requires 'HTML::FillInForm::Lite'         , '1.11';
requires 'JSON::XS'                       , '0';
requires 'Module::Functions'              , '2';
requires 'Plack::Middleware::ReverseProxy', '0.09';
requires 'Plack::Middleware::Session'     , '0';
requires 'Plack::Session'                 , '0.14';
requires 'Test::WWW::Mechanize::PSGI'     , '0';
requires 'Time::Piece'                    , '1.20';
requires 'Teng'                           , '0.19';

requires 'OAuth::Lite2'                   , '0.10_02';
requires 'OIDC::Lite'                     , '0.06';
requires 'Crypt::OpenSSL::Random'         , '0.10';
requires 'Crypt::OpenSSL::CA'             , '0';
requires 'Crypt::OpenSSL::RSA'            , '0';
requires 'Crypt::OpenSSL::Bignum'         , '0';
requires 'LWP::Protocol::https'           , '0';
requires 'DBI'                            , '1.633';

# MJG attempt to get ORCID https via proxy working
# requires 'HTTP::Tiny'                     , '0'; # no luck - different I/F
# requires 'LWP::Curl'                      , '0'; # missing libcurl headers
requires 'LWP::Protocol::connect'         , '0';

requires 'Plack::Middleware::Debug'       , '0';

# MJG Plack devs
requires 'Web::Simple'                    , '0';
requires 'Web::Machine'                   , '0';

# MJG Otter Test support - usually present on deskpro
requires 'Test::Class::Most'              , '0';
# needed for t/classes.t, but not the web auth stuff:
requires 'Config::IniFiles'               , '0';
requires 'Mac::PropertyList'              , '0';
requires 'Proc::ProcessTable'             , '0';
requires 'Types::Standard'                , '0';

# New Otter server dependency
requires 'Hash::Merge::Simple'            , '0';

requires 'CHI'                            , '0';
requires 'CHI::Driver::DBI'               , '0';
requires 'CHI::Driver::Memcached'         , '0';

on 'configure' => sub {
   requires 'Module::Build', '0.38';
   requires 'Module::CPANfile', '0.9010';
};

on 'test' => sub {
    requires 'Test::More', '0.98';
};
