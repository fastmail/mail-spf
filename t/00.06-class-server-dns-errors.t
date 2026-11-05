use strict;
use warnings;
use blib;

use Error ':try';
use Net::DNS::Resolver::Programmable;
use Net::DNS::RR;

use Test::More tests => 37;

use Mail::SPF::Server;
use Mail::SPF::Request;

my %zone = (
    'example.com'           => [ 'TXT "v=spf1 a -all"', 'A 192.168.0.1' ],
    'macro.example.com'     => [ 'TXT "v=spf1 exists:%{l}.users.example.com -all"' ],
    'macro2.example.com'    => [ 'TXT "v=spf1 a:mail.example.com exists:%{l}.users.example.com -all"' ],
    'mail.example.com'      => [ 'A 192.168.0.2' ]
);

my $die_on = '';
my @queries;

{
    package Mail::SPF::Test::CroakingResolver;
    our @ISA = ('Net::DNS::Resolver::Programmable');
    # Like Net::DNS::Resolver, compose a query packet first, which croaks on
    # invalid domain names:
    sub send {
        my $self = shift;
        Net::DNS::Packet->new($_[0], $_[1]);
        return $self->SUPER::send(@_);
    }
}

my $test_resolver = Mail::SPF::Test::CroakingResolver->new(
    resolver_code   => sub {
        my ($domain, $rr_type) = @_;
        push(@queries, "$rr_type $domain");
        die("Simulated resolver failure at /some/internal/path.pm line 42.\n")
            if "$rr_type $domain" eq $die_on;
        my @rrs = grep($_->type eq $rr_type,
            map(Net::DNS::RR->new("$domain 60 IN $_"), @{$zone{$domain} || []}));
        return ($zone{$domain} ? 'NOERROR' : 'NXDOMAIN', undef, @rrs);
    }
);

my $server = Mail::SPF::Server->new(
    dns_resolver    => $test_resolver
);

sub process {
    my ($identity, $ip_address, %request_options) = @_;
    return eval { $server->process(Mail::SPF::Request->new(
        identity    => $identity,
        ip_address  => $ip_address || '192.168.0.9',
        %request_options
    )) } || $@;
}


#### dns_lookup() with invalid domain names ####

foreach my $case (
    [ 'foo..example.com',                           'with empty label'                      ],
    [ ('a' x 64) . '.example.com',                  'with overlong label'                   ],
    [ join('.', ('a' x 63) x 4) . '.com',           'overlong'                              ],
    # Net::DNS counts the bytes of labels encoded as UTF-8:
    [ ("\x{e9}" x 32) . '.example.com',             'with label of 64 bytes in UTF-8'       ],
    [ join('.', ("\x{e9}" x 20) x 7) . '.com',      'of over 255 bytes in UTF-8'            ],
    # Net::DNS reads "\." as a dot within a label:
    [ ('a' x 40) . '\\.' . ('b' x 40) . '.example.com', 'with overlong label with escaped dot' ]
) {
    my ($domain, $description) = @$case;
    @queries = ();
    my $packet = eval { $server->dns_lookup($domain, 'A') };
    my $label = "Server dns_lookup() of invalid domain $description";
    is(($packet ? $packet->header->rcode : "error: $@"), 'NXDOMAIN', "$label NXDOMAIN");
    is(scalar(@queries),        0,                      "$label does not query resolver");
}


#### dns_lookup() with resolver throwing an exception ####

{
    $die_on = 'A example.com';
    my $packet = eval { $server->dns_lookup('example.com', 'A') };
    isa_ok($@,                  'Mail::SPF::EDNSError', 'Server dns_lookup() resolver exception');
    $die_on = '';
}


#### process() with resolver throwing an exception ####

{
    my $result = process('foo@example.com');
    isa_ok($result,     'Mail::SPF::Result::Fail',      'Server process() control result');

    $die_on = 'TXT example.com';
    $result = process('foo@example.com');
    isa_ok($result,     'Mail::SPF::Result::TempError', 'Server process() resolver exception during record selection');

    $die_on = 'A example.com';
    $result = process('foo@example.com');
    isa_ok($result,     'Mail::SPF::Result::TempError', 'Server process() resolver exception during evaluation');
    unlike($result->text, qr/internal/,                 'Server process() result text does not include resolver exception text');

    $die_on = '';
}


#### process() with invalid domain names from macro expansion ####

{
    my $result = process('"foo..bar"@macro.example.com');
    isa_ok($result,     'Mail::SPF::Result::Fail',      'Server process() local-part with empty label in first mechanism');

    $result = process('"foo..bar"@macro2.example.com');
    isa_ok($result,     'Mail::SPF::Result::Fail',      'Server process() local-part with empty label in later mechanism');

    $result = process(("\x{e9}" x 32) . '@macro.example.com');
    isa_ok($result,     'Mail::SPF::Result::Fail',      'Server process() local-part of 64 bytes in UTF-8');

    $result = process(('a' x 40) . '\\.' . ('b' x 40) . '@macro.example.com');
    isa_ok($result,     'Mail::SPF::Result::Fail',      'Server process() local-part with escaped dot');
}


#### process() with invalid identity domain names (RFC 7208, 4.3/1) ####

{
    my $result = process('foo@foo..example.com');
    isa_ok($result,     'Mail::SPF::Result::None',      'Server process() identity domain with empty label');

    $result = process('foo@' . ('a' x 64) . '.example.com');
    isa_ok($result,     'Mail::SPF::Result::None',      'Server process() identity domain with overlong label');
}


#### process() with empty or single-label identity domain names (RFC 7208, 4.3) ####

{
    foreach my $case (
        [ 'foo@',               'mfrom',    'empty MAIL FROM domain'        ],
        [ 'foo@localhost',      'mfrom',    'single-label MAIL FROM domain' ],
        [ 'mailhost',           'helo',     'single-label HELO identity'    ]
    ) {
        my ($identity, $scope, $label) = @$case;
        @queries = ();
        my $result = process($identity, undef, scope => $scope);
        isa_ok($result, 'Mail::SPF::Result::None',      "Server process() $label");
        is(scalar(@queries), 0,                         "Server process() $label does not query resolver");

        # Likewise with a proposed record:
        @queries = ();
        $result = eval { $server->process(Mail::SPF::Request->new(
            identity    => $identity,
            ip_address  => '192.168.0.9',
            scope       => $scope
        ), { record => 'v=spf1 a mx -all' }) } || $@;
        isa_ok($result, 'Mail::SPF::Result::None',      "Server process() with proposed record and $label");
        is(scalar(@queries), 0,                         "Server process() with proposed record and $label does not query resolver");
    }

    # A fully qualified authority domain is valid:
    my $result = process('foo@example.com', '192.168.0.1', authority_domain => 'example.com.');
    isa_ok($result, 'Mail::SPF::Result::Pass',          'Server process() with fully qualified authority domain');
    $result = process('foo@example.com', '192.168.0.1', authority_domain => '.');
    isa_ok($result, 'Mail::SPF::Result::None',          'Server process() with root domain as authority domain');
}
