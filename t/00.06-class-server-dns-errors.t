use strict;
use warnings;
use blib;

use Error ':try';
use Net::DNS::Resolver::Programmable;
use Net::DNS::RR;

use Test::More tests => 15;

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
    my ($identity, $ip_address) = @_;
    return eval { $server->process(Mail::SPF::Request->new(
        identity    => $identity,
        ip_address  => $ip_address || '192.168.0.9'
    )) } || $@;
}


#### dns_lookup() with invalid domain names ####

foreach my $domain (
    'foo..example.com',
    ('a' x 64) . '.example.com',
    join('.', ('a' x 63) x 4) . '.com'
) {
    @queries = ();
    my $packet = eval { $server->dns_lookup($domain, 'A') };
    my $label = 'Server dns_lookup() of invalid domain ' . substr($domain, 0, 20) . '...';
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
}


#### process() with invalid identity domain names (RFC 7208, 4.3/1) ####

{
    my $result = process('foo@foo..example.com');
    isa_ok($result,     'Mail::SPF::Result::None',      'Server process() identity domain with empty label');

    $result = process('foo@' . ('a' x 64) . '.example.com');
    isa_ok($result,     'Mail::SPF::Result::None',      'Server process() identity domain with overlong label');
}
