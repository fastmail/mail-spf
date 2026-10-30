use strict;
use warnings;
use blib;

use Error ':try';
use Net::DNS::Resolver::Programmable;
use Net::DNS::RR;
use Mail::SPF::Request;

use Test::More tests => 36;

my $test_resolver_empty = Net::DNS::Resolver::Programmable->new(
    records         => {}
);

my $test_resolver_1 = Net::DNS::Resolver::Programmable->new(
    records         => {
        'example.com'   => [
            Net::DNS::RR->new('example.com. A 192.168.0.1')
        ]
    }
);

my $test_resolver_nxdomain = Net::DNS::Resolver::Programmable->new(
    resolver_code   => sub { return ('NXDOMAIN', undef) }
);

my $test_resolver_servfail = Net::DNS::Resolver::Programmable->new(
    resolver_code   => sub { return ('SERVFAIL', undef) }
);


#### Class Compilation ####

BEGIN { use_ok('Mail::SPF::Server') }


#### Basic Instantiation ####

{
    my $server = eval { Mail::SPF::Server->new(
        dns_resolver                    => $test_resolver_empty,
        max_dns_interactive_terms       => 1,
        max_name_lookups_per_term       => 2,
        max_name_lookups_per_mx_mech    => 3
    ) };

    $@ eq '' and isa_ok($server, 'Mail::SPF::Server',   'Basic server object')
        or BAIL_OUT("Basic server instantiation failed: $@");

    # Have options been interpreted correctly?
    isa_ok($server->dns_resolver, 'Net::DNS::Resolver::Programmable', 'Basic server dns_resolver()');
    is($server->max_dns_interactive_terms,     1,       'Basic server max_dns_interactive_terms()');
    is($server->max_name_lookups_per_term,     2,       'Basic server max_name_lookups_per_term()');
    is($server->max_name_lookups_per_mx_mech,  3,       'Basic server max_name_lookups_per_mx_mech()');
    is($server->max_name_lookups_per_ptr_mech, 2,       'Basic server fallback max_name_lookups_per_ptr_mech()');
}


#### Minimally Parameterized Server ####

{
    my $server = eval { Mail::SPF::Server->new() };

    $@ eq '' and isa_ok($server, 'Mail::SPF::Server',   'Minimal server object')
        or BAIL_OUT("Minimal server instantiation failed: $@");

    # Have omitted options been defaulted correctly?
    isa_ok($server->dns_resolver, 'Net::DNS::Resolver', 'Minimal server default dns_resolver()');
    is($server->max_dns_interactive_terms,     10,      'Minimal server default max_dns_interactive_terms()');
    is($server->max_name_lookups_per_term,     10,      'Minimal server default max_name_lookups_per_term()');
    is($server->max_name_lookups_per_mx_mech,  10,      'Minimal server default max_name_lookups_per_mx_mech()');
    is($server->max_name_lookups_per_ptr_mech, 10,      'Minimal server default max_name_lookups_per_ptr_mech()');
}


#### dns_lookup() ####

# No-records lookup:

{
    my $server = Mail::SPF::Server->new(
        dns_resolver => $test_resolver_empty
    );

    my $packet = $server->dns_lookup('example.com', 'A');
    isa_ok($packet,                 'Net::DNS::Packet', 'Server no-records dns_lookup() packet object');
    is($packet->header->rcode,      'NOERROR',          'Server no-records dns_lookup() rcode');
    is($packet->answer,             0,                  'Server no-records dns_lookup() answer RR count');
}

# 'A' record lookup:

{
    my $server = Mail::SPF::Server->new(
        dns_resolver => $test_resolver_1
    );

    my $packet = $server->dns_lookup('example.com', 'A');
    isa_ok($packet,                 'Net::DNS::Packet', 'Server "A" dns_lookup() packet object');

    my @rrs = $packet->answer;
    is($rrs[0]->name,               'example.com',      'Server "A" dns_lookup() answer domain name');
    is($rrs[0]->type,               'A',                'Server "A" dns_lookup() answer RR type');
}

# NXDOMAIN lookup:

{
    my $server = Mail::SPF::Server->new(
        dns_resolver => $test_resolver_nxdomain
    );

    my $packet = $server->dns_lookup('example.com', 'A');
    isa_ok($packet,                 'Net::DNS::Packet', 'Server NXDOMAIN dns_lookup() packet object');
    is($packet->header->rcode,      'NXDOMAIN',         'Server NXDOMAIN dns_lookup() rcode');
    is($packet->answer,             0,                  'Server NXDOMAIN dns_lookup() answer RR count');
}

# SERVFAIL lookup:

{
    my $server = Mail::SPF::Server->new(
        dns_resolver => $test_resolver_servfail
    );

    my $packet = eval { $server->dns_lookup('example.com', 'A') };
    isa_ok($@,                  'Mail::SPF::EDNSError', 'Server SERVFAIL dns_lookup()');
}


#### SPF Record Selection / select_record(), get_acceptable_records_from_packet() ####

# This gets checked by the RFC 4408 test suite.


#### process() with includes of CNAME-aliased domains ####

{
    my %zone = (
        'policy.example.net'    => [ 'TXT "v=spf1 -all"' ],
        'alias.example.net'     => [ 'CNAME policy.example.net' ],
        'bracket.example.net'     => [ 'CNAME x[y.example.net' ],
        'x[y.example.net'       => [ 'TXT "v=spf1 -all"' ],
        'dot.example.net'       => [ 'CNAME policy.example.net' ],
        'policyxexample.net'    => [ 'TXT "v=spf1 -all"' ],
        'alias.example.com'     => [ 'TXT "v=spf1 include:policy.example.net include:alias.example.net ip4:192.168.0.1 -all"' ],
        'bracket.example.com'     => [ 'TXT "v=spf1 include:bracket.example.net include:policy.example.net ip4:192.168.0.1 -all"' ],
        'dot.example.com'       => [ 'TXT "v=spf1 include:dot.example.net include:policyxexample.net ip4:192.168.0.1 -all"' ]
    );

    # Resolver that chases CNAMEs like a recursive resolver would:
    my $test_resolver_cname = Net::DNS::Resolver::Programmable->new(
        resolver_code   => sub {
            my ($domain, $rr_type) = @_;
            my @rrs;
            while (defined($domain) and $zone{$domain}) {
                my @domain_rrs = map(Net::DNS::RR->new("$domain 60 IN $_"), @{$zone{$domain}});
                my @matching_rrs = grep($_->type eq $rr_type, @domain_rrs);
                my ($cname_rr) = grep($_->type eq 'CNAME', @domain_rrs);
                push(@rrs, @matching_rrs ? @matching_rrs : $cname_rr ? $cname_rr : ());
                $domain = (not @matching_rrs and $cname_rr) ? $cname_rr->cname : undef;
            }
            return (@rrs ? 'NOERROR' : 'NXDOMAIN', undef, @rrs);
        }
    );

    my $server = Mail::SPF::Server->new(
        dns_resolver => $test_resolver_cname
    );

    my $process = sub {
        my ($domain) = @_;
        return eval { $server->process(Mail::SPF::Request->new(
            identity    => "foo\@$domain",
            ip_address  => '192.168.0.1'
        )) } || $@;
    };

    my $result = $process->('alias.example.com');
    isa_ok($result, 'Mail::SPF::Result::Pass',          'Server process() includes of a domain and its CNAME alias');

    $result = $process->('bracket.example.com');
    isa_ok($result, 'Mail::SPF::Result',                'Server process() include of CNAME to name with "[" does not die');
    isa_ok($result, 'Mail::SPF::Result::Pass',          'Server process() include of CNAME to name with "["');

    $result = $process->('dot.example.com');
    isa_ok($result, 'Mail::SPF::Result::Pass',          'Server process() include of CNAME is not matched as a regex');
}


#### process() with a proposed record (record_from_string()) ####

# Without a proposed record, an empty DNS zone yields "none":

{
    my $server  = Mail::SPF::Server->new(dns_resolver => $test_resolver_empty);
    my $request = Mail::SPF::Request->new(
        scope       => 'mfrom',
        identity    => 'foo@example.com',
        ip_address  => '192.168.0.2'
    );

    my $result = $server->process($request);
    is($result->code, 'none', 'Server process() without record option queries DNS as usual');
}

# A proposed record is evaluated instead of the (non-existent) DNS record:

{
    my $server  = Mail::SPF::Server->new(dns_resolver => $test_resolver_empty);
    my $request = Mail::SPF::Request->new(
        scope       => 'mfrom',
        identity    => 'foo@example.com',
        ip_address  => '192.168.0.2'
    );

    my $result = $server->process($request, { record => 'v=spf1 -all' });
    is($result->code, 'fail', 'Server process() record option bypasses DNS record selection');
}

# Mechanisms within a proposed record still perform real DNS look-ups:

{
    my $server = Mail::SPF::Server->new(dns_resolver => $test_resolver_1);

    my $request_match = Mail::SPF::Request->new(
        scope       => 'mfrom',
        identity    => 'foo@example.com',
        ip_address  => '192.168.0.1'
    );
    my $result_match = $server->process($request_match, { record => 'v=spf1 a -all' });
    is($result_match->code, 'pass', 'Server process() record option mechanisms perform real DNS look-ups (match)');

    my $request_nomatch = Mail::SPF::Request->new(
        scope       => 'mfrom',
        identity    => 'foo@example.com',
        ip_address  => '192.168.0.9'
    );
    my $result_nomatch = $server->process($request_nomatch, { record => 'v=spf1 a -all' });
    is($result_nomatch->code, 'fail', 'Server process() record option mechanisms perform real DNS look-ups (no match)');
}

# A proposed record of a version unacceptable for the request's scope yields "none":

{
    my $server  = Mail::SPF::Server->new(dns_resolver => $test_resolver_empty);
    my $request = Mail::SPF::Request->new(
        scope       => 'helo',
        identity    => 'mta.example.com',
        ip_address  => '192.168.0.2'
    );

    my $result = $server->process($request, { record => 'spf2.0/mfrom -all' });
    is($result->code, 'none', 'Server process() record option for an unacceptable record version');
}

# A syntactically invalid proposed record yields "permerror":

{
    my $server  = Mail::SPF::Server->new(dns_resolver => $test_resolver_empty);
    my $request = Mail::SPF::Request->new(
        scope       => 'mfrom',
        identity    => 'foo@example.com',
        ip_address  => '192.168.0.2'
    );

    my $result = $server->process($request, { record => 'v=spf1 bogus-mechanism -all' });
    is($result->code, 'permerror', 'Server process() record option with invalid syntax');
}


#### select_record() with both 'v=spf1' and 'spf2.0' records ####

{
    my %zone = (
        'v2-v1.example.com'     => [ 'spf2.0/mfrom -all', 'v=spf1 +all' ],
        'v1-v2.example.com'     => [ 'v=spf1 +all', 'spf2.0/mfrom -all' ]
    );

    my $server = Mail::SPF::Server->new(
        dns_resolver => Net::DNS::Resolver::Programmable->new(
            resolver_code   => sub {
                my ($domain, $rr_type) = @_;
                return ('NXDOMAIN', undef) if not $zone{$domain};
                return ('NOERROR', undef) if $rr_type ne 'TXT';
                return ('NOERROR', undef, map(Net::DNS::RR->new("$domain 60 IN TXT \"$_\""), @{$zone{$domain}}));
            }
        )
    );

    my $select = sub {
        my ($domain, @versions) = @_;
        return $server->select_record(Mail::SPF::Request->new(
            identity    => "foo\@$domain",
            ip_address  => '192.168.0.1',
            @versions ? (versions => \@versions) : ()
        ));
    };

    isa_ok($select->('v2-v1.example.com'),      'Mail::SPF::v1::Record', 'Server select_record() prefers v=spf1 over spf2.0 listed first');
    isa_ok($select->('v1-v2.example.com'),      'Mail::SPF::v1::Record', 'Server select_record() prefers v=spf1 over spf2.0 listed last');
    isa_ok($select->('v2-v1.example.com', 2),   'Mail::SPF::v2::Record', 'Server select_record() uses spf2.0 if only version 2 is acceptable');
}
