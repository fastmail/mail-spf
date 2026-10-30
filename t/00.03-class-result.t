use strict;
use warnings;
use blib;

use Error ':try';
use Net::DNS::Resolver::Programmable;
use Net::DNS::RR;

use Test::More tests => 32;

use Mail::SPF::Request;
use Mail::SPF::Server;
use Mail::SPF::MacroString;


#### Class Compilation ####

BEGIN { use_ok('Mail::SPF::Result') }


#### Basic Instantiation ####

{
    my $result = eval { Mail::SPF::Result->new('dummy server', 'dummy request', 'result text') };

    $@ eq '' and isa_ok($result, 'Mail::SPF::Result',   'Basic result object')
        or BAIL_OUT("Basic result instantiation failed: $@");

    # Have options been interpreted correctly?
    is($result->server,             'dummy server',     'Basic result server()');
    is($result->request,            'dummy request',    'Basic result request()');
    is($result->text,               'result text',      'Basic result text()');
}


#### Parameterized Result Rethrowing ####

{
    eval {
        eval { throw Mail::SPF::Result('server', 'request', 'result text') };
        $@->throw('other server', 'other request', 'other text');
    };
    my $result = $@;

    isa_ok($result,                'Mail::SPF::Result', 'Param-rethrown result object');
    is($result->server,             'other server',     'Param-rethrown result server()');
    is($result->request,            'other request',    'Param-rethrown result request()');
    is($result->text,               'other text',       'Param-rethrown result text()');
}


#### class() ####

{
    my $class;

    $class = Mail::SPF::Result->class;
    is($class,                     'Mail::SPF::Result', 'Result class()');

    $class = Mail::SPF::Result->class('PaSs');
    is($class,               'Mail::SPF::Result::Pass', 'Result class($valid_name)');

    $class = Mail::SPF::Result->class('foo');
    is($class,                      undef,              'Result class($invalid_name)');
}


#### isa_by_name(), is_code() ####

{
    my $result = Mail::SPF::Result::Pass->new('dummy server', 'dummy request');
    ok($result->isa_by_name('PaSs'),                    'Result isa_by_name($valid_name)');
    ok((not $result->isa_by_name('foo')),               'Result isa_by_name($invalid_name)');
    ok($result->is_code('PaSs'),                        'Result is_code($valid_code)');
    ok((not $result->is_code('foo')),                   'Result is_code($invalid_code)');
}


#### NeutralByDefault, code(), isa_by_name() ####

{
    my $result = Mail::SPF::Result::NeutralByDefault->new('dummy server', 'dummy request');
    isa_ok($result,       'Mail::SPF::Result::Neutral', 'NeutralByDefault result object');
    is($result->code,               'neutral',          'NeutralByDefault result code()');
    ok($result->isa_by_name('neutral-by-default'),      'NeutralByDefault isa_by_name("neutral-by-default")');
    ok($result->isa_by_name('neutral'),                 'NeutralByDefault isa_by_name("neutral")');
}


#### received_spf_header() escaping ####

{
    my $server  = Mail::SPF::Server->new(hostname => 'mx.example.com');
    my $request = Mail::SPF::Request->new(
        identity        => "foo\r\nX-Forged: yes\@example.com",
        helo_identity   => "mta.example.com\r\nX-Forged: yes",
        ip_address      => '192.168.0.1'
    );
    my $result  = Mail::SPF::Result::PermError->new($server, $request,
        "Junk ) client-ip=10.0.0.1; receiver=victim.example.org (");
    my $header  = $result->received_spf_header;

    unlike($header, qr/[\r\n]/,                         'Received-SPF header contains no CR/LF');
    like($header, qr/envelope-from="foo\\\\x0d\\\\x0aX-Forged: yes\@example\.com"/,
                                                        'Received-SPF header escapes CR/LF in identity');
    like($header, qr/helo="mta\.example\.com\\\\x0d\\\\x0aX-Forged: yes"/,
                                                        'Received-SPF header escapes CR/LF in HELO identity');
    like($header, qr/Junk \\\) client-ip=10\.0\.0\.1; receiver=victim\.example\.org \\\(\)/,
                                                        'Received-SPF header escapes parentheses in comment');
    my $stripped = $header;
    $stripped =~ s/\\.//g;  # Remove quoted-pairs.
    my $depth = 0;
    for (split(//, $stripped)) { $depth++ if $_ eq '('; $depth-- if $_ eq ')'; last if $depth < 0 }
    $stripped =~ s/\([^()]*\)//;  # Remove the (now unnested) comment.
    my @client_ips = $stripped =~ /\bclient-ip=([^;\s]+)/g;
    is_deeply(\@client_ips, ['192.168.0.1'],            'Received-SPF header has only the genuine client-ip');
    is($depth, 0,                                       'Received-SPF header comment parentheses are balanced');
}


#### authority_explanation() escaping ####

{
    my $server  = Mail::SPF::Server->new(hostname => 'mx.example.com');
    my $request = Mail::SPF::Request->new(
        identity        => 'foo@example.com',
        ip_address      => '192.168.0.1'
    );
    $request->state('authority_explanation', Mail::SPF::MacroString->new(
        text            => "Rejected\r\nX-Forged: yes for %{d}",
        server          => $server,
        request         => $request,
        is_explanation  => 1
    ));
    my $explanation = Mail::SPF::Result::Fail->new($server, $request)->authority_explanation;

    unlike($explanation, qr/[\r\n]/,                    'Fail result authority_explanation() contains no CR/LF');
    is($explanation, 'Rejected\x0d\x0aX-Forged: yes for example.com',
                                                        'Fail result authority_explanation() escapes CR/LF');
}


#### authority_explanation() with 'p' macros ####

{
    my %zone = (
        '9.0.168.192.in-addr.arpa'  => [ 'PTR mail.example.com' ],
        'mail.example.com'          => [ 'A 192.168.0.9' ]
    );
    my @queries;
    my $resolver = Net::DNS::Resolver::Programmable->new(
        resolver_code   => sub {
            my ($domain, $rr_type) = @_;
            push(@queries, "$rr_type $domain");
            my @rrs = grep($_->type eq $rr_type,
                map(Net::DNS::RR->new("$domain 60 IN $_"), @{$zone{$domain} || []}));
            return ($zone{$domain} ? 'NOERROR' : 'NXDOMAIN', undef, @rrs);
        }
    );

    my $authority_explanation = sub {
        my ($ip_address, %server_options) = @_;
        my $server = Mail::SPF::Server->new(
            hostname        => 'mx.example.com',
            dns_resolver    => $resolver,
            %server_options
        );
        my $request = Mail::SPF::Request->new(
            identity        => 'foo@example.com',
            ip_address      => $ip_address
        );
        $request->state('authority_explanation', Mail::SPF::MacroString->new(
            text            => join(' ', ('%{p}') x 50),
            server          => $server,
            request         => $request,
            is_explanation  => 1
        ));
        @queries = ();
        return eval { Mail::SPF::Result::Fail->new($server, $request)->authority_explanation } || $@;
    };

    my $explanation = $authority_explanation->('192.168.0.9');
    is($explanation, join(' ', ('mail.example.com') x 50),
                                                        'Fail result authority_explanation() expands many p macros');
    is_deeply(\@queries, ['PTR 9.0.168.192.in-addr.arpa', 'A mail.example.com'],
                                                        'Fail result authority_explanation() looks up p macro value once');

    # Unanswered PTR look-ups count as void look-ups, but exceeding the limit
    # while expanding the explanation must not make authority_explanation() die:
    $explanation = $authority_explanation->('192.168.0.10', max_void_dns_lookups => 0);
    ok((not ref($explanation)),                         'Fail result authority_explanation() survives void look-ups limit')
        or diag("Exception: $explanation");
    like($explanation, qr/^Rejected by SPF record\.$/,          'Fail result authority_explanation() falls back to default explanation');
}
