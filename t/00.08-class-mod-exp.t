use strict;
use warnings;
use blib;

use Net::DNS::Resolver::Programmable;
use Net::DNS::RR;

use Test::More tests => 7;

use Mail::SPF::Server;
use Mail::SPF::Request;


#### Class Compilation ####

BEGIN { use_ok('Mail::SPF::Mod::Exp') }


#### process() with invalid explanation strings (RFC 7208, 6.2) ####

{
    my %zone = (
        'example.com'           => [ 'TXT "v=spf1 -all exp=exp.example.com"' ],
        'exp.example.com'       => []
    );

    my $server = Mail::SPF::Server->new(
        dns_resolver    => Net::DNS::Resolver::Programmable->new(
            resolver_code   => sub {
                my ($domain, $rr_type) = @_;
                my @rrs = grep($_->type eq $rr_type,
                    map(Net::DNS::RR->new("$domain 60 IN $_"), @{$zone{$domain} || []}));
                return ($zone{$domain} ? 'NOERROR' : 'NXDOMAIN', undef, @rrs);
            }
        )
    );

    my $authority_explanation = sub {
        my ($explanation_txt) = @_;
        $zone{'exp.example.com'} = [ "TXT $explanation_txt" ];
        my $result = $server->process(Mail::SPF::Request->new(
            identity    => 'foo@example.com',
            ip_address  => '192.168.0.1'
        ));
        return $result->authority_explanation;
    };

    is($authority_explanation->('"Go away, %{d}!"'),        'Go away, example.com!',
                                                        'Exp mod process() valid explanation');
    is($authority_explanation->('"Go away\013\010result=pass"'), 'Rejected by SPF record.',
                                                        'Exp mod process() explanation with CR/LF ignored');
    is($authority_explanation->('"Go\009away"'),            'Rejected by SPF record.',
                                                        'Exp mod process() explanation with tab ignored');
    is($authority_explanation->('"Go away\027[2J"'),        'Rejected by SPF record.',
                                                        'Exp mod process() explanation with escape character ignored');
    is($authority_explanation->('"Caf\195\169"'),           'Rejected by SPF record.',
                                                        'Exp mod process() explanation with non-ASCII characters ignored');
    is($authority_explanation->('"Go away %x"'),            'Rejected by SPF record.',
                                                        'Exp mod process() explanation with invalid macro ignored');
}
