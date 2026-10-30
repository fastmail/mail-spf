use strict;
use warnings;
use blib;

use Test::More tests => 6;

use Mail::SPF::Request;


#### Class Compilation ####

BEGIN { use_ok('Mail::SPF::Mech::IP6') }


#### match() ####

{
    my $mech     = Mail::SPF::Mech::IP6->new_from_string('ip6:2001:db8::/32');
    my $mech_all = Mail::SPF::Mech::IP6->new_from_string('ip6:::/0');
    my $mech_v4_mapped
                 = Mail::SPF::Mech::IP6->new_from_string('ip6:::ffff:0:0/96');

    my $match = sub {
        my ($mech, $ip_address) = @_;
        my $request = Mail::SPF::Request->new(
            identity    => 'foo@example.com',
            ip_address  => $ip_address
        );
        return $mech->match(undef, $request) ? 1 : 0;
    };

    is($match->($mech, '2001:db8::1'),          1,      'IP6 mech match() IPv6 address in network');
    is($match->($mech, '2001:db9::1'),          0,      'IP6 mech match() IPv6 address not in network');
    is($match->($mech_all, '192.168.0.1'),      0,      'IP6 mech match() IPv4 address never matches');
    is($match->($mech_v4_mapped, '192.168.0.1'),
                                                0,      'IP6 mech match() IPv4 address never matches IPv4-mapped network');
    is($match->($mech_v4_mapped, '::ffff:192.168.0.1'),
                                                0,      'IP6 mech match() IPv4-mapped IPv6 address never matches');
}
