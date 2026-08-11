#
# Mail::SPF::BlackMagic
# Server class implementing spfquery's/spfd's "black magic" options.
#
# (C) 2026 Giovanni Bechis <g.bechis@snb.it>
#
##############################################################################

package Mail::SPF::BlackMagic;

=head1 NAME

Mail::SPF::BlackMagic - Server class implementing the "black magic" options

=cut

# VERSION

use warnings;
use strict;

use base 'Mail::SPF::Server';

use Error ':try';

use Mail::SPF::Record;

use constant TRUE   => (0 == 0);
use constant FALSE  => not TRUE;

# Interface:
##############################################################################

=head1 SYNOPSIS

    use Mail::SPF::BlackMagic;

    my $spf_server  = Mail::SPF::BlackMagic->new(
        guess       => 'a mx -all',
        local       => 'mx:mydomain.example.org',
        override    => { 'example.org' => 'v=spf1 -all' },
        fallback    => { 'example.com' => 'v=spf1 -all' }
    );

    my $result      = $spf_server->process($request);

=cut

# Implementation:
##############################################################################

=head1 DESCRIPTION

B<Mail::SPF::BlackMagic> is a I<Mail::SPF::Server> sub-class that implements the
options that earlier versions of B<spfquery> and B<spfd> supported but that are
considered "black magic" (i.e. potentially dangerous for the innocent user) and
are therefore disabled unless this module is installed and B<--enable-black-magic>
is specified.  See the C<spfquery(1)> man-page for a description of these
options from the command-line tool's perspective.

This module follows the extension recipe described in the top-level C<README>
file: it sub-classes I<Mail::SPF::Server> and overrides C<select_record> and
C<process> to implement its additional behavior.

=head2 Constructor

The following constructor is provided:

=over

=item B<new(%options)>: returns I<Mail::SPF::BlackMagic>

Creates a new server object for processing SPF requests with black magic
enabled.  In addition to all options supported by
L<Mail::SPF::Server's C<new> constructor|Mail::SPF::Server/new>, the following
options are supported:

=over

=item B<authorize_mxes_for>

A reference to an I<array> of domains and e-mail addresses whose MXes should be
considered inherently authorized senders.  E-mail addresses are reduced to
their domain part.

=item B<tfwl>

A I<boolean> denoting whether C<trusted-forwarder.org> accreditation checking
should be performed.

=item B<guess>

A I<string> of SPF terms (without a leading version tag) to use as a default
record if a domain does not publish an SPF record of its own.

=item B<local>

A I<string> of SPF terms to check as an authorization short-cut (for example,
to white-list secondary MXes) ahead of a domain's own default result.

=item B<override>

A reference to a I<hash> mapping domain patterns to SPF record strings.  A
domain pattern may be a plain domain name, or a wildcard pattern with a leading
C<*.> (for example, C<*.example.net>).  If a request's authority domain matches
a pattern, the associated record string is used instead of querying DNS at all.

=item B<fallback>

A reference to a I<hash> mapping domain patterns to SPF record strings, used the
same way as B<override>, except that the associated record string is only used
if querying DNS for the domain's own record fails with a DNS error.

=back

=cut

sub new {
    my ($self, %options) = @_;
    $self = $self->SUPER::new(%options);

    $self->{authorize_mxes_for} ||= [];
    $self->{override}           ||= {};
    $self->{fallback}           ||= {};

    return $self;
}

=back

=head2 Instance methods

In addition to all instance methods provided by I<Mail::SPF::Server>, the
following instance methods are overridden:

=over 4

=item B<select_record($request)>: returns I<Mail::SPF::Record>;
throws I<Mail::SPF::EDNSError>, I<Mail::SPF::ENoAcceptableRecord>,
I<Mail::SPF::ERedundantAcceptableRecords>, I<Mail::SPF::ESyntaxError>

Behaves like L<Mail::SPF::Server's C<select_record>|Mail::SPF::Server/select_record>,
except that:

=over

=item *

If the B<override> option contains an entry matching the request's authority
domain, the corresponding record is used instead of querying DNS.

=item *

If querying DNS fails with a DNS error and the B<fallback> option contains a
matching entry, the corresponding record is used instead.

=item *

If the domain publishes no acceptable SPF record at all and the B<guess>
option is set, a record synthesized from it is used instead.

=back

=cut

sub select_record {
    my ($self, $request) = @_;

    my $domain = $request->authority_domain;

    my $override_text = $self->_matching_pattern_value($self->{override}, $domain);
    return $self->_record_from_string($override_text) if defined($override_text);

    my $record;
    try {
        $record = $self->SUPER::select_record($request);
    }
    catch Mail::SPF::EDNSError with {
        my $exception = shift;
        my $fallback_text = $self->_matching_pattern_value($self->{fallback}, $domain);
        defined($fallback_text)
            or $exception->throw;
        $record = $self->_record_from_string($fallback_text);
    }
    catch Mail::SPF::ENoAcceptableRecord with {
        my $exception = shift;
        defined($self->{guess})
            or $exception->throw;
        $record = $self->_record_from_string("v=spf1 $self->{guess}");
    };

    return $record;
}

=item B<process($request)>: returns I<Mail::SPF::Result>

Behaves like L<Mail::SPF::Server's C<process>|Mail::SPF::Server/process>, except
that, before evaluating the domain's own SPF record, it first checks the
B<authorize_mxes_for>, B<local>, and B<tfwl> options (if any are set) as an
inherent-authorization short-cut, immediately returning a C<pass> result if one
of them matches.

=cut

sub process {
    my ($self, $request) = @_;

    my @extra_terms = $self->_extra_terms;
    if (@extra_terms) {
        my $extra_record = $self->_record_from_string(
            'v=spf1 ' . join(' ', @extra_terms) . ' ?all');
        my $result;
        try {
            $extra_record->eval($self, $request);
        }
        catch Mail::SPF::Result with {
            $result = shift;
        };
        return $result if defined($result) and $result->code eq 'pass';
    }

    return $self->SUPER::process($request);
}

=back

=cut

sub _extra_terms {
    my ($self) = @_;
    my @terms;
    push(@terms, map("mx:$_", @{$self->{authorize_mxes_for}}));
    push(@terms, $self->{local}) if defined($self->{local});
    push(@terms, 'exists:%{ir}.wl.trusted-forwarder.org') if $self->{tfwl};
    return @terms;
}

sub _record_from_string {
    my ($self, $text) = @_;
    my $record;
    foreach my $version (sort { $b <=> $a } keys(%{$self->record_classes_by_version})) {
        my $class = $self->record_classes_by_version->{$version};
        eval("require $class");
        try {
            $record = $class->new_from_string($text);
        }
        catch Mail::SPF::EInvalidRecordVersion with {};
        last if defined($record);
    }
    return $record;
}

sub _matching_pattern_value {
    my ($self, $patterns, $domain) = @_;
    foreach my $pattern (keys(%$patterns)) {
        return $patterns->{$pattern} if $self->_match_domain_pattern($pattern, $domain);
    }
    return undef;
}

sub _match_domain_pattern {
    my ($self, $pattern, $domain) = @_;
    if ($pattern =~ /^\*\.(.+)$/) {
        my $suffix = quotemeta(lc($1));
        return lc($domain) =~ /(?:^|\.)$suffix$/;
    }
    return lc($pattern) eq lc($domain);
}

=head1 SEE ALSO

L<Mail::SPF>, L<Mail::SPF::Server>, L<Mail::SPF::Request>, L<Mail::SPF::Result>

For availability, support, and license information, see the README file
included with Mail::SPF.

=head1 AUTHORS

Giovanni Bechis <g.bechis@snb.it>

=cut

TRUE;
