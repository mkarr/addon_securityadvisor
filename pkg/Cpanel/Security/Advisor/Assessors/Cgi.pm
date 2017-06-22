package Cpanel::Security::Advisor::Assessors::Cgi;

# Copyright (c) 2017, cPanel, Inc.
# All rights reserved.
# http://cpanel.net
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the owner nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL  BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;

use base 'Cpanel::Security::Advisor::Assessors';

use File::Spec ();

use Cpanel::Config::Users   ();
use Cpanel::DomainLookup    ();
use Cpanel::FindBin         ();
use Cpanel::SafeRun::Object ();

sub generate_advice {
    my ($self) = @_;
    $self->_check_cgiemail_rpm();
    $self->_check_cgiemail_docroots();
    return 1;
}

sub _check_cgiemail_rpm {
    my ($self) = @_;

    my $rpm_bin = Cpanel::FindBin::findbin('rpm');
    my $run     = Cpanel::SafeRun::Object->new(
        program => $rpm_bin,
        args    => [ '-q', 'cpanel-cgiemail' ],
    );

    my $error_code = $run->error_code() || 0;

    if ( $run->error_code() ) {
        $self->add_good_advice(
            'key'  => 'Cgi_cgiemail_rpm_not_present',
            'text' => $self->_lh->maketext("The cgiemail RPM does not appear to be installed on the server.")
        );
    }
    else {
        $self->add_bad_advice(
            'key'        => 'Cgi_cgiemail_rpm_present',
            'text'       => $self->_lh->maketext('The cgiemail RPM is installed on the server.'),
            'suggestion' => $self->_lh->maketext('Run ‘/usr/local/cpanel/scripts/clean_cgiemail --rpm’ on the command line to uninstall the RPM.'),
        );
    }

    return 1;
}

sub _check_cgiemail_docroots {
    my ($self) = @_;

    my $found = 0;

    for my $user ( Cpanel::Config::Users::getcpusers() ) {
        for my $docroot ( Cpanel::DomainLookup::getdocroots($user) ) {
            for my $file ( map { File::Spec->catfile( $docroot, 'cgi-bin', $_ ) } qw { cgiemail cgiecho } ) {
                if ( -f $file ) {
                    $found++;
                }
            }
        }
    }

    if ($found) {
        $self->add_bad_advice(
            'key'        => 'Cgi_cgiemail_docroots_found',
            'text'       => $self->_lh->maketext("Copies of the cgiemail or cgiecho scripts found in users’ cgi-bin directories."),
            'suggestion' => $self->_lh->maketext('Run ‘/usr/local/cpanel/scripts/clean_cgiemail --docroot’ on the command line to remove these copies.'),
        );
    }
    else {
        $self->add_good_advice(
            'key'  => 'Cgi_cgiemail_docroots_not_found',
            'text' => $self->_lh->maketext("No copies of the cgiemail or cgiecho scripts found in users’ cgi-bin directories.")
        );
    }

    return 1;
}

1;
