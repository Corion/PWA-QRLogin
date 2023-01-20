#!perl
use strict;
use warnings;
use Mojolicious::Lite -signatures;
use Mojo::JSON qw(decode_json encode_json);
use Mojo::File;
use MojoX::Session; # because we need a central session storage, not client-side
use charnames ':full';

use Authen::OATH;

use FindBin;

push @{app->static->paths} => "$FindBin::Bin/../public";

# If we have a precompressed resource, serve that
app->static->with_roles('+Compressed');

# Compress all dynamic resources as well
plugin 'Gzip';

my %credentials = (
    'demo' => { name => 'demo', password => 'demo', otp_secret => 'demo', },
);

plugin session => {store => 'dummy', expires_delta => 60*60};

get '/' => sub {
    my $c = shift;
    return $c->redirect_to('index.html');
};

get '/index' => sub {
    my $c = shift;
	
    my $session = $c->stash('session');
	my $username;

    # Check if we already have a session
    if ($session->load) {
		$username = $session->data('username');
	}
    return $c->render('index', username => $username );
};

sub validate_password( $username, $expected, $password ) {
	return $expected eq $password
}

sub validate_totp( $username, $ts, $secret, $totp ) {
	my $totp_alg = Authen::OATH->new($secret);
	return $totp_alg->totp($ts) == $totp
}

sub valid_login( $username, $credential_type, $credential ) {
	if( my $cred = $credentials{ $username } ) {
		if( my $expected = $cred->{ $credential_type } ) {
			if( $credential_type eq 'password' ) {
				return validate_password( $username, $expected, $credential )
			} elsif ( $credential_type eq 'totp' ) {
				my $ts = time();
				return validate_totp( $username, $ts, $expected, $credential )
			} else {
				return undef
			}
		}
	} else {
		return undef
	}
}

get '/login' => sub( $c ) {
    my $session = $c->stash('session');
	# create a fresh session if necessary
	$session->load or $session->create;
	$session->flush;
    return $c->render('login');
};

post '/login' => sub( $c ) {
	my $target = $c->param('target') // 'index.html';
	my $account = $c->param('account');
	my $cred_type = $c->param('credential_type');
	my $credential = $c->param('credential');

    my $session = $c->stash('session');
    $session->load or $session->create; # well, we should have a session here?!
	
	my $next = $c->url_for('/login', { target => $target });
	if( ! $account ) {
	} elsif( valid_login( $account, $cred_type, $credential )) {
		$session->data( username => $account );
	}
	
    $c->redirect( $target );
};

# Start the Mojolicious command system
app->start;

__DATA__
@@ index.html.ep
<!DOCTYPE html>
<html>
% if( defined $username ) {
	<p>Welcome <%= $username %></p>
% } else {
	<p>Please <a href="login.html">log in</a></p>
% }
</html>