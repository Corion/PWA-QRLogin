#!perl
use strict;
use warnings;
use Mojolicious::Lite -signatures;
use Mojo::JSON qw(decode_json encode_json);
use Mojo::File;
use DBI;
use MojoX::Session::Store::Dbi;

use lib '../mojox-session/lib';

use MojoX::Session; # because we need a central session storage, not client-side
use charnames ':full';

use Authen::OATH;
use Imager::QRCode 'plot_qrcode';

use FindBin;

push @{app->static->paths} => "$FindBin::Bin/../public";

# If we have a precompressed resource, serve that
app->static->with_roles('+Compressed');

# Compress all dynamic resources as well
plugin 'Gzip';

my %credentials = (
    'demo' => { name => 'demo', password => 'demo', otp_secret => 'demo', },
);


my $dbh = DBI->connect('dbi:SQLite:dbname=:memory:');
$dbh->do(<<'SQL');
    CREATE TABLE session (
        sid          VARCHAR(40) PRIMARY KEY,
        data         TEXT,
        expires      INTEGER UNSIGNED NOT NULL,
        UNIQUE(sid)
    );
SQL

plugin session =>
      {stash_key => 'mojox-session', store => MojoX::Session::Store::Dbi->new(dbh  => $dbh), expires_delta =>  60*60};

get '/' => sub {
    my $c = shift;
    return $c->redirect_to('index.html');
};

get '/index.html' => sub {
    my $c = shift;

    my $session = $c->stash('mojox-session');
    my $username;

    # Check if we already have a session
    if ($session->load) {
        $username = $session->data('username');
    }
    return $c->render('index', username => $username );
};

sub validate_password( $username, $expected, $password ) {
    warn "$expected =/= $password?";
    return $expected eq $password
}

sub validate_totp( $username, $ts, $secret, $totp ) {
    my $totp_alg = Authen::OATH->new($secret);
    return $totp_alg->totp($ts) == $totp
}

sub valid_login( $username, $credential_type, $credential ) {
    if( my $cred = $credentials{ $username } ) {
        warn "Have credentials for '$username'";
        use Data::Dumper; warn Dumper $cred;
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
        warn "Unknown user '$username'";
        return undef
    }
}

get '/login.html' => sub( $c ) {
    my $session = $c->stash('mojox-session');

    my $username = $session->data('username');
    my $sid = $session->sid;

    return $c->render('login',
        username => $username,
        sid => $sid,
    );
};

sub qrcode_for( $str ) {
    my $img = plot_qrcode($str, {
        size          => 2,
        margin        => 2,
        version       => 1,
        level         => 'M',
        casesensitive => 1,
        lightcolor    => Imager::Color->new(255, 255, 255),
        darkcolor     => Imager::Color->new(0, 0, 0),
    });
    $img->write( data => \my $data, type => 'png' )
        or die $img->errstr;
warn sprintf "%d bytes of PNG", length($data);
    return $data
}

get 'qr.png' => sub( $c ) {
    my $url = $c->param('url');
    # Check that the URL is local to our server!
    $c->render( data => qrcode_for($url), format => 'png' );
};

helper qrcode_for_url => sub( $c, $url ) {
    return qrcode_for( $url )
};

get 'login-qrcode.png' => sub( $c ) {
    my $session = $c->stash('mojox-session');
    my $sid = $session->sid;
    my %payload = (
        target => $c->url_for('/login.html')->to_abs,
        sid    => $sid,
        # also add a nonce as another identifier
        nonce  => rand(),
        # add what information we want in return
        required => ['username', 'password', 'sid'],
        #required => ['username', 'totp'],
    );
    my $data = qrcode_for( encode_json(\%payload));
    $c->render( data => $data, format => 'png' );
};

post 'login.html' => sub( $c ) {
    my $target = $c->param('target') // '/';
    my $account = $c->param('account');
    my $cred_type = $c->param('credential_type');
    my $credential = $c->param('credential');

    my $session = $c->stash('mojox-session');
    #$session->load or $session->create; # well, we should have a session here?!

    my $next = $c->url_for('/login.html' )->query( target => $target );
    if( ! $account ) {
        # nothing to do here
        warn "No account passed in?!";

    } elsif( valid_login( $account, $cred_type, $credential )) {
        warn "Valid login for '$account' / '$cred_type' / '$credential'";

        # XXX check that $target is an URL on this host!
        $next = $target;
        $session->data( username => $account );
        $session->flush(); # this should not be necessary
    } else {
        warn "Invalid login credentials for $account / $cred_type";
    }

    $c->redirect_to( $next);
};

get '/logout.html' => sub( $c ) {
    my $session = $c->stash('mojox-session');

    my $username = $session->data('username');
    my $sid = $session->sid;
    $session->expire;

    return $c->redirect_to($c->url_for('login.html'));
};

# This is visited from the browser:
get '/setup-pwa.html' => sub( $c ) {
    my $session = $c->stash('mojox-session');
    my $sid = $session->sid;
    my $username = $session->data('username');

    if( ! $username ) {
        return $c->redirect_to($c->url_for('login.html'));

    } else {
        $c->render('setup-pwa',
            sid      => $sid,
            username => $username,
            # maybe add the totp, later
        );
    };
};

# This is the trampoline that never gets cached, as it has the SID
# in the URL
get '/login-pwa-setup' => sub( $c ) {
    my $session = $c->stash('mojox-session');

    my $sid = $c->param('sid');
    $session->load($sid);

    # never cache this URL
    $c->res->headers->cache_control('no-cache');

    if( $session->is_expired ) {
        # baaad user!
        # XXX Maybe let them log in via mobile and then return here?!
        $c->redirect_to($c->url_for('login.html')->to_abs);

    } else {
        $c->stash( sid => $sid );
        $c->redirect_to($c->url_for('login-pwa.html')->to_abs);
    }
};

# This is visited from the mobile and installs the PWA:
get '/login-pwa.html' => sub( $c ) {
    my $session = $c->stash('mojox-session');
    my $sid = $c->param('sid');
    $session->load($sid);

    if( $session->is_expired ) {
        # baaad user!
        $c->redirect_to($c->url_for('login.html')->to_abs);

    } else {

        my $username = $session->data('username');
        my $password = $credentials{ username }->{password};

        if( 0 ) {
            # Create a fresh totp:
            my $ts = time();
            my $totp = join "\0", app->secret, $username, $ts;
            $credentials{ $username }->{otp_secret} = 'totp';
        };

        $c->render('login-pwa.html',
            username => $username,
            password => $password,
            # maybe add the totp, later
        );
    }
};

# XXX in-browser confirmation for the OTP, just in case a session id leaks

# Start the Mojolicious command system
app->start;

__DATA__
@@ index.html.ep
<!DOCTYPE html>
<html>
% if( defined $username ) {
    <p>Welcome <%= $username %></p>
    <p>You can <a href="<%= url_for('logout.html') %>">log out</a>.</p>
    <p>You can <a href="<%= url_for('setup-pwa.html') %>">set up a QR code for login</a>.</p>
% } else {
    <p>Please <a href="<%= url_for('login.html') %>">log in</a></p>
% }
</html>

@@ login.html.ep
<!DOCTYPE html>
<html>
% if( defined $username ) {
    <p>You are already logged in as <b><%= $username %></b>. <a href="<%= url_for('logout.html') %>">Log out</a></p>
% } else {
    <h1>Login</h1>
    <form action="<%= url_for('login.html') %>" method="POST">
    <input type="hidden" name="credential_type" value="password" />
    <label for="username">Username</label><input type="text" name="account" /><br>
    <label for="password">Password</label><input type="password" name="credential" /><br>
    <div>
    <button type="submit">Log in</button>
    Log in using your mobile phone:<br>
    <img src="<%= url_for("/login-qrcode.png" )->query( sid => $sid )->to_abs %>" alt="Login QR code" />
    </div>
    <i><a href="/help.html">How do I use this?</a>
    </form>
% }
</html>

@@ setup-pwa.html.ep
<html>
<p>Hi <%= $username %></p>
<h1>Set up login via phone</h1>
<ol>
<li>Go to this URL with your phone:</li>
% my $url = url_for( 'login-pwa-setup' )->query( sid => $sid )->to_abs;
<img src="<%= url_for('qr.png')->query( url => $url ) %>" alt="QR code for login" />
<div><a href="<%= $url %>"> <%= $url %></div>
<li>Add the URL to your start screen as application</li>
<li>XXX this needs to be implemented:</li>
<li>Confirm the addition here</li>
<li>Done</li>
</ol>
</html>
