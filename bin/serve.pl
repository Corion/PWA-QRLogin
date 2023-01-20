#!perl
use strict;
use warnings;
use Mojolicious::Lite;
use Mojo::JSON qw(decode_json encode_json);
use Mojo::File;
use charnames ':full';

use FindBin;
use lib "$FindBin::Bin/../../Weather-MOSMIX/lib";
use Weather::MOSMIX;

push @{app->static->paths} => "$FindBin::Bin/../public";

my $dbfile = app->config->{dbfile}
           || '../../Weather-MOSMIX/mosmix-forecast.sqlite';

$dbfile = Mojo::File->new($dbfile);
if( !$dbfile->is_abs ) {
    $dbfile = Mojo::File->new("$FindBin::Bin/$dbfile");
};

# If we have a precompressed resource, serve that
app->static->with_roles('+Compressed');

# Compress all dynamic resources as well
plugin 'Gzip';

my $w = Weather::MOSMIX->new(
    dbh => {
        dsn => "dbi:SQLite:dbname=$dbfile",
    },
);

get '/' => sub {
    my $c = shift;
    return $c->redirect_to('index.html');
};

post '/forecast' => sub {
    my $c = shift;
    my $query = decode_json( $c->req->body );
    my @locations = @{ $query->{'locations'} };

    my @res;
    for my $l (@locations) {
        my $f =
            $w->forecast_dbh(latitude => $l->{latitude}, longitude => $l->{longitude} );
        my $out = $w->format_forecast_dbh( $f, 6 );
        #$out->[0]->{utf8} = "\N{CHECK MARK}";
        push @res, $out;
    };
    my $res = { forecast => \@res };
    $c->render( json => $res );
};

# This is available as a static file already
#get '/locations.json' => sub {
#    my $c = shift;
#    my $res = $w->locations();
#    $c->render( json => $res );
#};


# Start the Mojolicious command system
app->start;
