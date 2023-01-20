#!perl
use strict;
use JSON::PP;
use Getopt::Long;
use Pod::Usage;
use POSIX 'strftime';
use File::Basename 'dirname';

GetOptions(
    'f' => \my $force,
    'm|manifest=s' => \my $manifest,
    'service-worker=s' => \my $sw_file,
    'version=s' => \my $version,
) or pod2usage(2);

$sw_file ||= 'public/sw.js';
my $base_dir = dirname $sw_file;
$manifest ||= "$base_dir/manifest.json";

open my $fh, '<:encoding(UTF-8)', $sw_file
    or die "Couldn't read '$sw_file': $!";
my $sw = do { local $/; <$fh> };

#      return cache.addAll(
#        [ /* All resources that are fit to store */
#          '/index.html',
#          '/sw.js',
#          '/manifest.json',
#          '/js/localforage.min-1.7.3.js',
#          '/js/handlebars-v4.1.2.js',
#          '/js/morphdom-2.5.4.js',
#          '/css/bootstrap-3.4.1.min.css',
#          '/app.css'
#          // '/offline.html'
#        ]
#      );

$sw =~ m!cache.addAll\(\s+\[([^\]]+)\]!ms
    or die "Couldn't read cache.addAll() stanza from '$sw_file'";
my $cache_string = $1;
my @cached_files = map { "$base_dir/$_" } ($cache_string =~ /^\s+'([^']+)'/mg);

my $mtime = (stat($manifest))[9];
my $manifest_time = $mtime;
if( not defined $version ) {
    for my $f (@cached_files) {
        if( ! -f $f ) {
            warn "File '$f' not found?!";
        } else {
            my $ftime = (stat($f))[9];
            if( $ftime > $mtime ) {
                $mtime = $ftime;
            };
        };
    }
    $version = strftime '%Y%m%d.%H%M%S', gmtime($mtime);
} else {
    # Force an update, if the files differ
    $manifest_time = 0;
}

if( $mtime > $manifest_time or $force) {
    open my $fh, '<:raw', $manifest
        or die "Couldn't read '$manifest': $!";

    my $json = do { local $/; <$fh> };
    close $fh;
    my $data = decode_json( $json );
    $data->{version} = $version;

    my $new = encode_json( $data );
    if( $new ne $json ) {
        open my $fh, '>:raw', $manifest
            or die "Couldn't update '$manifest': $!";
        print $fh $new;
        print "Updated version number in '$manifest' to '$version'";
    };
}
