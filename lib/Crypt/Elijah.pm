package Elijah;

use 5.006;
use bytes;
use Carp;

our $VERSION = '0.07';

sub _encrypt {
    if (   !defined( $_[0] )
        || !defined( $_[1] )
        || ref( $_[0] )
        || !ref( $_[1] ) )
    {
        croak('Argument invalid');
    }
    my $len = length( $_[0] );
    my @t   = unpack( 'C' . $len, $_[0] );
    my $s   = $_[1];
    my $pc  = $$s[359];
    my $i;
    for ( $i = 0 ; $i < $len ; $i++ ) {
        $t[$i] = ( $t[$i] + $pc ) % 256;
        $t[$i] ^= $$s[ $i % 360 ];
        $pc = ( $t[$i] + $i ) % 256;
    }
    $_[0] = pack( 'C' . $len, @t );
}

sub _decrypt {
    if (   !defined( $_[0] )
        || !defined( $_[1] )
        || ref( $_[0] )
        || !ref( $_[1] ) )
    {
        croak('Argument invalid');
    }
    my $len = length( $_[0] );
    my @t   = unpack( 'C' . $len, $_[0] );
    my $s   = $_[1];
    my $pc  = $$s[359];
    my ( $a, $i );
    for ( $i = 0 ; $i < $len ; $i++ ) {
        $a = $t[$i];
        $t[$i] ^= $$s[ $i % 360 ];
        $t[$i] = ( $t[$i] - $pc ) % 256;
        $pc = ( $a + $i ) % 256;
    }
    $_[0] = pack( 'C' . $len, @t );
}

sub encrypt {
    if (   !defined( $_[0] )
        || !defined( $_[1] )
        || ref( $_[0] )
        || !ref( $_[1] ) )
    {
        croak('Argument invalid');
    }
    my @x = ( 66, 70, 241, 196 );
    $x[0] ^= int( rand(256) );
    $x[1] ^= int( rand(256) );
    $x[2] ^= int( rand(256) );
    $x[3] ^= int( rand(256) );
    $_[0] = pack( 'C4', @x ) . $_[0];
    my $len = length( $_[0] );
    my @t   = unpack( 'C' . $len, $_[0] );
    my $s   = $_[1];
    my $pc  = $$s[359];
    my $i;

    for ( $i = 0 ; $i < $len ; $i++ ) {
        $t[$i] = ( $t[$i] + $pc ) % 256;
        $t[$i] ^= $$s[ $i % 360 ];
        $pc = ( $t[$i] + $i ) % 256;
    }
    $_[0] = pack( 'C' . $len, @t );
}

sub decrypt {
    if (   !defined( $_[0] )
        || !defined( $_[1] )
        || ref( $_[0] )
        || !ref( $_[1] ) )
    {
        croak('Argument invalid');
    }
    my $len = length( $_[0] );
    my @t   = unpack( 'C' . $len, $_[0] );
    my $s   = $_[1];
    my $pc  = $$s[359];
    my ( $a, $i );
    for ( $i = 0 ; $i < $len ; $i++ ) {
        $a = $t[$i];
        $t[$i] ^= $$s[ $i % 360 ];
        $t[$i] = ( $t[$i] - $pc ) % 256;
        $pc = ( $a + $i ) % 256;
    }
    $_[0] = pack( 'C' . $len, @t );
    $_[0] = substr( $_[0], 4 );
}

sub set_key {
    if ( !defined( $_[0] ) || ref( $_[0] ) || ( length( $_[0] ) < 12 ) ) {
        croak('Argument invalid');
    }
    my @k      = ();
    my @s      = ();
    my $keylen = length( $_[0] );
    my ( $a, $b, $c, $d, $e, $pc, $i );
    if ( $keylen < 16 ) {
        $a    = 16 - $keylen;
        $b    = "\0" x $a;
        $_[0] = $b . $_[0];
    }
    @k = unpack( 'C16', $_[0] );
    $pc = 21;
    for ( $i = 360 ; $i > 0 ; $i-- ) {
        $a  = $i % 256;
        $b  = $a % 16;
        $c  = ( $b + 1 ) * ( $b + 1 );
        $d  = ( $c + $a ) % 256;
        $e  = ( $d + $k[$b] + $pc ) % 256;
        $pc = $e;
        push( @s, $e );
    }
    return \@s;
}

1;

=head1 NAME

Crypt::Elijah - cipher module 

=head1 SYNOPSIS

    use Crypt::Elijah;

    $text = 'secretive';
    $key = '0123456789abcdef'; 
    $keyref = Elijah::set_key($key);
    Elijah::encrypt($text, $keyref);
    Elijah::decrypt($text, $keyref);

=head1 DESCRIPTION

This module provides a pure Perl implementation of the Elijah cipher.
The module consists of the following functions: set_key(), encrypt(), and decrypt().

Call set_key() to prepare the encryption key.
This function takes a single argument: a packed string containing your key.
The key must be at least 12 bytes long.
Keys longer than 16 bytes are truncated.
This function returns a reference to the prepared key.

Call encrypt() and decrypt() to process your data.
These functions take two arguments.
The first argument is a string containing your data.
The second argument is a reference returned by set_key().
Salt is added to your data; ciphertext will always be larger than the corresponding plaintext.

=head1 BUGS

It is a good idea to remove redundancy from your data prior to encryption (e.g. using compression); this module has no built-in mechanism for achieving this.
Redundancy in your data may allow information to be discovered from the ciphertext.

This module is not intended for bulk encryption.  
If you pass a large amount of data to encrypt() or decrypt(), it can take a really long time.

This module is experimental software -- use at your own risk.

=head1 AUTHOR

Michael W. Bombardieri <bombardierix@gmail.com>

=head1 COPYRIGHT

Copyright 2007 Michael W. Bombardieri.

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=head1 DEDICATION

This software is dedicated to Elijah DePiazza.

=cut
