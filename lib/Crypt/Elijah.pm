package Crypt::Elijah;

use Carp;
use bytes;
use vars qw($VERSION @ISA @EXPORT);

require Exporter;
@ISA    = qw(Exporter);
@EXPORT = qw(el_key el_encrypt el_decrypt _el_encrypt _el_decrypt);

$VERSION = '0.09';

sub el_key {
    croak('Bad arg')
      if ( !defined( $_[0] ) || ref( $_[0] ) || ( length( $_[0] ) < 12 ) );
    my ( @k, @s, $a, $b, $c, $d, $e, $i, $pc );
    if ( length( $_[0] ) < 16 ) {
        $a    = 16 - length( $_[0] );
        $b    = "\0" x $a;
        $_[0] = $b . $_[0];
    }
    $pc = 21;
    @k = unpack( 'C16', $_[0] );
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

sub _el_encrypt {
    croak('Bad arg')
      if ( !defined( $_[0] )
        || !defined( $_[1] )
        || ref( $_[0] )
        || !ref( $_[1] ) );
    my ( @t, $len, $s, $pc, $i );
    $len = length( $_[0] );
    @t   = unpack( 'C' . $len, $_[0] );
    $s   = $_[1];
    $pc  = $$s[359];
    for ( $i = 0 ; $i < $len ; $i++ ) {
        $t[$i] = ( $t[$i] + $pc ) % 256;
        $t[$i] ^= $$s[ $i % 360 ];
        $pc = ( $t[$i] + $i ) % 256;
    }
    $_[0] = pack( 'C' . $len, @t );
}

sub el_encrypt {
    croak('Bad arg')
      if ( !defined( $_[0] )
        || !defined( $_[1] )
        || ref( $_[0] )
        || !ref( $_[1] ) );
    $_[0] = pack(
        'N',
        (
            ( ( int( rand(0xFFFF) ) << 16 ) + int( rand(0xFFFF) ) ) ^ 0x19860719
        )
    ) . $_[0];
    my ( @t, $len, $s, $pc, $i );
    $len = length( $_[0] );
    @t   = unpack( 'C' . $len, $_[0] );
    $s   = $_[1];
    $pc  = $$s[359];
    for ( $i = 0 ; $i < $len ; $i++ ) {
        $t[$i] = ( $t[$i] + $pc ) % 256;
        $t[$i] ^= $$s[ $i % 360 ];
        $pc = ( $t[$i] + $i ) % 256;
    }
    $_[0] = pack( 'C' . $len, @t );
}

sub _el_decrypt {
    croak('Bad arg')
      if ( !defined( $_[0] )
        || !defined( $_[1] )
        || ref( $_[0] )
        || !ref( $_[1] ) );
    my ( @t, $len, $s, $pc, $i, $a );
    $len = length( $_[0] );
    @t   = unpack( 'C' . $len, $_[0] );
    $s   = $_[1];
    $pc  = $$s[359];
    for ( $i = 0 ; $i < $len ; $i++ ) {
        $a = $t[$i];
        $t[$i] ^= $$s[ $i % 360 ];
        $t[$i] = ( $t[$i] - $pc ) % 256;
        $pc = ( $a + $i ) % 256;
    }
    $_[0] = pack( 'C' . $len, @t );
}

sub el_decrypt {
    croak('Bad arg')
      if ( !defined( $_[0] )
        || !defined( $_[1] )
        || ref( $_[0] )
        || !ref( $_[1] ) );
    my ( @t, $len, $s, $pc, $i, $a );
    $len = length( $_[0] );
    @t   = unpack( 'C' . $len, $_[0] );
    $s   = $_[1];
    $pc  = $$s[359];
    for ( $i = 0 ; $i < $len ; $i++ ) {
        $a = $t[$i];
        $t[$i] ^= $$s[ $i % 360 ];
        $t[$i] = ( $t[$i] - $pc ) % 256;
        $pc = ( $a + $i ) % 256;
    }
    $_[0] = pack( 'C' . $len, @t );
    $_[0] = substr( $_[0], 4 );
}

1;

=head1 NAME

Crypt::Elijah - cipher module 

=head1 SYNOPSIS

    use Crypt::Elijah;

    $text = 'secretive';
    $key = '0123456789abcdef'; 
    $keyref = el_key($key);
    el_encrypt($text, $keyref);
    el_decrypt($text, $keyref);

=head1 DESCRIPTION

This module provides a pure Perl implementation of the Elijah cipher.
The module exports the following functions: el_key(), el_encrypt() and 
el_decrypt().

Call el_key() to prepare the encryption key.
This function takes a single argument: a packed string containing your key.
The key must be at least 12 bytes long.
Keys longer than 16 bytes are truncated.
This function returns a reference to the prepared key.

Call el_encrypt() and el_decrypt() to process your data.
These functions take two arguments.
The first argument is a string containing your data.
The second argument is a reference returned by el_key().
Salt is added to your data; ciphertext will always be larger than the 
corresponding plaintext.

=head1 BUGS

This module is not intended for bulk encryption.
It would be more sensible to use an XS encryption module for processing large 
amounts of data.

It is a good idea to remove redundancy from your data prior to encryption (e.g. 
using compression); this module has no built-in mechanism for achieving this.
Redundancy in your data may allow information to be discovered from the 
ciphertext.

This module is experimental software and should be used with caution.
Please report any bugs to the author.

=head1 AUTHOR

Michael W. Bombardieri <bombardierix@gmail.com>

=head1 COPYRIGHT

Copyright 2007 Michael W. Bombardieri.

This program is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself.

=head1 DEDICATION

This software is dedicated to Elijah DePiazza.

=cut
