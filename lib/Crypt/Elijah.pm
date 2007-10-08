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

=head1 NOTES

This module is experimental software.
Please do not rely on the security of this software.

This module is not intended for bulk encryption.
It is more suitable for processing passwords.  
If you pass a large amount of data to encrypt() or decrypt(), it can take a really long time.

It is a good idea to remove redundancy from your data prior to encryption.
This may be achieved using compression.
Redundancy in your data may allow an attacker to discover information from the ciphertext.

=head1 AUTHOR

Copyright (c) 2007 Michael W. Bombardieri

This software is released under the same license as Perl itself. 
See the Perl README for details.

=head1 DEDICATION

This software is dedicated to Elijah DePiazza.

=cut


package Elijah;

use 5.006;
use strict;
use warnings;
use bytes;
use Carp;

our $VERSION = '0.06';


sub _check_key_args { # set_key($key)
	if (!defined($_[0])) {
		croak("Argument undefined");
	} elsif (ref($_[0])) {
		croak("Argument shouldn't be a reference");
	} elsif (length($_[0]) < 12) { # min. 96 bit
		croak("Key is too short");
	} elsif (length($_[0]) > 16) { # max. 128 bit
		carp("Warning: truncating key to 16 bytes");
		$_[0] = substr($_[0], 0, 16);
	}	
}
 
sub _check_enc_args { # encrypt($text, $keyref)
	if (!defined($_[0]) || !defined($_[1])) {
		croak("Argument undefined");
	} elsif (ref($_[0])) {
		croak("Text argument shouldn't be a reference");
	} elsif (!ref($_[1])) {
		croak("Key argument isn't a reference");
	}
}

sub _salt { # 4 bytes
	my @x = (66, 70, 241, 196);
	my $padder;

	$x[0] ^= int(rand(256)); $x[1] ^= int(rand(256));
	$x[2] ^= int(rand(256)); $x[3] ^= int(rand(256));
	$padder = pack("C4", @x);
	return $padder;
}

sub _enc { # encrypt some text
	my $len = length($_[0]); # text length
	my @t = unpack("C$len", $_[0]); # unpacked text
	my $s = $_[1]; # reference to keystream array
	my $pc = $$s[359];
	my $i;

	for ($i = 0; $i < $len; $i++) {
		$t[$i] = ($t[$i] + $pc) % 256;
		$t[$i] ^= $$s[$i % 360];
		$pc = ($t[$i] + $i) % 256;
	}
	$_[0] = pack("C$len", @t);
}

sub _encp { # wrapper for probabilistic encryption
	$_[0] = _salt() . $_[0]; # grow the plaintext	
	_enc(@_);
}

sub _dec { # decrypt some text
	my $len = length($_[0]); # text length
	my @t = unpack("C$len", $_[0]); # unpacked text
	my $s = $_[1]; # reference to keystream array
	my $pc = $$s[359];
	my ($a, $i); # temporary

	for ($i = 0; $i < $len; $i++) {
		$a = $t[$i];
		$t[$i] ^= $$s[$i % 360];
		$t[$i] = ($t[$i] - $pc) % 256;
		$pc = ($a + $i) % 256;
	}
	$_[0] = pack("C$len", @t);
}

sub _decp { # wrapper for probabilistic encryption
	_dec(@_);
	$_[0] = substr($_[0], 4);
}

# enable probabilistic encryption by default
my $_encrypt = \&_encp;
my $_decrypt = \&_decp;

sub encrypt {
	_check_enc_args(@_);
	&$_encrypt(@_);
}

sub decrypt {
	_check_enc_args(@_);
	&$_decrypt(@_);
}

sub switch { # enable/disable probabilistic encryption
	if (\&_enc == $_encrypt) {
		$_encrypt = \&_encp;
		$_decrypt = \&_decp;
	} else {
		$_encrypt = \&_enc;
		$_decrypt = \&_dec;
	}
}

sub probable { # return true if probabilistic encryption is enabled
	return ($_encrypt == \&_encp) ? 1 : 0;
}

sub set_key { # allocate keystream and return reference
	_check_key_args(@_);

	my @k = (); # unpacked user key
	my @s = (); # keystream
	my ($a, $b, $c, $d, $e, $pc, $i); # temporary
	my $key_len = length($_[0]);

	# pad a short key
	if ($key_len < 16) {
		$a = 16 - $key_len;
		$b = "\0" x $a;
		$_[0] = $b . $_[0];
	}

	# prepare keystream
	@k = unpack("C16", $_[0]);
	$pc = 21;
	for ($i = 360; $i > 0; $i--) {
		$a = $i % 256; 
		$b = $a % 16;
		$c = ($b + 1) * ($b + 1);
		$d = ($c + $a) % 256;
		$e = ($d + $k[$b] + $pc) % 256;
		$pc = $e;
		push(@s, $e);
	}
	return \@s;
}

1;
