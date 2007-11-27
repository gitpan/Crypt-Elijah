use strict;
use Test;

BEGIN {
	plan tests => 2;
}

use Crypt::Elijah;

print('# Using Crypt::Elijah version ' . $Crypt::Elijah::VERSION . "\n");

sub test_api {
	my $key;
	my $keyref;
	my $text;
	my $code;
	my $tmp;
	my $plaintext;
	my $ciphertext;
	my $newciphertext;

	print("# el_key()\n");
	$code = '$keyref = el_key($key); 1;';

	print('# Testing normal key input (max. length)... ');
	undef($keyref);
	$key = '0123456789abcdef';
	if (eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	print('# Testing normal key input (min. length)... ');
	undef($keyref);
	$key = '0123456789ab';
	if (eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	print('# Testing invalid key input (too short)... ');
	undef($keyref);
	$key = '0123456789a';
	if (!eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	print('# Testing invalid key arg (undefined)... ');
	undef($keyref);
	undef($key);
	if (!eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	print('# Testing invalid key arg (reference)... ');
	undef($keyref);
	$key = \$text;
	if (!eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	print('# Checking whether el_key() returns a reference... ');
	undef($keyref);
	$key = '0123456789abcdef';
	if (eval($code) && ref($keyref)) {
		print("Done\n");
	} else {
		return 0;
	}

	print("# el_encrypt()\n");
	$code = 'el_encrypt($text, $keyref); 1;';

	print('# Testing normal encryption... ');
	undef($text);
	$text = 'Jamie works with two hammers';
	$plaintext = $text;
	if (eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}	
	$ciphertext = $text;

	print('# Testing invalid text arg (undefined)... ');
	undef($text);
	if (!eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	print('# Testing invalid text arg (reference)... ');
	undef($text);
	$text = \$tmp;
	if (!eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	print('# Testing invalid keyref arg (undefined)... ');
	$tmp = $keyref;
	undef($keyref);
	undef($text);
	$text = 'Jamie works with two hammers';
	if (!eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	print('# Testing invalid keyref arg (not a reference)... ');
	undef($text);
	$text = 'Jamie works with two hammers';
	$keyref = "bla";
	if (!eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	$keyref = $tmp;
	$text = $ciphertext;

	print("# el_decrypt()\n");
	$code = 'el_decrypt($text, $keyref); 1;';

	print('# Testing normal decryption... ');
	if (eval($code) && ($text eq $plaintext)) {
		print("Done\n");
	} else {
		return 0;
	}

	$text = $plaintext;

	print('# Checking sample usage... ');
	$code = 'no strict;'
		. '$t = \'secret\';'
		. '$k = \'0123456789abcdef\';'
		. '$K = el_key($k);'
		. 'el_encrypt($t, $K);'
		. 'el_decrypt($t, $K);';
	if (eval($code)) {
		print("Done\n");
	} else {
		print "$@\n";
		return 0;
	}

	return 1;
}

sub test_cipher_operation {
	my $key;
	my $keyref;
	my $ciphertext;
	my $expected;

	my @keys = (
		'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 
		'0123456789ABCDEF0123456789ABCDEF',
		'000000000000DEADBEEF000000000000',
		'F01FF23FF45FF67FF89FFABFFCDFFEFF'
	);
	my @plaintexts = (
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 
		'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
		'AABBCCDDEEFF00112233445566778899',
		'01010101010101010101010101010101',
		'00000000000000000000000000000000'
	);

	print('# Checking cipher operation... ');

	while ($key = shift(@keys)) {
		$ciphertext = shift(@plaintexts);

		$key = pack('H32', $key); # note 32 nibbles long
		$expected = pack('H32', $expected);
		$ciphertext = pack('H32', $ciphertext);
		$expected = $ciphertext;

		$keyref = el_key($key);
		el_encrypt($ciphertext, $keyref);
		el_decrypt($ciphertext, $keyref);

		if ($ciphertext ne $expected) {
			return 0;
		}
	}

	print("Done\n");
	return 1;
}

ok(test_api());
ok(test_cipher_operation());
