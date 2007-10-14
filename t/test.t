use strict;
use Test;

BEGIN {
	plan tests => 2;
}

use Crypt::Elijah;

print("# Using Crypt::Elijah version " . $Crypt::Elijah::VERSION . "\n");

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

	print("# Testing normal key input (max. length)... ");
	undef($keyref);
	$key = '0123456789abcdef';
	if (eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	print("# Testing normal key input (min. length)... ");
	undef($keyref);
	$key = '0123456789ab';
	if (eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	print("# Testing invalid key input (too short)... ");
	undef($keyref);
	$key = '0123456789a';
	if (!eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	print("# Testing invalid key arg (undefined)... ");
	undef($keyref);
	undef($key);
	if (!eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	print("# Testing invalid key arg (reference)... ");
	undef($keyref);
	$key = \$text;
	if (!eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	print("# Checking whether set_key() returns a reference... ");
	undef($keyref);
	$key = '0123456789abcdef';
	if (eval($code) && ref($keyref)) {
		print("Done\n");
	} else {
		return 0;
	}

	print("# el_encrypt()\n");
	$code = 'el_encrypt($text, $keyref); 1;';

	print("# Testing normal encryption... ");
	undef($text);
	$text = 'Jamie works with two hammers';
	$plaintext = $text;
	if (eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}	
	$ciphertext = $text;

	print("# Testing invalid text arg (undefined)... ");
	undef($text);
	if (!eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	print("# Testing invalid text arg (reference)... ");
	undef($text);
	$text = \$tmp;
	if (!eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	print("# Testing invalid keyref arg (undefined)... ");
	$tmp = $keyref;
	undef($keyref);
	undef($text);
	$text = 'Jamie works with two hammers';
	if (!eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}

	print("# Testing invalid keyref arg (not a reference)... ");
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

	print("# Testing normal decryption... ");
	if (eval($code) && ($text eq $plaintext)) {
		print("Done\n");
	} else {
		return 0;
	}	


	$text = $plaintext;

	print("# _el_encrypt()\n");
	$code = '_el_encrypt($text, $keyref); 1;';

	print("# Testing base encryption... ");
	if (eval($code)) {
		print("Done\n");
	} else {
		return 0;
	}	
	$ciphertext = $text;

	print("# _el_decrypt()\n");
	$code = '_el_decrypt($text, $keyref); 1;';

	print("# Testing base decryption... ");
	if (eval($code) && ($text eq $plaintext)) {
		print("Done\n");
	} else {
		return 0;
	}
	
	return 1;
}

sub test_cipher_vectors {
	my @key;
	my @txt;
	my @out;
	my $Key;
	my $Txt;
	my $keyref;
	my $Expected;

	print("# Checking test vectors for Elijah cipher... ");

	@key = (
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	);
	@txt = (
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
	);
	@out = (
		0x1A, 0xB7, 0x6B, 0x86, 0x3E, 0x93, 0xAB, 0x16,
		0x6A, 0x17, 0x83, 0x5E, 0x7E, 0x63, 0x33, 0x0E
	);
	$Txt = pack('C16', @txt);
	$Key = pack('C16', @key);
	$Expected = pack('C16', @out);
	$keyref = el_key($Key);
	_el_encrypt($Txt, $keyref);
	if ($Txt ne $Expected) {
		return 0;
	}

	@key = (
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
	);
	@txt = (
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	);
	@out = (
		0xDC, 0x12, 0x18, 0x24, 0x42, 0xC4, 0x5E, 0xC6, 
		0x7C, 0x3A, 0xE0, 0x84, 0x92, 0x2C, 0x16, 0xB6
	);
	$Txt = pack('C16', @txt);
	$Key = pack('C16', @key);
	$Expected = pack('C16', @out);
	$keyref = el_key($Key);
	_el_encrypt($Txt, $keyref);
	if ($Txt ne $Expected) {
		return 0;
	}

	@key = (
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	);
	@txt = (
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
	);
	@out = (
		0x30, 0x8E, 0x92, 0x8C, 0x7E, 0x5C, 0xEC, 0x16, 
		0x48, 0x46, 0x42, 0x3C, 0x86, 0x74, 0x9C, 0x36
	);
	$Txt = pack('C16', @txt);
	$Key = pack('C16', @key);
	$Expected = pack('C16', @out);
	$keyref = el_key($Key);
	_el_encrypt($Txt, $keyref);
	if ($Txt ne $Expected) {
		return 0;
	}

	@key = (
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD,
		0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	);
	@txt = (
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
	);
	@out = (
		0x23, 0xC4, 0x93, 0x48, 0x17, 0xD2, 0xE1, 0x76, 
		0x81, 0xD4, 0x43, 0xF0, 0x3F, 0xE2, 0x71, 0xAD
	);
	$Txt = pack('C16', @txt);
	$Key = pack('C16', @key);
	$Expected = pack('C16', @out);
	$keyref = el_key($Key);
	_el_encrypt($Txt, $keyref);
	if ($Txt ne $Expected) {
		return 0;
	}

	@key = (
		0xF0, 0x1F, 0xF2, 0x3F, 0xF4, 0x5F, 0xF6, 0x7F,
		0xF8, 0x9F, 0xFA, 0xBF, 0xFC, 0xDF, 0xFE, 0xFF
	);
	@txt = (
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	);
	@out = (
		0x03, 0xEF, 0x89, 0xEA, 0x3F, 0xC7, 0x2D, 0x56, 
		0xEB, 0xE7, 0xA1, 0xFA, 0x57, 0x9F, 0x65, 0x56
	);
	$Txt = pack('C16', @txt);
	$Key = pack('C16', @key);
	$Expected = pack('C16', @out);
	$keyref = el_key($Key);
	_el_encrypt($Txt, $keyref);
	if ($Txt ne $Expected) {
		return 0;
	}

	print("Done\n");
	return 1;
}

ok(test_api());
ok(test_cipher_vectors());
