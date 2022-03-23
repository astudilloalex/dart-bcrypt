// Copyright (c) 2006 Damien Miller <djm@mindrot.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:bcrypt/src/bcrypt_arrays.dart';
import 'package:bcrypt/src/bcrypt_utils.dart';
import 'package:bcrypt/src/constants.dart' as constants;

/// BCrypt implements OpenBSD-style Blowfish password hashing using the scheme described in
/// "A Future-Adaptable Password Scheme" by Niels Provos and David Mazieres.
///
/// This is a jBCrypt modified class.
class BCrypt {
  const BCrypt._();

  /// Look up the 3 bits [base64Encode] by the specified character, range-checking againt
  /// conversion table.
  ///
  /// [char] the base64-encoded value.
  static int _char64(final String char) {
    final int charCode = char.codeUnitAt(0);
    final Int8List index64 = BCryptArrays.base64Decoding;
    if (charCode < 0 || charCode >= index64.length) {
      return -1;
    }
    return index64[charCode];
  }

  /// Check that a [text] password matches a previously [hashed] one.
  ///
  /// Returns true if the passwords match, false otherwise.
  static bool checkpw(final String text, final String hashed) {
    return hashed.compareTo(hashpw(text, hashed)) == 0;
  }

  /// Decode a [data] encoded using bcrypt's base64 scheme to a byte array with
  /// the [maxLength] number of bytes to decode.
  ///
  /// Note that this is not compatible with the standard MIME-base64 encoding.
  static Int8List decodeBase64(final String data, final int maxLength) {
    if (maxLength <= 0) {
      throw ArgumentError.value(maxLength, 'maxLength', 'Invalid max length');
    }
    final int dataLength = data.length;
    final StringBuffer stringBuffer = StringBuffer();
    int char1;
    int char2;
    int char3;
    int char4;
    int mainChar;
    int length = 0;
    int off = 0;
    while (off < dataLength - 1 && length < maxLength) {
      char1 = _char64(data[off++]);
      char2 = _char64(data[off++]);
      if (char1 == -1 || char2 == -1) break;
      mainChar = char1 << 2;
      mainChar |= (char2 & 0x30) >> 4;
      stringBuffer.write(String.fromCharCode(mainChar));
      if (++length >= maxLength || off >= dataLength) break;
      char3 = _char64(data[off++]);
      if (char3 == -1) break;
      mainChar = (char2 & 0x0f) << 4;
      mainChar |= (char3 & 0x3c) >> 2;
      stringBuffer.write(String.fromCharCode(mainChar));
      if (++length >= maxLength || off >= dataLength) break;
      char4 = _char64(data[off++]);
      mainChar = (char3 & 0x03) << 6;
      mainChar |= char4;
      stringBuffer.write(String.fromCharCode(mainChar));
      ++length;
    }
    final Int8List decodeData = Int8List(length);
    final String strBufferValue = stringBuffer.toString();
    for (off = 0; off < length; off++) {
      decodeData[off] = strBufferValue.codeUnitAt(off);
    }
    return decodeData;
  }

  /// Encode [data] using bcrypt's slightly-modified base64 encoding scheme with
  /// the [length] of bytes to encode.
  static String encodeBase64(final Int8List data, final int length) {
    if (length <= 0 || length > data.length) {
      throw ArgumentError.value(length, 'length', 'Invalid length');
    }
    final StringBuffer stringBuffer = StringBuffer();
    int off = 0;
    int char1;
    int char2;
    while (off < length) {
      char1 = data[off++] & 0xff;
      stringBuffer.write(BCryptArrays.base64Encode[(char1 >> 2) & 0x3f]);
      char1 = (char1 & 0x03) << 4;
      if (off >= length) {
        stringBuffer.write(BCryptArrays.base64Encode[char1 & 0x3f]);
        break;
      }
      char2 = data[off++] & 0xff;
      char1 |= (char2 >> 4) & 0x0f;
      stringBuffer.write(BCryptArrays.base64Encode[char1 & 0x3f]);
      char1 = (char2 & 0x0f) << 2;
      if (off >= length) {
        stringBuffer.write(BCryptArrays.base64Encode[char1 & 0x3f]);
        break;
      }
      char2 = data[off++] & 0xff;
      char1 |= (char2 >> 6) & 0x03;
      stringBuffer.write(BCryptArrays.base64Encode[char1 & 0x3f]);
      stringBuffer.write(BCryptArrays.base64Encode[char2 & 0x3f]);
    }
    return stringBuffer.toString();
  }

  /// Generate a salt for use with the [hashpw] method.
  ///
  /// Use [prefix] value to generate salt (default '$2a$'),
  /// The Log2 [logRounds] of the number of rounds of hashing to apply.
  static String gensalt({
    final String prefix = '\$2a',
    final int logRounds = constants.saltDefaultLogRounds,
    final Random? secureRandom,
  }) {
    if (logRounds < constants.minLogRounds ||
        logRounds > constants.maxLogRounds) {
      throw ArgumentError.value(
        logRounds,
        'logRounds',
        'Invalid rounds (min: ${constants.minLogRounds}, max: ${constants.maxLogRounds})',
      );
    }
    if (prefix.length != 3) {
      throw ArgumentError.value(
        prefix,
        'prefix',
        'Prefix invalid length (Length should be 3)',
      );
    }
    if (!prefix.startsWith('\$2') ||
        (prefix[2] != 'a' && prefix[2] != 'b' && prefix[2] != 'y')) {
      throw ArgumentError.value(
        prefix,
        'prefix',
        'Invalid prefix\n(available prefixes: \$2a, \$2b, \$2y)',
      );
    }
    final Random random = secureRandom ?? Random.secure();
    final Int8List round = Int8List(constants.saltLength);
    for (int i = 0; i < constants.saltLength; i++) {
      round[i] = random.nextInt(256) - 128;
    }
    final StringBuffer stringBuffer = StringBuffer();
    stringBuffer.write(prefix);
    stringBuffer.write('\$');
    if (logRounds < 10) stringBuffer.write('0');
    stringBuffer.write(logRounds);
    stringBuffer.write('\$');
    stringBuffer.write(encodeBase64(round, round.length));
    return stringBuffer.toString();
  }

  /// Hash a password using the OpenBSD bcrypt scheme.
  ///
  /// You need the [password] to hash and [salt] to hash you can generate using
  /// [gensalt] function.
  static String hashpw(final String password, final String salt) {
    final int saltLength = salt.length;
    if (saltLength < 28) {
      throw ArgumentError.value(
        salt,
        'salt',
        'Invalid salt length (The length should be greater than or equal to 28)',
      );
    }
    if (salt[0] != '\$' || salt[1] != '2') {
      throw ArgumentError.value(
        salt,
        'salt',
        'Invalid salt version',
      );
    }
    final int off;
    final String minor;
    if (salt[2] == '\$') {
      off = 3;
      minor = String.fromCharCode(0);
    } else {
      minor = salt[2];
      if ((minor != 'a' && minor != 'b' && minor != 'y') || salt[3] != '\$') {
        throw ArgumentError.value(
          salt,
          'salt',
          'Invalid salt revision',
        );
      }
      off = 4;
    }
    // Extract number of rounds
    if (salt[off + 2].codeUnitAt(0) > '\$'.codeUnitAt(0)) {
      throw ArgumentError.value(
        salt,
        'salt',
        'Missing salt rounds',
      );
    }
    if (off == 4 && saltLength < 29) {
      throw ArgumentError.value(
        salt,
        'salt',
        'Invalid salt',
      );
    }
    final int rounds = int.parse(salt.substring(off, off + 2));
    final StringBuffer stringBuffer = StringBuffer();
    final Int8List realSalt = decodeBase64(
      salt.substring(off + 3, off + 25),
      constants.saltLength,
    );
    final List<int> charCodes = const Utf8Encoder().convert(
      '$password${minor.codeUnitAt(0) >= 'a'.codeUnitAt(0) ? '\u0000' : ''}',
    );
    final Int8List passwordBytes = Int8List.fromList(charCodes);
    final Int8List hashed = BCryptUtils(
      pArray: BCryptArrays.pArray,
      sArray: BCryptArrays.sArray,
    ).cryptRaw(passwordBytes, realSalt, rounds);
    stringBuffer.write('\$2');
    if (minor.codeUnitAt(0) >= 'a'.codeUnitAt(0)) stringBuffer.write(minor);
    stringBuffer.write('\$');
    if (rounds < 10) stringBuffer.write('0');
    stringBuffer.write(rounds);
    stringBuffer.write('\$');
    stringBuffer.write(encodeBase64(realSalt, realSalt.length));
    stringBuffer.write(
      encodeBase64(hashed, BCryptArrays.bfCryptCiphertext.length * 4 - 1),
    );
    return stringBuffer.toString();
  }
}
