import 'dart:typed_data';

import 'package:bcrypt/src/bcrypt_arrays.dart';
import 'package:bcrypt/src/constants.dart';

/// BCrypt utils to hash passwords
class BCryptUtils {
  /// Define a [BCryptUtils] class.
  const BCryptUtils({
    required this.pArray,
    required this.sArray,
  });

  /// Initial contents of key schedule.
  ///
  /// Array of 18 per-round subkeys.
  final Int32List pArray;

  /// Contain information subkeys to cipher.
  ///
  /// Array of four SBoxes; each SBox is 256 UInt32
  final Int32List sArray;

  // Int8List cryptRaw(final Int8List password, ){}

  /// Blowfish encipher a single 64-bit block encoded as two 32-bit halves.
  ///
  /// [data] an array containing the two 32-bit half blocks.
  /// [off] the position in the array of the blocks.
  void _encipher(final Int32List data, final int off) {
    int n;
    int l = data[off];
    int r = data[off + 1];
    l ^= pArray[0];
    for (int i = 0; i <= blowfishRounds - 2;) {
      // Feistel substitution on left word
      n = sArray[(l >> 24) & 0xff];
      n += sArray[0x100 | ((l >> 16) & 0xff)];
      n ^= sArray[0x200 | ((l >> 8) & 0xff)];
      n += sArray[0x300 | (l & 0xff)];
      r ^= n ^ pArray[++i];

      // Feistel substitution on right word
      n = sArray[(r >> 24) & 0xff];
      n += sArray[0x100 | ((r >> 16) & 0xff)];
      n ^= sArray[0x200 | ((r >> 8) & 0xff)];
      n += sArray[0x300 | (r & 0xff)];
      l ^= n ^ pArray[++i];
    }
    data[off] = r ^ pArray[blowfishRounds + 1];
    data[off + 1] = l;
  }

  /// Perform the "enhanced key schedule" step described by Provos and Mazieres in "A
  /// Future-Adaptable Password Scheme" https://www.openbsd.org/papers/bcrypt-paper.ps
  ///
  /// [data] salt information.
  /// [key] password information.
  void _enhancedKeySchedule(final Int8List data, final Int8List key) {
    final Int32List keyOffPointer = Int32List(1);
    final Int32List lr = Int32List(2);
    final Int32List dataOffPointer = Int32List(1);
    for (int i = 0; i < pArray.length; i++) {
      pArray[i] = pArray[i] ^ _streamToWord(key, keyOffPointer);
    }
    for (int i = 0; i < pArray.length; i += 2) {
      lr[0] ^= _streamToWord(data, dataOffPointer);
      lr[1] ^= _streamToWord(data, dataOffPointer);
      _encipher(lr, 0);
      pArray[i] = lr[0];
      pArray[i + 1] = lr[1];
    }
    for (int i = 0; i < sArray.length; i += 2) {
      lr[0] ^= _streamToWord(data, dataOffPointer);
      lr[1] ^= _streamToWord(data, dataOffPointer);
      _encipher(lr, 0);
      sArray[i] = lr[0];
      sArray[i + 1] = lr[1];
    }
  }

  /// Key the Blowfish cipher.
  ///
  /// [key] an array containing the key.
  void _key(final Int8List key) {
    final Int32List keyOffPointer = Int32List(1);
    final Int32List data = Int32List(2);
    for (int i = 0; i < pArray.length; i++) {
      pArray[i] = pArray[i] ^ _streamToWord(key, keyOffPointer);
    }
    for (int i = 0; i < pArray.length; i += 2) {
      _encipher(data, 0);
      pArray[i] = data[0];
      pArray[i + 1] = data[1];
    }
    for (int i = 0; i < sArray.length; i += 2) {
      _encipher(data, 0);
      sArray[i] = data[0];
      sArray[i + 1] = data[1];
    }
  }

  /// Cycically extract a word of key material.
  ///
  /// You need [data] the string to extract the data from [offsetPointer]
  /// (as a one-entry array) to the current offset into data.
  ///
  /// Returns a correct and buggy next word of material from [data] as [Int32List]
  /// with length 2.
  int _streamToWord(
    final Int8List data,
    final Int32List offsetPointer,
  ) {
    int word = 0;
    int off = offsetPointer[0];
    for (int i = 0; i < 4; i++) {
      word = (word << 8) | (data[off] & 0xff);
      off = (off + 1) % data.length;
    }
    offsetPointer[0] = off;
    return word;
  }

  Int8List cryptRaw(
    final Int8List password,
    final Int8List salt,
    int logRounds,
  ) {
    if (logRounds < minLogRounds || logRounds > maxLogRounds) {
      throw ArgumentError.value(
        logRounds,
        'logRounds',
        'Invalid rounds (min: $minLogRounds, max: $maxLogRounds)',
      );
    }
    if (salt.length != saltLength) {
      throw ArgumentError.value(
        salt,
        'salt',
        'Bad salt length',
      );
    }
    _enhancedKeySchedule(salt, password);
    final int rounds = 1 << logRounds;
    for (int i = 0; i < rounds; i++) {
      _key(password);
      _key(salt);
    }
    final Int32List data = BCryptArrays.bfCryptCiphertext.sublist(
      0,
      BCryptArrays.bfCryptCiphertext.length,
    );
    for (int i = 0; i < 64; i++) {
      for (int j = 0; j < (data.length >> 1); j++) {
        _encipher(data, j << 1);
      }
    }
    final Int8List cryptData = Int8List(data.length * 4);
    int j = 0;
    for (int i = 0; i < data.length; i++) {
      cryptData[j++] = (data[i] >> 24) & 0xff;
      cryptData[j++] = (data[i] >> 16) & 0xff;
      cryptData[j++] = (data[i] >> 8) & 0xff;
      cryptData[j++] = data[i] & 0xff;
    }
    return cryptData;
  }
}
