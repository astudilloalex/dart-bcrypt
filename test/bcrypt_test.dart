import 'package:bcrypt/bcrypt.dart';
import 'package:test/test.dart';

void main() {
  group('A group of tests', () {
    setUp(() {
      // Additional setup goes here.
    });

    test('Check BCrypt prefix', () {
      expect(BCrypt.gensalt().startsWith('\$2a\$'), isTrue);
      expect(BCrypt.gensalt(prefix: '\$2b\$').startsWith('\$2b\$'), isTrue);
      expect(BCrypt.gensalt(prefix: '\$2x\$').startsWith('\$2x\$'), isTrue);
      expect(BCrypt.gensalt(prefix: '\$2y\$').startsWith('\$2y\$'), isTrue);
    });
  });
}
