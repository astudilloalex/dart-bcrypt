// ignore_for_file: avoid_print

import 'package:bcrypt/bcrypt.dart';

void main() {
  final String passwordHashed = BCrypt.hashpw(
    'password',
    BCrypt.gensalt(),
  );
  print(passwordHashed);
  final bool checkPassword = BCrypt.checkpw(
    'password',
    '\$2a\$10\$Yh5aw8xmKr3TS1Gk2UX98Oz7PT.Qhz5nnmGBb4dnayrTitMIDTKhK',
  );
  print(checkPassword);
}
