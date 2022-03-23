<!-- 
This README describes the package. If you publish this package to pub.dev,
this README's contents appear on the landing page for your package.

For information about how to write a good package README, see the guide for
[writing package pages](https://dart.dev/guides/libraries/writing-package-pages). 

For general information about developing packages, see the Dart guide for
[creating packages](https://dart.dev/guides/libraries/create-library-packages)
and the Flutter guide for
[developing packages and plugins](https://flutter.dev/developing-packages). 
-->

Hash your passwords with BCrypt algorithm, this is a jBCrypt modified code to work with Dart.

## Features

Use BCrypt password-hashing function to keep your system secure.

## Getting started

[![pub package](https://pub.dev/static/img/pub-dev-logo-2x.png?hash=umitaheu8hl7gd3mineshk2koqfngugi)](https://pub.dev/packages/bcrypt)

Only add [bcrypt](https://pub.dev/packages/bcrypt) package to your pubspec.yaml.

```yaml
dependencies:
  bcrypt: ^1.1.1
```

## Usage

Use Bcrypt to hash and check password.

```dart
final String hashed = BCrypt.hashpw('password', BCrypt.gensalt());
// $2a$10$r6huirn1laq6UXBVu6ga9.sHca6sr6tQl3Tiq9LB6/6LMpR37XEGu

final bool checkPassword = BCrypt.checkpw('password', hashed);
// true
```

## Additional information

This package is modified jBCrypt code used in Java and Spring Boot to improve security when saving passwords.
