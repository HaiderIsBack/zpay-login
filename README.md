# ZAuth

ZAuth provides session-based authentication methods for PHP applications.

## Requirements

- PHP 8.0 or later
- Composer autoloader
- PDO with the PDO MySQL driver
- `mbstring`
- GD with FreeType support and `PASSWORD_ARGON2ID` support to generate CAPTCHA images
- A MySQL-compatible database with the tables and columns listed below
- An active PHP session before calling session-dependent methods

Install the Composer dependencies and load the autoloader before using ZAuth:

```sh
composer require zcoders/zauth
```

```php
require_once __DIR__ . '/vendor/autoload.php';
session_start();
```

## Database requirements

Pass a configured PDO connection to `Authenticator`. The authentication
methods expect:

- `users`: `ID`, `EMAIL`, `STATUS`, `PWDHASH`, `IPSEC`, `MFA`, `BID`, `NAME`,
  `CAT`, `PICPATH1`, and `LVERSION`. Store password hashes in `PWDHASH` using
  PHP's `password_hash()`.
- `users_meta`: `USER_ID`, `KEY`, and `VALUE`. Values are returned under their
  corresponding `KEY` when looking up a user.
- `log_login`: `ID`, `TYPE`, `USERID`, `IPADDRESS`, `URL`, `INTIME`, `OUTTIME`,
  and `STATUS`.
- `iprange`: `MEMID`, `STARTIP`, and `ENDIP`.
- `ipblock`: `STARTIP`, `ENDIP`, and `ETIME`.

IP range and block columns are compared against packed addresses from
`inet_pton()`. Login logging reads `$_SERVER['HTTP_HOST']`.

## Initialize

Create the PDO connection using your database credentials and pass it to
`Authenticator`:

```php
use ZAuth\Core\Authenticator;

$auth = new Authenticator($pdo);
```

`Authenticator::__construct(PDO $conn)` requires a configured PDO connection.
It returns an `Authenticator` instance.

## Methods

### `login(array $payload): string`

```php
$result = json_decode($auth->login([
    'email'      => $email,
    'password'   => $password,
    'csrf_token' => $csrfToken,
    'captcha'    => $captcha,
]), true);
```

Requires an active session, a valid CSRF token, and a CAPTCHA generated for
that session. The payload must contain:

- `email`: valid email address, 3-254 characters
- `password`: string, 3-100 characters
- `csrf_token`: string, 1-128 characters
- `captcha`: string, exactly 6 characters

Checks the user credentials, IP restrictions, and login risk rules. Returns a
JSON-encoded string with the `success`, `data`, and `code` fields. On
authentication, `data.status_code` is `AUTHENTICATED`. For an account with
MFA enabled, it returns `MFA_REQUIRED`. Invalid input, CSRF, CAPTCHA,
credentials, or IP checks return an error response with a message and
`error_code`.

### `isLoggedIn(): bool`

```php
if ($auth->isLoggedIn()) {
    // The session belongs to an active user and its login version is current.
}
```

Requires an active session and the database connection. Returns `true` when
the session has a valid user ID and login version matching an active database
user; otherwise returns `false`.

### `logout(array $payload): string`

```php
$result = json_decode($auth->logout([
    'csrf_token' => $csrfToken,
]), true);
```

Requires an active, authenticated session, the database connection, and a
valid CSRF token. The payload must contain a `csrf_token` string between 1 and
128 characters. On success, updates the login audit record when possible,
clears and destroys the session, and returns a JSON-encoded string with
`success: true` and `data.status_code` equal to `LOGGED_OUT`. Validation,
CSRF, or authentication failures return a JSON error response.

## CSRF methods

All CSRF methods require an active PHP session.

### `CSRF::token(): string`

```php
use ZAuth\Core\CSRF;

$csrfToken = CSRF::token();
```

Creates a token if needed and returns it as a string. Submit this token with
the request and pass the submitted value to `login()` or `logout()`.

### `CSRF::validate(?string $token): bool`

Compares the supplied token with the token stored in the session. Returns
`true` for a match and `false` otherwise.

### `CSRF::regenerate(): void`

Replaces the session's CSRF token. Returns no value.

## CAPTCHA methods

Both CAPTCHA methods require an active PHP session.

### `CAPTCHA::generate(): void`

```php
use ZAuth\Core\CAPTCHA;

CAPTCHA::generate();
```

Creates a six-digit challenge, stores its hash in the session, and writes a
PNG image to the response. Requires GD with FreeType support and the bundled
font at `public/assets/font/Codystar-Regular.ttf`. Returns no value. Errors
such as missing GD support or font are reported as `RuntimeException`.

### `CAPTCHA::verify(mixed $pin): bool`

Checks the submitted PIN against the challenge stored in the session and
consumes that challenge. Returns `true` when it matches and `false` otherwise.

## MFA

`ZAuth\MFA\MFA::verify(array $payload): string` currently returns a successful
JSON response with empty data. MFA challenge verification is not implemented;
do not treat this method as validating an MFA code.
