# User Registry Storage

- `pending/` contains pending registration files awaiting OTP confirmation.
- `users/` contains confirmed user profiles.
- Each record is JSON encoded, one file per user (or per pending request).
