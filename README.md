# venmo-auto-transfer-neue

This is a wrapper for
[venmo-auto-cashout](https://github.com/evanpurkhiser/venmo-auto-cashout)
that does some automation. It's what I replaced my previous custom
[venmo-auto-transfer](https://github.com/radian-software/venmo-auto-transfer)
work with.

This is kind of a weird project because actually the majority of the
interesting logic is the part where I wrote a whole interop with
Matrix E2EE in order to access SMS OTPs programmatically. Haha whoops.
