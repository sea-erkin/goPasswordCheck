# Build and run instructions

```
git clone https://github.com/sea-erkin/goPasswordCheck.git
cd goPasswordCheck
go build
./goPasswordCheck
```

# What does this thing do?

Uses pwned passwords API to check if your password has been pwned - without sending your password. 

# How does it do this?

By sending out the first five characters of a SHA1 hash of your password. The API then returns a list of pwned password hashes that matched your hash prefix. This program then checks that list of similar hashes for a direct match.

# Why would you want to use this?

You should already be using a password generator to generate your passwords, even so your password can still be breached. This tool allows you to check if your password has been breached without actual sending your password to the service.
