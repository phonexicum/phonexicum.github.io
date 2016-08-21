# phonexicum.github.io

### Repository structure
I use jekylls with pandoc, but it requires greater ruby version, then served by github, and it requires preinstalled pandoc binaries, github has not.

I decided to store my jekylls source in a different repository [src.phonexicum.github.io](https://github.com/phonexicum/src.phonexicum.github.io) and compile jekylls there into git submodule phonexicum.github.io. Everything github has to do after is to host my static html.

Everything here is generated automatically from [src.phonexicum.github.io](https://github.com/phonexicum/src.phonexicum.github.io), nothing must be done here manually.