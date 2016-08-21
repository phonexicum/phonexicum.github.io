# phonexicum.github.io

### Repository structure
I use jekylls with pandoc, but it requires greater ruby version, then served by github, and it requires preinstalled pandoc binaries, github has not.
I decided to store my jekylls source in a different dir "src.phonexicum.github.io" and compile it into static html5 in "site.phonexicum.github.io" locally with my own configurations etc. in "src. ...". Finally, github will host my html as github-pages based on configuration files, lying in root directory.