#! /bin/bash
bundle exec jekyll clean &&
bundle exec jekyll build -t &&
cp -r -v static.phonexicum.github.io/. ./phonexicum.github.io/ &&
mv ./phonexicum.github.io/git.bak ./phonexicum.github.io/.git &&
mv ./phonexicum.github.io/gitignore.bak ./phonexicum.github.io/.gitignore &&
mv ./phonexicum.github.io/gitmodules.bak ./phonexicum.github.io/.gitmodules &&
cd phonexicum.github.io &&
git commit -a --amend -m "Added some content." &&
cd ../
