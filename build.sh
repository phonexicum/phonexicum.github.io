#! /bin/bash
bundle exec jekyll clean &&
bundle exec jekyll build -t &&
cp -r -v static.phonexicum.github.io/. ./phonexicum.github.io/ &&
mv ./phonexicum.github.io/_.git ./phonexicum.github.io/.git
