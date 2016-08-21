#! /bin/bash
bundle exec jekyll clean && bundle exec jekyll build -t && cp -r -v static.phonexicum.github.io/. ./phonexicum.github.io/
