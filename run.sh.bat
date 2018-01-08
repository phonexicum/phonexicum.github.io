:: https://gist.github.com/fnichol/867550#the-manual-way-boring
set SSL_CERT_FILE=..\cacert.pem

bundle exec jekyll serve -t --incremental
:: bundle exec jekyll serve -t --incremental --host 0.0.0.0
