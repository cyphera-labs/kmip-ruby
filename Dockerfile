FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795
RUN apk add --no-cache ruby-3.1 && rm -rf /var/cache/apk/*
USER nonroot
WORKDIR /home/nonroot
COPY --chown=nonroot:nonroot Gemfile cyphera-kmip.gemspec ./
COPY --chown=nonroot:nonroot lib/ lib/
COPY --chown=nonroot:nonroot test/ test/
CMD ["ruby", "-Ilib", "-Itest", "-e", "Dir['test/test_*.rb'].each { |f| require_relative f }"]
