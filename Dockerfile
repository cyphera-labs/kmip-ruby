FROM ruby:3.3-slim
WORKDIR /app
COPY Gemfile cyphera-kmip.gemspec ./
COPY lib/ lib/
COPY test/ test/
CMD ["ruby", "-Ilib", "-Itest", "-e", "Dir['test/test_*.rb'].each { |f| require_relative f }"]
