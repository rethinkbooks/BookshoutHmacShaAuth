module BookshoutHmacShaAuth
  class HmacShaGenerator
    def self.build_signature(timestamp, params, application = 'www')
      digest = OpenSSL::Digest.new('sha1')

      key = ENV["BOOKSHOUT_#{application.upcase}_HMAC_KEY"]

      data = timestamp + params

      hmac = OpenSSL::HMAC.digest(digest, key, data)

      Base64.encode64(hmac).strip
    end
  end
end
