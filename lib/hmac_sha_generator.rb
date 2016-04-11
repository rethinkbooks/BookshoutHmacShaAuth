class BookshoutHmacShaAuth::HmacShaGenerator
  def self.build_signature(timestamp_str, params_string,application="www")
    #key = "bookshout_key"
    begin
      #env_key =YAML.load_file("#{Rails.root}/config/hmac_sha_envs.yml")["hmac_sha_env_key"]
      env_key = "BOOKSHOUT_#{application.upcase}_HMAC_KEY"
    rescue
      env_key = "BOOKSHOUT_HMAC_SHA_LOCAL_KEY"
    end
    key = ENV[env_key]
    data = timestamp_str + params_string
    digest = OpenSSL::Digest.new('sha1')
    hmac = OpenSSL::HMAC.digest(digest, key, data)
    Base64.encode64(hmac)
  end
end
