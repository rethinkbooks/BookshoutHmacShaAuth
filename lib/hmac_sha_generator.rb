class BookshoutHmacShaAuth::HmacShaGenerator
  def self.build_signature timestamp_str,params_string
    #key = "bookshout_key"
    env_key =YAML.load_file("#{Rails.root}/config/hmac_sha_envs.yml")["hmac_sha_env_key"]
    key = ENV[env_key]
    data = timestamp_str + params_string 
    digest = OpenSSL::Digest.new('sha1')
    hmac = OpenSSL::HMAC.digest(digest, key, data)
    Base64.encode64(hmac)
  end 
end
