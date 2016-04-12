require 'open-uri'
require 'active_support/concern'
module BookshoutHmacShaAuth::HmacShable
  extend ::ActiveSupport::Concern

  def handle_auth
    timestamp   = request.headers["X-Bs-Timestamp"]
    param_list  = request.headers["X-Bs-Param-List"]
    signature   = request.headers["X-Bs-Signature"]

    datetime = DateTime.parse(timestamp)
    param_str   = ""
    param_list.split(",").each do |param|
      param_str << (params[param.to_sym].to_s || "")
    end
    app_name = YAML.load_file("#{Rails.root}/config/hmac_sha_envs.yml")["app_name"]
    computed_signature = BookshoutHmacShaAuth::HmacShaGenerator.build_signature timestamp,param_str,app_name
    computed_signature = URI::encode(computed_signature.strip)

    #if user_id && timestamp && param_list && signature &&  computed_signature == signature
    successfull_attempt = signature == computed_signature
    Rails.logger.debug "Access: #{successfull_attempt}"

    if datetime < DateTime.now-1.minute
      Rails.logger.debug "INVALID TIMESTAMP"
      render(json: {:message => "Invalid timestamp. Too far in the past. Request expired."}, :status => 401 )
    end

    if !successfull_attempt
      render(json: {:message => "Invalid auth credentials."}, :status => 401 )
    end

    true
  end

  def handle_grape_auth
    begin
      handle_auth
      true
    rescue Exception => e
      Rails.logger.error e.to_s
      false
    end
  end

end
