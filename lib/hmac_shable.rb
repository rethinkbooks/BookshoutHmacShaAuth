# TODO: Refactor this module so that it makes no assumptions about what is using it. It should probably be renamed something like HmacShaVerifier. That way it can accept
# the headers as arguments and then verify the signature. Extraction of the headers/params should happen in a separate class that is autoloaded when the gem loads using
# ActiveSupport.on_load(:action_controller) and provides a class method like "verifies_hmac_sha" which can than be configured like other before_action filters. Additonally
# this would allow for the gem to be used in non-Rails apps.
module BookshoutHmacShaAuth::HmacShable
  extend ::ActiveSupport::Concern

  def handle_auth
    timestamp  = request.headers["X-Bs-Timestamp"]
    param_list = request.headers["X-Bs-Param-List"]
    signature  = request.headers["X-Bs-Signature"]

    unless timestamp.present? && param_list.present? && signature.present?
      # TODO: Just return false instead of calling render. This makes way too many assumptions about how failures should be handled.
      render(json: { message: 'Auth headers not set.' }, status: 401)

      return false
    end

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
    Rails.logger.debug "Access: #{successfull_attempt}" if defined?(Rails)

    if datetime < DateTime.now-25.minute
      Rails.logger.debug "INVALID TIMESTAMP" if defined?(Rails)

      # TODO: Again, just return false instead of calling render for the same reason as above.
      render(json: {:message => "Invalid timestamp. Too far in the past. Request expired."}, :status => 401 )

      return false
    end

    unless successfull_attempt
      # TODO: Again, return false instead of calling render for the same reason as above.
      render(json: {:message => "Invalid auth credentials."}, :status => 401 )

      return false
    end

    true
  end

  # TODO: Remove this. It's apparently relying on the old behavior of throwing an exception when the request headers aren't set. Also, see the note at the top.
  def handle_grape_auth
    begin
      handle_auth
      true
    rescue Exception => e
      Rails.logger.error e.to_s if defined?(Rails)
      false
    end
  end
end
