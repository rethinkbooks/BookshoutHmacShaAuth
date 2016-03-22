require 'open-uri'
module BookshoutHmacShaAuth::HmacShable
  extend ::ActiveSupport::Concern

  def handle_auth

    #settings params
    #user_id     = params[:user_id]

    # auth params
    timestamp   = request.headers["X-bs-timestamp"]  || ""
    param_list  = request.headers["X-bs-param-list"] || ""
    signature   = request.headers["X-bs-signature"]  || ""

    Rails.logger.debug "Timestamp: #{timestamp}"
    Rails.logger.debug "ParamList: #{param_list}"
    Rails.logger.debug "Content-Type: #{request.headers["Content-Type"]}"
    param_str   = ""
    param_list.split(",").each do |param|
      param_str << (params[param.to_sym] || "") 
    end 
    Rails.logger.debug "Param str: #{param_str}"
    computed_signature = HmacShaGenerator.build_signature timestamp,param_str
    computed_signature = URI::encode(computed_signature)
    Rails.logger.debug "#{signature}|"
    Rails.logger.debug "#{computed_signature}|"
    Rails.logger.debug params

    #if user_id && timestamp && param_list && signature &&  computed_signature == signature
    successfull_attempt = signature == computed_signature
    Rails.logger.debug "Access: #{successfull_attempt}"
    if !successfull_attempt
      render(json: {:message => "Invalid auth credentials."}, :status => 401 )
    end 
  end 


end

