class ApplicationController < ActionController::API
  before_action :set_csrf_cookie
  include ActionController::Cookies
  # protect_from_forgery with: :null_session

  def cookie
    render json: { status: 'ok' }
  end

  def set_csrf_cookie
    puts "Setting cookie"
    cookies["CSRF-TOKEN"] = form_authenticity_token
  end
end
