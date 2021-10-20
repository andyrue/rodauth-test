class RodauthController < ApplicationController
  include ActionController::RequestForgeryProtection
  protect_from_forgery with: :null_session

  # used by Rodauth for rendering views, CSRF protection, and running any
  # registered action callbacks and rescue_from handlers
end
