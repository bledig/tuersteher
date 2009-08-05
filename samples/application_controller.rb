class ApplicationController  < ActionController::Base



  include Tuersteher::ControllerExtensions
  before_filter :check_access # methode is from Tuersteher::ControllerExtensions

  # This method need Tuersteher for his rules-check
  # It should return a User-Object, which have a method "has_role?"
  #
  # This is here a dummy Stub-Implementation
  def current_user
    user = Object.new
    def user.has_role?(*roles)
      true
    end
    user
  end

  # This Method is called from Tuersteher if access are denied (no grant rules fired)
  # stub Authentication-Methode
  def access_denied
    redirect_to "/"
  end

end
