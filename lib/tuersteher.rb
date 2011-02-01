# Module, welches AccesRules fuer Controller/Actions und
# Model-Object umsetzt.
#
# Die Regeln werden aus der Datei "config/acces_rules.rb" geladen
#
# Author: Bernd Ledig
#

require 'singleton'
require 'logger'

module Tuersteher

  # Logger to log messages with timestamp and severity
  class TLogger < Logger
    @@logger = nil

    def format_message(severity, timestamp, progname, msg)
      "#{timestamp.to_formatted_s(:db)} #{severity} #{msg}\n"
    end

    def self.logger
      return @@logger if @@logger
      @@logger = self.new(File.join(Rails.root, 'log', 'tuersteher.log'), 3)
      @@logger.level = INFO if Rails.env != 'development'
      @@logger
    end

    def self.logger= logger
      @@logger = logger
    end
  end


  class AccessRulesStorage
    include Singleton

    attr_accessor :rules_config_file # to set own access_rules-path

    DEFAULT_RULES_CONFIG_FILE = 'access_rules.rb' # in config-dir

    # private initializer why this class is a singleton
    def initialize
      @path_rules = []
      @model_rules = []
    end

    # get all path_rules as array of PathAccessRule-Instances
    def path_rules
      read_rules unless @was_read
      @path_rules
    end

    # get all model_rules as array of ModelAccessRule-Instances
    def model_rules
      read_rules unless @was_read
      @model_rules
    end


    # evaluated rules_definitions and create path-/model-rules
    def eval_rules rules_definitions
      @path_rules = []
      @model_rules = []
      eval rules_definitions, binding, (@rules_config_file||'no file')
      @was_read = true
      Tuersteher::TLogger.logger.info "Tuersteher::AccessRulesStorage: #{@path_rules.size} path-rules and #{@model_rules.size} model-rules"
    end

    # Load AccesRules from file
    #  config/access_rules.rb
    def read_rules
      @rules_config_file ||= File.join(Rails.root, 'config', DEFAULT_RULES_CONFIG_FILE)
      rules_file = File.new @rules_config_file
      @was_read = false
      content = nil
      if @last_mtime.nil? || rules_file.mtime > @last_mtime
        @last_mtime = rules_file.mtime
        content = rules_file.read
      end
      rules_file.close
      if content
        eval_rules content
      end
    rescue => ex
      Tuersteher::TLogger.logger.error "Tuersteher::AccessRulesStorage - Error in rules: #{ex.message}\n\t"+ex.backtrace.join("\n\t")
    end

    # definiert HTTP-Pfad-basierende Zugriffsregel
    #
    # path:            :all fuer beliebig, sonst String mit der http-path beginnen muss,
    #                  wird als RegEX-Ausdruck ausgewertet
    def path url_path
      if block_given?
        @current_rule_class = PathAccessRule
        @current_rule_init = url_path
        @current_rule_storage = @path_rules
        yield
        @current_rule_class = @current_rule_init = nil
      else
        rule = PathAccessRule.new(url_path)
        @path_rules << rule
        rule
      end
    end

    
    # definiert Model-basierende Zugriffsregel
    #
    # model_class:  Model-Klassenname oder :all fuer alle
    def model model_class
      if block_given?
        @current_rule_class = ModelAccessRule
        @current_rule_init = model_class
        @current_rule_storage = @model_rules
        yield
        @current_rule_class = @current_rule_init = @current_rule_storage = nil
      else
        rule = ModelAccessRule.new(model_class)
        @model_rules << rule
        rule
      end
    end

    # create new rule as grant-rule
    # and add this to the model_rules array
    def grant
      rule = @current_rule_class.new(@current_rule_init)
      @current_rule_storage << rule
      rule.grant
    end

    # create new rule as deny-rule
    # and add this to the model_rules array
    def deny
      rule = grant
      rule.deny
    end

    # Erweitern des Path um einen Prefix
    # Ist notwenig wenn z.B. die Rails-Anwendung nicht als root-Anwendung läuft
    # also root_path != '/' ist.'
    def extend_path_rules_with_prefix prefix
      Tuersteher::TLogger.logger.info "extend_path_rules_with_prefix: #{prefix}"
      @path_prefix = prefix
      path_rules.each do |rule|
        path_spec = rule.path_spezification
        if path_spec
          path_spec.path = "#{prefix}#{path_spec.path}"
        end
      end
    end


  end # of AccessRulesStorage


  class AccessRules
    class << self

      # Pruefen Zugriff fuer eine Web-action
      # user        User, für den der Zugriff geprüft werden soll (muss Methode has_role? haben)
      # path        Pfad der Webresource (String)
      # method      http-Methode (:get, :put, :delete, :post), default ist :get
      #
      def path_access?(user, path, method = :get)
        rule = AccessRulesStorage.instance.path_rules.detect do |r|
          r.fired?(path, method, user)
        end
        if Tuersteher::TLogger.logger.debug?
          if rule.nil?
            s = 'denied'
          elsif rule.deny?
            s = "denied with #{rule}"
          else
            s = "granted with #{rule}"
          end
          usr_id = user && user.respond_to?(:id) ? user.id : user.object_id
          Tuersteher::TLogger.logger.debug("Tuersteher: path_access?(user.id=#{usr_id}, path=#{path}, method=#{method})  =>  #{s}")
        end
        !(rule.nil? || rule.deny?)
      end


      # Pruefen Zugriff auf ein Model-Object
      #
      # user        User, für den der Zugriff geprüft werden soll (muss Methode has_role? haben)
      # model       das Model-Object
      # permission  das geforderte Zugriffsrecht (:create, :update, :destroy, :get)
      #
      # liefert true/false
      def model_access? user, model, permission
        raise "Wrong call! Use: model_access(model-instance-or-class, permission)" unless permission.is_a? Symbol
        return false unless model

        rule = AccessRulesStorage.instance.model_rules.detect do |rule|
          rule.fired? model, permission, user
        end
        access = rule && !rule.deny?
        if Tuersteher::TLogger.logger.debug?
          usr_id = user && user.respond_to?(:id) ? user.id : user.object_id
          if model.instance_of?(Class)
            Tuersteher::TLogger.logger.debug(
              "Tuersteher: model_access?(user.id=#{usr_id}, model=#{model}, permission=#{permission}) =>  #{access || 'denied'} #{rule}")
          else
            Tuersteher::TLogger.logger.debug(
              "Tuersteher: model_access?(user.id=#{usr_id}, model=#{model.class}(#{model.respond_to?(:id) ? model.id : model.object_id }), permission=#{permission}) =>  #{access || 'denied'} #{rule}")
          end
        end
        access
      end

      # Bereinigen (entfernen) aller Objecte aus der angebenen Collection,
      # wo der angegebene User nicht das angegebene Recht hat
      #
      # liefert ein neues Array mit den Objecten, wo der spez. Zugriff arlaubt ist
      def purge_collection user, collection, permission
        collection.select{|model| model_access?(user, model, permission)}
      end
    end # of Class-Methods
  end # of AccessRules



  # Module zum Include in Controllers
  # Dieser muss die folgenden Methoden bereitstellen:
  #
  #   current_user : akt. Login-User
  #   access_denied :  Methode aus dem authenticated_system, welche ein redirect zum login auslöst
  #
  # Der Loginuser muss fuer die hier benoetigte Funktionalitaet
  # die Methode:
  #   has_role?(role)  # role the Name of the Role as Symbol
  # besitzen.
  #
  # Beispiel der Einbindung in den ApplicationController
  #   include Tuersteher::ControllerExtensions
  #   before_filter :check_access # methode is from Tuersteher::ControllerExtensions
  #
  module ControllerExtensions

    @@url_path_method = nil
    @@prefix_checked = nil

    # Pruefen Zugriff fuer eine Web-action
    #
    # path        Pfad der Webresource (String)
    # method      http-Methode (:get, :put, :delete, :post), default ist :get
    #
    def path_access?(path, method = :get)
      unless @@prefix_checked
        @@prefix_checked = true
        prefix = respond_to?(:root_path) && root_path
        if prefix.size > 1
          prefix.chomp!('/') # des abschliessende / entfernen
          AccessRulesStorage.instance.extend_path_rules_with_prefix(prefix)
          Rails.logger.info "Tuersteher::ControllerExtensions: set path-prefix to: #{prefix}"
        end
      end
      AccessRules.path_access? current_user, path, method
    end

    # Pruefen Zugriff auf ein Model-Object
    #
    # model       das Model-Object
    # permission  das geforderte Zugriffsrecht (:create, :update, :destroy, :get)
    #
    # liefert true/false
    def model_access? model, permission
      AccessRules.model_access? current_user, model, permission
    end

    # Bereinigen (entfernen) aller Objecte aus der angebenen Collection,
    # wo der akt. User nicht das angegebene Recht hat
    #
    # liefert ein neues Array mit den Objecten, wo der spez. Zugriff arlaubt ist
    def purge_collection collection, permission
      AccessRules.purge_collection(current_user, collection, permission)
    end


    def self.included(base)
      base.class_eval do
        # Diese Methoden  auch als Helper fuer die Views bereitstellen
        helper_method :path_access?, :model_access?, :purge_collection
      end
    end

    protected

    # Pruefen, ob Zugriff des current_user
    # fuer aktullen Request erlaubt ist
    def check_access

      # im dev-mode rules bei jeden request auf Änderungen prüfen
      AccessRulesStorage.instance.read_rules if Rails.env=='development'

      # Rails3 hat andere url-path-methode
      @@url_path_method ||= Rails.version[0..1]=='3.' ? :fullpath : :request_uri

      # bind current_user on the current thread
      Thread.current[:user] = current_user

      req_method = request.method
      req_method = req_method.downcase.to_sym if req_method.is_a?(String)
      url_path = request.send(@@url_path_method)
      unless path_access?(url_path, req_method)
        usr_id = current_user && current_user.respond_to?(:id) ? current_user.id : current_user.object_id
        msg = "Tuersteher#check_access: access denied for #{url_path} :#{req_method} user.id=#{usr_id}"
        Tuersteher::TLogger.logger.warn msg
        logger.warn msg  # log message also for Rails-Default logger
        access_denied  # Methode aus dem authenticated_system, welche ein redirect zum login auslöst
      end
    end

  end



  # Module for include in Model-Object-Classes
  #
  # The module get the current-user from Thread.current[:user]
  #
  # Sample for ActiveRecord-Class
  #   class Sample < ActiveRecord::Base
  #    include Tuersteher::ModelExtensions
  #
  #     def transfer_to account
  #       check_model_access :transfer # raise a exception if not allowed
  #       ....
  #     end
  #
  #
  module ModelExtensions

    # Check permission for the Model-Object
    #
    # permission  the requested permission (sample :create, :update, :destroy, :get)
    #
    # raise a SecurityError-Exception if access denied
    def check_access permission
      user = Thread.current[:user]
      unless AccessRules.model_access? user, self, permission
        raise SecurityError, "Access denied! Current user have no permission '#{permission}' on Model-Object #{self}."
      end
    end

    def self.included(base)
      base.extend ClassMethods
    end

    module ClassMethods

      # Bereinigen (entfernen) aller Objecte aus der angebenen Collection,
      # wo der akt. User nicht das angegebene Recht hat
      #
      # liefert ein neues Array mit den Objecten, wo der spez. Zugriff arlaubt ist
      def purge_collection collection, permission
        user = Thread.current[:user]
        AccessRules.purge_collection(user, collection, permission)
      end
    end # of ClassMethods

  end # of module ModelExtensions


  # The Classes for the separate Rule-Specifications
  class PathSpecification
    attr_reader :path

    def initialize path, negation
      @negation = negation
      self.path = path
    end

    def path= url_path
      @path = url_path
      # url_path in regex ^#{path} wandeln ausser bei "/",
      # dies darf keine Regex mit ^/ werden, da diese dann ja immer matchen wuerde
      if url_path == "/"
        @path_regex = /^\/$/
      else
        @path_regex = /^#{url_path}/
      end
    end

    def grant? path_or_model, method, login_ctx
      rc = @path_regex =~ path_or_model
      rc = !rc if @negation
      rc
    end
  end

  class ModelSpecification
    def initialize clazz, negation
      @clazz, @negation = clazz, negation
    end

    def grant? path_or_model, method, login_ctx
      m_class = path_or_model.instance_of?(Class) ? path_or_model : path_or_model.class
      rc = @clazz == m_class
      rc = !rc if @negation
      rc
    end
  end

  class RoleSpecification
    def initialize role, negation
      @role, @negation = role, negation
    end

    def grant? path_or_model, method, login_ctx
      return false if login_ctx.nil?
      rc = login_ctx.has_role?(@role)
      rc = !rc if @negation
      rc
    end
  end

  class MethodSpecification
    def initialize method, negation
      @method, @negation = method, negation
    end

    def grant? path_or_model, method, login_ctx
      rc = @method==method
      rc = !rc if @negation
      rc
    end
  end

  class ExtensionSpecification
    def initialize method_name, negation, expected_value=nil
      @method, @negation, @expected_value = method_name, negation, expected_value
    end

    def grant? path_or_model, method, login_ctx
      return false if login_ctx_or_model.nil?
      obj_to_check = path_or_model.is_a?(String) ? login_ctx : path_or_model
      unless obj_to_check.respond_to?(key)
        if path_or_model.is_a?(String)
          Tuersteher::TLogger.logger.warn("#{to_s}.grant? => false why Login-Context have not method '#{key}'!")
        else
          m_msg = obj_to_check.instance_of?(Class) ? "Class '#{obj_to_check.name}'" : "Object '#{obj_to_check.class}'"
          Tuersteher::TLogger.logger.warn("#{to_s}.grant? => false why #{m_msg} have not method '#{key}'!")
        end
        return false
      end
      rc = false
      if @expected_value
        rc = obj_to_check.send(key,@expected_value)
      else
        rc = obj_to_check.send(key)
      end
      rc = !rc if @deny
      rc
    end
  end



  # Abstracte base class for Access-Rules
  class BaseAccessRule
    attr_reader :rule_spezifications

    def initialize
      @rule_spezifications = []
    end

    # add role
    def role(role_name)
      raise "wrong role '#{role_name}'! Must be a symbol " unless role_name.is_a?(Symbol)
      @rule_spezifications << RoleSpecification.new(role_name, @negation)
      @negation = false if @negation
      self
    end

    # add list of roles
    def roles(*role_names)
      role_names.flatten.each do |role_name|
        @rule_spezifications << RoleSpecification.new(role_name, @negation)
      end
      @negation = false if @negation
      self
    end

    # add extension-definition
    # parmaters:
    #   method_name:      Symbol with the name of the method to call for addional check
    #   expected_value:   optional expected value for the result of the with metho_name specified method, defalt is true
    def extension method_name, expected_value=nil
      @rule_spezifications << ExtensionSpecification.new(method_name, @negation, expected_value)
      @negation = false if @negation
      self
    end

    # set methode for access
    # access_method        Name of Methode for access as Symbol
    def method(access_method)
      return if access_method==:all  # :all is only syntax sugar
      @rule_spezifications << MethodSpecification.new(access_method, @negation)
      @negation = false if @negation
      self
    end


    # mark this rule as grant-rule
    def grant
      self
    end

    # mark this rule as deny-rule
    def deny
      @deny = true
      self
    end

    # is this rule a deny-rule
    def deny?
      @deny
    end


    # negate role followed rule specification (role or extension
    def not
      @negation = true
      self
    end

    # check, if this rule fired for specified parameter
    def fired? path_or_model, method, login_ctx
      login_ctx = nil if login_ctx==:false # manche Authenticate-System setzen den login_ctx/user auf :false
      @rule_spezifications.all?{|spec| spec.grant?(path_or_model, method, login_ctx)}
    end

  end # of BaseAccessRule


  class PathAccessRule < BaseAccessRule

    METHOD_NAMES = [:get, :edit, :put, :delete, :post, :all].freeze
    attr_reader :path_spezification

    # Zugriffsregel
    #
    # path          :all fuer beliebig, sonst String mit der http-path beginnen muss
    #
    def initialize(path)
      raise "wrong path '#{path}'! Must be a String or :all ." unless path==:all or path.is_a?(String)
      super()
      if path != :all # :all is only syntax sugar
        @path_spezification = PathSpecification.new(path, @negation)
        @rule_spezifications << @path_spezification
      end
    end


    # set http-methode
    # http_method        http-Method, allowed is :get, :put, :delete, :post, :all
    def method(http_method)
      raise "wrong method '#{http_method}'! Must be #{METHOD_NAMES.join(', ')} !" unless METHOD_NAMES.include?(http_method)
      super
      self
    end



    def to_s
      s = 'PathAccesRule['
      s << 'DENY ' if @deny
      s << @rule_spezifications.map(&:to_s).join(', ')
      s << ']'
      s
    end

  end



  class ModelAccessRule < BaseAccessRule

    # erzeugt neue Object-Zugriffsregel
    #
    # clazz         Model-Klassenname oder :all fuer alle
    #
    def initialize(clazz)
      raise "wrong clazz '#{clazz}'! Must be a Class or :all ." unless clazz==:all or clazz.is_a?(Class)
      super()
      if clazz != :all # :all is only syntax sugar
        @rule_spezifications << ModelSpecification.new(clazz, @negation)
      end
    end


    def to_s
      s = 'ModelAccessRule['
      s << 'DENY ' if @deny
      s << @rule_spezifications.map(&:to_s).join(', ')
      s << ']'
      s
    end

  end

end
