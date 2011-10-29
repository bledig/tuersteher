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

    attr_writer :rules_config_file # to set own access_rules-path
    attr_accessor :check_intervall # check intervall in seconds to check config file
    attr_accessor :path_prefix # prefix for path-rules

    DEFAULT_RULES_CONFIG_FILE = 'access_rules.rb' # in config-dir

    # private initializer why this class is a singleton
    def initialize
      @path_rules = []
      @model_rules = []
      @check_intervall = 300 # set default check interval to 5 minutes
    end

    def ready?
      @was_read
    end

    # get all path_rules as array of PathAccessRule-Instances
    def path_rules
      read_rules_if_needed
      @path_rules
    end

    # get all model_rules as array of ModelAccessRule-Instances
    def model_rules
      read_rules_if_needed
      @model_rules
    end


    def read_rules_if_needed
      if @was_read
        # im check_intervall pruefen ob AccessRules-File sich geändert hat
        t = Time.now.to_i
        @last_read_check ||= t
        if (t - @last_read_check) > @check_intervall
          @last_read_check = t
          cur_mtime = File.mtime(self.rules_config_file)
          @last_mtime ||= cur_mtime
          if cur_mtime > @last_mtime
            @last_mtime = cur_mtime
            read_rules
          end
        end
      else
        read_rules
      end
    end


    def rules_config_file
      @rules_config_file ||= File.join(Rails.root, 'config', DEFAULT_RULES_CONFIG_FILE)
    end

    # evaluated rules_definitions and create path-/model-rules
    def eval_rules rules_definitions
      @path_rules = []
      @model_rules = []
      eval rules_definitions, binding, (@rules_config_file||'no file')
      @was_read = true
      Tuersteher::TLogger.logger.info "Tuersteher::AccessRulesStorage: #{@path_rules.size} path-rules and #{@model_rules.size} model-rules loaded"
      extend_path_rules_with_prefix
    end

    # Load AccesRules from file
    #  config/access_rules.rb
    def read_rules
      @was_read = false
      content = File.read self.rules_config_file
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
    # model_class:  Model-Klassenname(als CLass oder String) oder :all fuer alle
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


    private

    # Erweitern des Path um einen Prefix
    # Ist notwenig wenn z.B. die Rails-Anwendung nicht als root-Anwendung läuft
    # also root_path != '/' ist.'
    def extend_path_rules_with_prefix
      return if @path_prefix.nil? || @path_rules.nil?
      prefix = @path_prefix.chomp('/') # das abschliessende / entfernen
      @path_rules.each do |rule|
        path_spec = rule.path_spezification
        if path_spec
          path_spec.path = "#{prefix}#{path_spec.path}"
        end
      end
      Tuersteher::TLogger.logger.info "extend_path_rules_with_prefix: #{prefix}"
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
          else
            s = "fired with #{rule}"
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

    # Pruefen Zugriff fuer eine Web-action
    #
    # path        Pfad der Webresource (String)
    # method      http-Methode (:get, :put, :delete, :post), default ist :get
    #
    def path_access?(path, method = :get)
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

      ar_storage = AccessRulesStorage.instance
      unless ar_storage.ready?
        # bei nicht production-env check-intervall auf 5 sek setzen
        ar_storage.check_intervall = 5 if Rails.env!='production'
        # set root-path as prefix for all path rules
        prefix = respond_to?(:root_path) && root_path
        ar_storage.path_prefix = prefix if prefix && prefix.size > 1
        ar_storage.read_rules
      end

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

    def to_s
      "#{@negation && 'not.'}path('#{@path}')"
    end
  end

  class ModelSpecification
    def initialize clazz, negation
      clazz = clazz.name if clazz.is_a?(Class)
      @clazz, @negation = clazz, negation
    end

    def grant? path_or_model, method, login_ctx
      m_class = path_or_model.instance_of?(Class) ? path_or_model.name : path_or_model.class.name
      rc = @clazz == m_class
      rc = !rc if @negation
      rc
    end

    def to_s
      "#{@negation && 'not.'}model(#{@clazz})"
    end
  end

  class RolesSpecification
    attr_reader :roles, :negation

    def initialize role, negation
      @negation = negation
      @roles = [role]
    end

    def grant? path_or_model, method, login_ctx
      return false if login_ctx.nil?
      # roles sind or verknüpft
      rc = @roles.any?{|role| login_ctx.has_role?(role) }
      rc = !rc if @negation
      rc
    end

    def to_s
      role_s = @roles.size == 1 ? "role(:#{@roles.first})" : "roles(#{@roles.map{|r| ":#{r}"}.join(',')})"
      "#{@negation && 'not.'}#{role_s}"
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

    def to_s
      "#{@negation && 'not.'}method(:#{@method})"
    end
  end

  class ExtensionSpecification
    def initialize method_name, negation, expected_value=nil
      @method, @negation, @expected_value = method_name, negation, expected_value
    end

    def grant? path_or_model, method, login_ctx
      rc = false
      if path_or_model.is_a?(String)
        # path-variante
        return false if login_ctx.nil?
        unless login_ctx.respond_to?(@method)
          Tuersteher::TLogger.logger.warn("#{to_s}.grant? => false why Login-Context have not method '#{@method}'!")
          return false
        end
        if @expected_value
          rc = login_ctx.send(@method, @expected_value)
        else
          rc = login_ctx.send(@method)
        end
      else
        # model-variante
        unless path_or_model.respond_to?(@method)
          m_msg = path_or_model.instance_of?(Class) ? "Class '#{path_or_model.name}'" : "Object '#{path_or_model.class}'"
          Tuersteher::TLogger.logger.warn("#{to_s}.grant? => false why #{m_msg} have not method '#{@method}'!")
          return false
        end
        if @expected_value
          rc = path_or_model.send(@method, login_ctx, @expected_value)
        else
          rc = path_or_model.send(@method, login_ctx)
        end
      end
      rc = !rc if @negation
      rc
    end

    def to_s
      val_s = @expected_value.nil? ? nil :  ", #{@expected_value}"
      "#{@negation && 'not.'}extension(:#{@method}#{val_s})"
    end
  end



  # Abstracte base class for Access-Rules
  class BaseAccessRule
    attr_reader :rule_spezifications

    def initialize
      @rule_spezifications = []
      @last_role_specification
    end

    # add role
    def role(role_name)
      return self if role_name==:all  # :all is only syntax sugar
      raise "wrong role '#{role_name}'! Must be a symbol " unless role_name.is_a?(Symbol)
      # roles are OR-linked (per default)
      # => add the role to RolesSpecification, create only new RolesSpecification if not exist
      if @last_role_specification
        raise("Mixin of role and not.role are yet not implemented!") if @negation != @last_role_specification.negation
        @last_role_specification.roles << role_name
      else
        @last_role_specification = RolesSpecification.new(role_name, @negation)
        @rule_spezifications << @last_role_specification
      end
      @negation = false if @negation
      self
    end

    # add list of roles
    def roles(*role_names)
      negation_state = @negation
      role_names.flatten.each do |role_name|
        self.role(role_name)
        @negation = negation_state # keep Negation-State for all roles
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
      return self if access_method==:all  # :all is only syntax sugar
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


    def to_s
      "Rule[#{@deny ? 'deny' : 'grant'}.#{@rule_spezifications.map(&:to_s).join('.')}]"
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
      @_to_s ||= super
    end
  end



  class ModelAccessRule < BaseAccessRule

    # erzeugt neue Object-Zugriffsregel
    #
    # clazz         Model-Klassenname(als Class oder String) oder :all fuer alle
    #
    def initialize(clazz)
      raise "wrong clazz '#{clazz}'! Must be a Class/String or :all ." unless clazz==:all or clazz.is_a?(Class) or clazz.is_a?(String)
      super()
      if clazz != :all # :all is only syntax sugar
        @rule_spezifications << ModelSpecification.new(clazz, @negation)
      end
    end


    def to_s
      @_to_s ||= super
    end
  end

end
